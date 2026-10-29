#!/usr/bin/env bash
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work="${JOURNEY_WORK:-$HOME/build/ragewarden/journey}"
out="$work/out"
port="${JOURNEY_PORT:-18222}"
server="http://127.0.0.1:$port"

email="journey-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')@ragewarden.test"
password="journey-correct-horse-battery-staple-$$"
item="journey-item"
secret="journey-plaintext-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')"

app_id="ragewarden.ragedroid.fdroid"

say() { printf '\n[journey] %s\n' "$*"; }
die() {
  printf '\n[journey] FATAL: %s\n' "$*" >&2
  exit 1
}

read_phrase() {
  _phrase=$(awk '
        /^ *[0-9]+\./ {
            for (i = 1; i < NF; i++) {
                if ($i ~ /^[0-9]+\.$/) { n = $i; sub(/\./, "", n); w[n + 0] = $(i + 1) }
            }
        }
        END { for (i = 1; i <= 24; i++) printf "%s%s", w[i], (i < 24 ? " " : "") }
    ' "$1")
  [ "$(printf '%s' "$_phrase" | wc -w)" -eq 24 ] || return 1
  printf '%s' "$_phrase"
}

rm -rf "$work"
mkdir -p "$work" "$out"

cleanup() {
  code=$?
  [ -n "${vw_pid:-}" ] && kill "$vw_pid" 2>/dev/null || true
  adb reverse --remove "tcp:$port" 2>/dev/null || true
  say "artifacts in $out"
  exit $code
}
trap cleanup EXIT INT TERM

command -v vaultwarden >/dev/null 2>&1 ||
  [ -n "${RAGEWARDEN_VAULTWARDEN_BIN:-}" ] ||
  die "no vaultwarden. Enter nix develop <path-to-nixos-config>#ragewarden, which exports RAGEWARDEN_VAULTWARDEN_BIN."
vw="${RAGEWARDEN_VAULTWARDEN_BIN:-$(command -v vaultwarden)}"

say "starting vaultwarden on $server"
DATA_FOLDER="$work/vw" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT="$port" \
  DOMAIN="$server" SIGNUPS_ALLOWED=true WEB_VAULT_ENABLED=false LOG_LEVEL=warn \
  LOGIN_RATELIMIT_MAX_BURST=1000 LOGIN_RATELIMIT_SECONDS=1 \
  ADMIN_RATELIMIT_MAX_BURST=1000 ADMIN_RATELIMIT_SECONDS=1 \
  "$vw" >"$work/vaultwarden.log" 2>&1 &
vw_pid=$!

i=0
while [ "$i" -lt 120 ]; do
  curl -fsS "$server/alive" >/dev/null 2>&1 && break
  kill -0 "$vw_pid" 2>/dev/null || die "vaultwarden exited; see $work/vaultwarden.log"
  i=$((i + 1))
  sleep 1
done
[ "$i" -lt 120 ] || die "vaultwarden never answered /alive"
say "vaultwarden up (pid $vw_pid)"

rageterm="${RAGETERM_BIN:-$root/target/debug/rageterm}"
[ -x "$rageterm" ] || die "no rageterm at $rageterm -- cargo build -p rageterm, or set RAGETERM_BIN"

export RAGEWARDEN_CONFIG_DIR="$work/rageterm"

say "registering $email (the Android app has no registration screen)"
printf '%s\n%s\n' "$password" "$password" |
  "$rageterm" register --server "$server" --email "$email" >"$work/register.log" 2>&1 ||
  die "register failed; see $work/register.log"

printf '%s\n' "$password" |
  "$rageterm" login --server "$server" --email "$email" >"$work/login.log" 2>&1 ||
  die "login failed; see $work/login.log"

"$rageterm" enroll-software-identity >"$work/enroll-software.log" 2>&1 ||
  die "enroll-software-identity failed; see $work/enroll-software.log"

say "enrolling a paper recovery identity -- its 24 words are what crosses to the phone"
"$rageterm" enroll-recovery --no-confirm --label paper >"$work/enroll-recovery.log" 2>&1 ||
  die "enroll-recovery failed; see $work/enroll-recovery.log"

phrase=$(read_phrase "$work/enroll-recovery.log") ||
  die "could not read 24 words out of $work/enroll-recovery.log -- the mnemonic
        layout changed and read_phrase no longer matches it"
printf '%s\n' "$phrase" >"$out/recovery-phrase.txt"

say "storing '$item' wrapped to the paper recipient"
printf '%s\n' "$secret" | "$rageterm" set "$item" --from-stdin >"$work/set.log" 2>&1 ||
  die "storing the fixture item failed; see $work/set.log"

"$rageterm" recipients list >"$work/recipients.log" 2>"$work/recipients.err" ||
  die "listing recipients failed; see $work/recipients.err"
enrolled=$(awk '
    /^ID[[:space:]]/ { t = 1; next }
    t && NF == 0 { t = 0 }
    t { n++ }
    END { print n + 0 }
' "$work/recipients.log")
unwrapped=$(awk '
    /^Not wrapped to by writes from this machine:/ { s = 1; next }
    s && NF { n++ }
    END { print n + 0 }
' "$work/recipients.log")
[ -s "$RAGEWARDEN_CONFIG_DIR/identity.age" ] ||
  die "no identity.age under $RAGEWARDEN_CONFIG_DIR -- enroll-software-identity did not run,
        and the +1 below would be counting a recipient that is not in the header"
recipient_count=$((enrolled - unwrapped + 1))
[ "$recipient_count" -ge 2 ] ||
  die "derived $recipient_count recipient(s) for writes from here, expected at least
        2 (paper + identity.age). See $work/recipients.log"
say "'$item' is wrapped to $recipient_count recipient(s)"

say "minting a decoy phrase on a second account -- valid words, wrong identity"
decoy_email="journey-decoy-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')@ragewarden.test"
decoy_password="journey-decoy-correct-horse-battery-staple-$$"
(
  export RAGEWARDEN_CONFIG_DIR="$work/rageterm-decoy"
  printf '%s\n%s\n' "$decoy_password" "$decoy_password" |
    "$rageterm" register --server "$server" --email "$decoy_email" \
      >"$work/decoy-register.log" 2>&1
  printf '%s\n' "$decoy_password" |
    "$rageterm" login --server "$server" --email "$decoy_email" \
      >"$work/decoy-login.log" 2>&1
  "$rageterm" enroll-recovery --no-confirm --label decoy \
    >"$work/enroll-decoy.log" 2>&1
) || die "could not mint the decoy phrase; see $work/decoy-*.log and $work/enroll-decoy.log"

decoy_phrase=$(read_phrase "$work/enroll-decoy.log") ||
  die "could not read 24 words out of $work/enroll-decoy.log"
[ "$decoy_phrase" != "$phrase" ] ||
  die "the decoy phrase is identical to the real one -- RAGEWARDEN_CONFIG_DIR did not
        isolate the second account, and the negative control would prove nothing"
printf '%s\n' "$decoy_phrase" >"$out/decoy-phrase.txt"

registry_state="$work/registry-state.json"
say "seeding a browser-published registry into a third account (wasm under node)"
node "$here/seed-browser-registry.mjs" seed "$server" "$registry_state" \
  >"$work/registry-seed.log" 2>&1 ||
  die "could not seed the browser registry; see $work/registry-seed.log"
cp "$work/registry-seed.log" "$out/registry-seed.log"

registry_email=$(node -e 'process.stdout.write(require(process.argv[1]).email)' "$registry_state")
registry_password=$(node -e 'process.stdout.write(require(process.argv[1]).password)' "$registry_state")
registry_entry_ids=$(node -e 'const s=require(process.argv[1]);process.stdout.write([s.swEntryId,s.pkEntryId].join(","))' "$registry_state")
[ -n "$registry_email" ] && [ -n "$registry_password" ] &&
  [ "$(printf '%s' "$registry_entry_ids" | tr ',' '\n' | grep -c .)" -eq 2 ] ||
  die "the seeding script did not report an account and two browser entry ids; see
        $work/registry-seed.log and $registry_state"
say "browser registry seeded for $registry_email ($registry_entry_ids)"

command -v adb >/dev/null 2>&1 || die "no adb -- enter nix develop <path-to-nixos-config>#android"
adb get-state >/dev/null 2>&1 || die "no device. Start one: ragedroid-emulator & ragedroid-wait-boot"
say "adb reverse tcp:$port (the app requires a loopback server, see header)"
adb reverse "tcp:$port" "tcp:$port" >/dev/null

results_dir="$root/ragedroid/app/build/outputs/androidTest-results/connected"
extra_dir="$root/ragedroid/app/build/outputs/connected_android_test_additional_output"
# Each instrumented run below reads only its own results: a file left by an
# earlier run (an unfiltered connected suite, the other flavour) would be read
# as this one's.
fresh_results() { rm -rf "$results_dir" "$extra_dir"; }
# The <testsuite> tag this run wrote for one test class.
class_suite() {
  find "$results_dir" -maxdepth 4 -name '*.xml' -exec grep -ho '<testsuite [^>]*>' {} + 2>/dev/null |
    grep "name=\"[^\"]*\.$1\"" | head -n 1
}
tag_attr() { printf '%s' "$1" | grep -o " $2=\"[^\"]*\"" | sed 's/^.*="//; s/"$//'; }

say "uninstalling any previous $app_id so the app starts cold"
adb uninstall "$app_id" >/dev/null 2>&1 || true
adb uninstall "$app_id.test" >/dev/null 2>&1 || true

say "driving the app"
android_ok=1
fresh_results
(
  cd "$root/ragedroid" && gradle --no-daemon connectedFdroidDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.journey.JourneyTest \
    -Pandroid.testInstrumentationRunnerArguments.journeyServer="$server" \
    -Pandroid.testInstrumentationRunnerArguments.journeyEmail="$email" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPassword="$password" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPhrase="$(printf '%s' "$phrase" | tr ' ' _)" \
    -Pandroid.testInstrumentationRunnerArguments.journeyDecoyPhrase="$(printf '%s' "$decoy_phrase" | tr ' ' _)" \
    -Pandroid.testInstrumentationRunnerArguments.journeyItem="$item" \
    -Pandroid.testInstrumentationRunnerArguments.journeySecret="$secret" \
    -Pandroid.testInstrumentationRunnerArguments.journeyRecipientCount="$recipient_count" \
    -Pandroid.testInstrumentationRunnerArguments.RAGEWARDEN_MOCK_HARDWARE=1
) >"$work/android.log" 2>&1 || android_ok=0

pulled=$(find "$root/ragedroid/app/build/outputs/connected_android_test_additional_output" \
  -type d -name android 2>/dev/null | head -n 1)
if [ -n "$pulled" ]; then
  rm -rf "$out/android"
  cp -r "$pulled" "$out/android"
  captures=$(find "$out/android" -name '*.txt' ! -name 'handoff-*' | wc -l)
  say "android journey: $captures accessibility-tree captures"
fi

if [ "$android_ok" -eq 0 ]; then
  printf '[journey] android run failed; last lines of %s:\n' "$work/android.log" >&2
  tail -n 40 "$work/android.log" >&2
  if [ -n "$pulled" ]; then
    node "$here/report.mjs" "$out/journey.html" "$out/android" >/dev/null 2>&1 || true
    say "failure trees kept in $out/android (report: $out/journey.html)"
  fi
  die "android journey failed"
fi

[ -n "$pulled" ] || die "no journey artifacts were pulled back; see $work/android.log"
journey_suite=$(class_suite JourneyTest)
[ -n "$journey_suite" ] ||
  die "no androidTest result names JourneyTest -- gradle reported success without the
        test running on the device. See $work/android.log"
say "android journey: tests=$(tag_attr "$journey_suite" tests) failures=$(tag_attr "$journey_suite" failures) errors=$(tag_attr "$journey_suite" errors) skipped=$(tag_attr "$journey_suite" skipped)"
[ "$(tag_attr "$journey_suite" tests)" -ge 1 ] && [ "$(tag_attr "$journey_suite" skipped)" -eq 0 ] &&
  [ "$(tag_attr "$journey_suite" failures)" -eq 0 ] && [ "$(tag_attr "$journey_suite" errors)" -eq 0 ] ||
  die "the android journey did not run and pass; see $work/android.log"

say "driving the registry-destruction guard"
adb uninstall "$app_id" >/dev/null 2>&1 || true
adb uninstall "$app_id.test" >/dev/null 2>&1 || true
registry_ok=1
fresh_results
(
  cd "$root/ragedroid" && gradle --no-daemon connectedFdroidDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.registry.RegistryPushInstrumentedTest \
    -Pandroid.testInstrumentationRunnerArguments.registryServer="$server" \
    -Pandroid.testInstrumentationRunnerArguments.registryEmail="$registry_email" \
    -Pandroid.testInstrumentationRunnerArguments.registryPassword="$registry_password" \
    -Pandroid.testInstrumentationRunnerArguments.registryBrowserEntryIds="$registry_entry_ids"
) >"$work/registry.log" 2>&1 || registry_ok=0

registry_pulled=$(find "$root/ragedroid/app/build/outputs/connected_android_test_additional_output" \
  -type d -name registry 2>/dev/null | head -n 1)
if [ -n "$registry_pulled" ]; then
  rm -rf "$out/registry"
  cp -r "$registry_pulled" "$out/registry"
fi

if [ "$registry_ok" -eq 0 ]; then
  printf '[journey] registry guard failed; last lines of %s:\n' "$work/registry.log" >&2
  tail -n 60 "$work/registry.log" >&2
  die "registry-destruction guard failed"
fi

registry_xml=$(find "$root/ragedroid/app/build/outputs/androidTest-results/connected" \
  -name '*.xml' -exec grep -l 'RegistryPushInstrumentedTest' {} + 2>/dev/null | head -n 1)
[ -n "$registry_xml" ] ||
  die "no androidTest result XML mentions RegistryPushInstrumentedTest -- the run reported
        success without the test existing on the device. See $work/registry.log"
cp "$registry_xml" "$out/registry-results.xml"
suite_line=$(class_suite RegistryPushInstrumentedTest)
suite_attr() {
  printf '%s' "$suite_line" | grep -o " $1=\"[^\"]*\"" | sed 's/^.*="//; s/"$//'
}
registry_tests=$(suite_attr tests)
registry_failures=$(suite_attr failures)
registry_errors=$(suite_attr errors)
registry_skipped=$(suite_attr skipped)
say "registry guard: tests=${registry_tests:-?} failures=${registry_failures:-?} errors=${registry_errors:-?} skipped=${registry_skipped:-?}"
[ "${registry_tests:-0}" -ge 1 ] ||
  die "the registry guard reported $registry_tests test cases. It did not run.
        See $out/registry-results.xml"
[ "${registry_skipped:-0}" -eq 0 ] ||
  die "the registry guard SKIPPED $registry_skipped of its $registry_tests case(s). That is
        its assumption firing, which means the instrumentation arguments above did not reach
        it -- the run is green and nothing was tested. See $out/registry-results.xml"
[ "${registry_failures:-0}" -eq 0 ] && [ "${registry_errors:-0}" -eq 0 ] ||
  die "the registry guard failed ($registry_failures failure(s), $registry_errors error(s)).
        See $out/registry-results.xml and $work/registry.log"

say "driving autofill, the keyboard and TOTP against a foreign login form"
adb uninstall "$app_id" >/dev/null 2>&1 || true
adb uninstall "$app_id.test" >/dev/null 2>&1 || true
flows_ok=1
fresh_results
(
  cd "$root/ragedroid" && gradle --no-daemon connectedFdroidDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.journey.DeliveryFlowsTest \
    -Pandroid.testInstrumentationRunnerArguments.journeyServer="$server" \
    -Pandroid.testInstrumentationRunnerArguments.journeyEmail="$email" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPassword="$password" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPhrase="$(printf '%s' "$phrase" | tr ' ' _)" \
    -Pandroid.testInstrumentationRunnerArguments.journeyItem="$item"
) >"$work/flows.log" 2>&1 || flows_ok=0
flows_xml=$(find "$root/ragedroid/app/build/outputs/androidTest-results/connected" \
  -name '*.xml' -exec grep -l 'DeliveryFlowsTest' {} + 2>/dev/null | head -n 1)
[ -n "$flows_xml" ] && cp "$flows_xml" "$out/flows-results.xml"
if [ "$flows_ok" -eq 0 ]; then
  printf '[journey] delivery flows failed; last lines of %s:\n' "$work/flows.log" >&2
  tail -n 60 "$work/flows.log" >&2
  die "delivery flows failed"
fi
[ -n "$flows_xml" ] ||
  die "no androidTest result XML mentions DeliveryFlowsTest; see $work/flows.log"
flows_line=$(class_suite DeliveryFlowsTest)
flows_attr() {
  printf '%s' "$flows_line" | grep -o " $1=\"[^\"]*\"" | sed 's/^.*="//; s/"$//'
}
say "delivery flows: tests=$(flows_attr tests) failures=$(flows_attr failures) errors=$(flows_attr errors) skipped=$(flows_attr skipped)"
[ "$(flows_attr tests)" -ge 6 ] && [ "$(flows_attr skipped)" -eq 0 ] &&
  [ "$(flows_attr failures)" -eq 0 ] && [ "$(flows_attr errors)" -eq 0 ] ||
  die "the delivery flows did not all run and pass; see $out/flows-results.xml"

if [ "${JOURNEY_BENCH:-0}" = 1 ]; then
  say "benchmarking the release-shaped build on the journey account (JOURNEY_BENCH=1)"
  # vaultListScroll measures frames while flinging the list, and the journey's
  # handful of items fits on one screen: a fling drew nothing and the metric
  # failed with "no renderthread slices". Forty more make the list scroll.
  i=0
  while [ "$i" -lt 40 ]; do
    printf 'bench-secret-%02d\n' "$i" | "$rageterm" set "$(printf 'bench-item-%02d' "$i")" --from-stdin >>"$work/bench-seed.log" 2>&1 ||
      die "seeding the bench items failed; see $work/bench-seed.log"
    i=$((i + 1))
  done
  adb uninstall "$app_id" >/dev/null 2>&1 || true
  bench_args=(
    -Pandroid.testInstrumentationRunnerArguments.benchServer="$server"
    -Pandroid.testInstrumentationRunnerArguments.benchEmail="$email"
    -Pandroid.testInstrumentationRunnerArguments.benchPassword="$password"
    -Pandroid.testInstrumentationRunnerArguments.benchItem="$(printf '%s' "Flow login" | tr ' ' _)"
    -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.suppressErrors=EMULATOR
  )
  (
    cd "$root/ragedroid" && gradle --no-daemon :baselineprofile:connectedFdroidBenchmarkBenchmarkAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.baselineprofile.Macrobenchmark \
      "${bench_args[@]}"
  ) >"$work/bench.log" 2>&1 || die "the macrobenchmark failed; see $work/bench.log"
  bench_json=$(find "$root/ragedroid/baselineprofile/build/outputs" -name '*benchmarkData.json' 2>/dev/null | head -n 1)
  [ -n "$bench_json" ] || die "the macrobenchmark wrote no benchmarkData.json; see $work/bench.log"
  cp "$bench_json" "$out/benchmarkData.json"
  node -e '
    const b = require(process.argv[1]);
    const want = ["coldStartup", "vaultListScroll", "detailOpenClose", "detailReveal"];
    const got = Object.fromEntries(b.benchmarks.map((t) => [t.name, t]));
    for (const n of want) {
      const t = got[n];
      const runs = t && Object.values(t.metrics || {}).concat(Object.values(t.sampledMetrics || {}))
        .reduce((a, m) => a + (m.runs || []).length, 0);
      if (!runs) { console.error(`${n}: no samples`); process.exit(1); }
      console.log(`${n}: ${runs} samples`);
    }' "$bench_json" >"$out/bench-summary.txt" 2>&1 ||
    die "a macrobenchmark measured nothing; see $out/bench-summary.txt"
  say "macrobenchmark: $(tr '\n' ' ' <"$out/bench-summary.txt")"
  (
    cd "$root/ragedroid" && gradle --no-daemon :app:generateBaselineProfile \
      -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.baselineprofile.BaselineProfileGenerator \
      "${bench_args[@]}"
  ) >"$work/profile.log" 2>&1 || die "baseline profile generation failed; see $work/profile.log"
  say "baseline profile written to ragedroid/app/src/main/generated/baselineProfiles"
fi

say "re-reading the seeded vault as the browser"
node "$here/seed-browser-registry.mjs" audit "$registry_state" \
  >"$work/registry-audit.log" 2>&1 || {
  tail -n 40 "$work/registry-audit.log" >&2
  cp "$work/registry-audit.log" "$out/registry-audit.log"
  die "the browser can no longer read its own registry after the phone enrolled;
        see $out/registry-audit.log"
}
cp "$work/registry-audit.log" "$out/registry-audit.log"

# The item the phone wrote above (JourneyTest's COMPOSER_ITEM/COMPOSER_SECRET),
# opened in the browser with the paper phrase.
android_item=composer-fail-open-item
android_secret=composer-fail-open-secret
journey_kt="$root/ragedroid/app/src/androidTest/kotlin/ragewarden/ragedroid/journey/JourneyTest.kt"
grep -q "COMPOSER_ITEM = \"$android_item\"" "$journey_kt" &&
  grep -q "COMPOSER_SECRET = \"$android_secret\"" "$journey_kt" ||
  die "JourneyTest's COMPOSER_ITEM/COMPOSER_SECRET no longer read $android_item /
        $android_secret; update them here too"

say "browser half: the extension opens the phone's item with the paper phrase"
pw="$root/ragemanifest/tests/playwright"
command -v pnpm >/dev/null 2>&1 ||
  die "no pnpm for the browser half -- enter nix develop <nixos-config>#ragewarden, or put pnpm_12 on PATH"
[ -d "$pw/node_modules" ] || (cd "$pw" && pnpm install --frozen-lockfile) >"$work/browser-pnpm.log" 2>&1 ||
  die "pnpm install failed; see $work/browser-pnpm.log"
browser_ok=1
(
  cd "$pw" && VAULTWARDEN_URL="$server" RAGETERM_BIN="$rageterm" \
    JOURNEY_EMAIL="$email" JOURNEY_PASSWORD="$password" \
    JOURNEY_PHRASE="$phrase" JOURNEY_DECOY_PHRASE="$decoy_phrase" \
    JOURNEY_ITEM="$item" JOURNEY_SECRET="$secret" \
    JOURNEY_ANDROID_ITEM="$android_item" JOURNEY_ANDROID_SECRET="$android_secret" \
    PLAYWRIGHT_JUNIT_OUTPUT_FILE="$work/browser-results.xml" \
    pnpm exec playwright test tests/android-recovery.spec.ts --reporter=list,junit
) >"$work/browser.log" 2>&1 || browser_ok=0
cp "$work/browser.log" "$out/browser.log"
[ -s "$work/browser-results.xml" ] ||
  die "Playwright wrote no result file; see $out/browser.log"
cp "$work/browser-results.xml" "$out/browser-results.xml"
suite_line=$(grep -o '<testsuites [^>]*>' "$work/browser-results.xml")
browser_tests=$(suite_attr tests)
browser_failures=$(suite_attr failures)
browser_errors=$(suite_attr errors)
browser_skipped=$(suite_attr skipped)
say "browser half: tests=${browser_tests:-?} failures=${browser_failures:-?} errors=${browser_errors:-?} skipped=${browser_skipped:-?}"
[ "${browser_tests:-0}" -ge 1 ] && [ "${browser_skipped:-0}" -eq 0 ] ||
  die "the browser half ran ${browser_tests:-0} test(s), ${browser_skipped:-0} skipped: the
        JOURNEY_* environment did not reach the spec. See $out/browser-results.xml"
[ "$browser_ok" -eq 1 ] && [ "${browser_failures:-0}" -eq 0 ] && [ "${browser_errors:-0}" -eq 0 ] ||
  die "the browser could not open the phone's item with the paper phrase; see $out/browser.log"

say "rendering report"
node "$here/report.mjs" "$out/journey.html" "$out/android"

say "done: $out/journey.html"
