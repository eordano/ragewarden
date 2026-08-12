#!/bin/sh
# Not executed directly -- run it as `bash tests/journey/run.sh` from inside
# `nix develop <path-to-nixos-config>#android`. There is no `#!/usr/bin/env bash`
# shebang on purpose: /usr is 0700 on some hardened hosts and an env shebang
# fails there as "bad interpreter: Permission denied" for any non-root user.
#
# ---------------------------------------------------------------------------
# End-to-end journey across two clients, annotated with the accessibility tree.
#
#   1. bring up a throwaway Vaultwarden on the HOST
#   2. with rageterm, build the fixture the phone will recover:
#        * register the account, because the Android app CANNOT.
#          BitwardenVaultRepository.register() and RageNative.register() both
#          exist, but no screen calls either -- grep the ui/ tree and you get
#          nothing. A user with no Bitwarden account cannot start from the phone.
#        * enrol a 24-word paper recovery identity and capture the phrase
#        * store an item wrapped to it
#        * count the recipients that item was actually wrapped to, so the phone
#          can assert its recipient pip by value instead of against a constant
#        * mint a DECOY phrase on a SECOND throwaway account -- a valid BIP-39
#          mnemonic deriving a real age identity that is not a recipient of the
#          item. This is the negative control, and it is what stops the journey
#          from being a test that cannot fail: JourneyTest types it first and
#          requires the reveal to be refused. A checksum-broken phrase would not
#          do -- the app's own "24 of 24 words" gate rejects that before any
#          unwrap is attempted, so it would prove nothing about the unwrap.
#   3. adb reverse, so the emulator's 127.0.0.1 is the host's. Not a shortcut:
#      core::sync::host_is_loopback accepts only localhost and real loopback
#      addresses, and FirstRunScreen's own signInFormProblem() independently
#      requires host == localhost / ::1 / 127.*, so the emulator's usual
#      10.0.2.2 host alias is refused by the product itself.
#   4. drive the Android app (JourneyTest) -- sign in, skip both enrolment steps,
#      check the vault row's recipient pip, type the DECOY words under Settings
#      -> "Recover from paper backup" and require a refusal, then type the real
#      24 words and assert the plaintext rageterm wrote, then compose an item
#      with nothing enrolled here and require the save to be gated. Record the
#      accessibility tree before and after every interaction.
#   5. the browser half is NOT IMPLEMENTED -- see the section below, which says so
#      instead of running anything
#   6. render everything into one annotated HTML page
#
# WHAT CROSSES, AND WHY IT IS THE PHRASE. The emulator has no security key, so
# any identity enrolled on the device would be a MOCK, and
# BitwardenVaultRepository.pushRecipientRegistry filters mocks out of the
# published registry (`filterNot { it.mock }`). The browser and the phone can
# therefore never share a device identity here even in principle. The BIP-39
# recovery phrase is a real age key, and it is the thing that crosses. This
# script proves the rageterm -> ragedroid direction of that crossing, by value:
# a secret written on the host is read back on the phone from 24 typed words.
#
# NO SCREENSHOTS. ragedroid sets FLAG_SECURE (ui/SecureWindow.kt), so Android
# blanks every capture of the app -- `adb exec-out screencap` from the host
# included; it returns a solid black frame the moment ragedroid has focus. That
# is correct behaviour for a password manager, not a bug to work around, so the
# journey records the Compose semantics tree per step instead of pixels. See the
# header of ragedroid/.../journey/Journal.kt for the full reproduction.
#
# EVERYTHING HERE IS THROWAWAY: a fresh account, a random password, a loopback
# server, and a data dir this script deletes. The recovery phrase and the item's
# plaintext are written to disk in the clear and passed as instrumentation
# arguments. Never point this at a real vault.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# Deliberately NOT $TMPDIR and NOT /tmp.
#
# $TMPDIR inside `nix develop` is a per-shell directory removed when the shell
# exits, taking the logs you need to diagnose a failed run with it.
#
# /tmp is worse on a tmpfs-root host: /tmp is RAM.
# A run leaves a Vaultwarden data dir, a rageterm config and the artifacts here,
# and anything that puts a cargo or gradle target dir under the same root will
# quietly eat the machine's memory -- 28 GB of it, once, on a 32 GB tmpfs that
# then sat at 94% full. $HOME is a real dataset with room.
work="${JOURNEY_WORK:-$HOME/build/ragewarden/journey}"
out="$work/out"
port="${JOURNEY_PORT:-18222}"
server="http://127.0.0.1:$port"

email="journey-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')@ragewarden.test"
password="journey-correct-horse-battery-staple-$$"
item="journey-item"
secret="journey-plaintext-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')"

# The fdroid flavour appends .fdroid to the applicationId; the debug build type
# adds no suffix of its own (ragedroid/app/build.gradle.kts).
app_id="ragewarden.ragedroid.fdroid"

say() { printf '\n[journey] %s\n' "$*"; }
die() { printf '\n[journey] FATAL: %s\n' "$*" >&2; exit 1; }

# Read the 24 words out of an `enroll-recovery` log.
#
# They are printed as a four-column grid ("  1. staff    2. hello ..."), so
# reading them off in text order happens to be correct -- but only by luck of the
# layout. Index by the printed ordinal instead, and restrict to the numbered
# lines so nothing else in the output can contribute a word. Fails (non-zero)
# rather than returning a short phrase, so a layout change is caught here and not
# as a mysterious "24 of 24 words" timeout on the device.
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

# --- 1. server ------------------------------------------------------------
command -v vaultwarden >/dev/null 2>&1 \
    || [ -n "${RAGEWARDEN_VAULTWARDEN_BIN:-}" ] \
    || die "no vaultwarden. Enter nix develop <path-to-nixos-config>#ragewarden, which exports RAGEWARDEN_VAULTWARDEN_BIN."
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
    i=$((i + 1)); sleep 1
done
[ "$i" -lt 120 ] || die "vaultwarden never answered /alive"
say "vaultwarden up (pid $vw_pid)"

# --- 2. account and fixture -----------------------------------------------
rageterm="${RAGETERM_BIN:-$root/target/debug/rageterm}"
[ -x "$rageterm" ] || die "no rageterm at $rageterm -- cargo build -p rageterm, or set RAGETERM_BIN"

export RAGEWARDEN_CONFIG_DIR="$work/rageterm"

say "registering $email (the Android app has no registration screen)"
printf '%s\n%s\n' "$password" "$password" \
  | "$rageterm" register --server "$server" --email "$email" >"$work/register.log" 2>&1 \
  || die "register failed; see $work/register.log"

printf '%s\n' "$password" \
  | "$rageterm" login --server "$server" --email "$email" >"$work/login.log" 2>&1 \
  || die "login failed; see $work/login.log"

# `set` wraps to every recipient this machine covers, and refuses to store an
# item with no recipient at all -- so the software identity comes first even
# though the phone will never use it.
"$rageterm" enroll-software-identity >"$work/enroll-software.log" 2>&1 \
  || die "enroll-software-identity failed; see $work/enroll-software.log"

say "enrolling a paper recovery identity -- its 24 words are what crosses to the phone"
"$rageterm" enroll-recovery --no-confirm --label paper >"$work/enroll-recovery.log" 2>&1 \
  || die "enroll-recovery failed; see $work/enroll-recovery.log"

phrase=$(read_phrase "$work/enroll-recovery.log") \
  || die "could not read 24 words out of $work/enroll-recovery.log -- the mnemonic
        layout changed and read_phrase no longer matches it"
printf '%s\n' "$phrase" >"$out/recovery-phrase.txt"

say "storing '$item' wrapped to the paper recipient"
printf '%s\n' "$secret" | "$rageterm" set "$item" --from-stdin >"$work/set.log" 2>&1 \
  || die "storing the fixture item failed; see $work/set.log"

# How many recipients that `set` just wrapped to. The phone asserts its
# `RAGE · N` pip against this number, and the whole point of that assertion is
# that N counts REAL recipients: age writes a GREASE stanza into every header it
# produces, and the JNI parser used to name that stanza like a recipient, so
# every item in the app claimed one more key than could ever open it.
#
# Derived from the fixture rather than hardcoded, in two parts, because rageterm
# keeps them in two places:
#
#   * the enrolled recipients, which `recipients list` prints as a table:
#     "ID  KIND  CREATED  LABEL", one line each, terminated by a blank line.
#     Anything this machine does NOT wrap to is repeated under a "Not wrapped
#     to" header further down, so subtract those.
#
#   * PLUS ONE for identity.age. `enroll-software-identity` writes that file and
#     nothing else -- it registers no recipient, so it never appears in the table
#     above -- and `recipients::load_encrypt_plan` appends it to the selection
#     unconditionally (rageterm/src/recipients.rs, "if id_path.exists()"). It is
#     a real stanza in every header this machine writes.
"$rageterm" recipients list >"$work/recipients.log" 2>"$work/recipients.err" \
  || die "listing recipients failed; see $work/recipients.err"
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
[ -s "$RAGEWARDEN_CONFIG_DIR/identity.age" ] \
  || die "no identity.age under $RAGEWARDEN_CONFIG_DIR -- enroll-software-identity did not run,
        and the +1 below would be counting a recipient that is not in the header"
recipient_count=$((enrolled - unwrapped + 1))
# Two here and now: the paper identity in the table, plus identity.age. Enrol
# something else above and the table count follows it; the floor is a guard
# against a table that stopped parsing, which would otherwise hand the device a
# 1 and quietly turn the pip assertion into the GREASE miscount's expected value.
[ "$recipient_count" -ge 2 ] \
  || die "derived $recipient_count recipient(s) for writes from here, expected at least
        2 (paper + identity.age). See $work/recipients.log"
say "'$item' is wrapped to $recipient_count recipient(s)"

# --- 2b. the decoy phrase (negative control) -------------------------------
# A SECOND account, with its own config dir, so that enrolling a second paper
# identity cannot touch the fixture above: `enroll-recovery` rewrites the local
# recovery identity and republishes to the account's registry, so minting the
# decoy in $RAGEWARDEN_CONFIG_DIR would replace the very key the journey is
# about to recover with.
say "minting a decoy phrase on a second account -- valid words, wrong identity"
decoy_email="journey-decoy-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')@ragewarden.test"
decoy_password="journey-decoy-correct-horse-battery-staple-$$"
(
    export RAGEWARDEN_CONFIG_DIR="$work/rageterm-decoy"
    printf '%s\n%s\n' "$decoy_password" "$decoy_password" \
      | "$rageterm" register --server "$server" --email "$decoy_email" \
        >"$work/decoy-register.log" 2>&1
    printf '%s\n' "$decoy_password" \
      | "$rageterm" login --server "$server" --email "$decoy_email" \
        >"$work/decoy-login.log" 2>&1
    "$rageterm" enroll-recovery --no-confirm --label decoy \
      >"$work/enroll-decoy.log" 2>&1
) || die "could not mint the decoy phrase; see $work/decoy-*.log and $work/enroll-decoy.log"

decoy_phrase=$(read_phrase "$work/enroll-decoy.log") \
  || die "could not read 24 words out of $work/enroll-decoy.log"
# Two independently generated 256-bit mnemonics colliding is not a thing that
# happens; a decoy EQUAL to the real phrase means the second config dir did not
# take effect and the "negative" control would silently pass by revealing.
[ "$decoy_phrase" != "$phrase" ] \
  || die "the decoy phrase is identical to the real one -- RAGEWARDEN_CONFIG_DIR did not
        isolate the second account, and the negative control would prove nothing"
printf '%s\n' "$decoy_phrase" >"$out/decoy-phrase.txt"

# --- 2c. a vault the BROWSER already published a registry into -------------
# The precondition for the registry-destruction guard in step 4b. It is a THIRD,
# separate account on purpose: seeding it into the journey's account would add a
# second `__ragedroid_recipients_v1__` writer to the vault whose item counts and
# recipient pip JourneyTest asserts on, and the two tests would start explaining
# each other's failures.
#
# The seeding runs the shipped ragemanifest/ext/wasm bundle under node, so the
# registry in that account is byte-for-byte what the browser extension writes.
# See tests/journey/seed-browser-registry.mjs.
registry_state="$work/registry-state.json"
say "seeding a browser-published registry into a third account (wasm under node)"
node "$here/seed-browser-registry.mjs" seed "$server" "$registry_state" \
    >"$work/registry-seed.log" 2>&1 \
  || die "could not seed the browser registry; see $work/registry-seed.log"
cp "$work/registry-seed.log" "$out/registry-seed.log"

# Read back with node rather than a JSON-shaped grep: these values become
# instrumentation arguments and a silently-empty one would make the device-side
# assertion vacuous instead of failing here.
registry_email=$(node -e 'process.stdout.write(require(process.argv[1]).email)' "$registry_state")
registry_password=$(node -e 'process.stdout.write(require(process.argv[1]).password)' "$registry_state")
registry_entry_ids=$(node -e 'const s=require(process.argv[1]);process.stdout.write([s.swEntryId,s.pkEntryId].join(","))' "$registry_state")
[ -n "$registry_email" ] && [ -n "$registry_password" ] \
  && [ "$(printf '%s' "$registry_entry_ids" | tr ',' '\n' | grep -c .)" -eq 2 ] \
  || die "the seeding script did not report an account and two browser entry ids; see
        $work/registry-seed.log and $registry_state"
say "browser registry seeded for $registry_email ($registry_entry_ids)"

# --- 3. device ------------------------------------------------------------
command -v adb >/dev/null 2>&1 || die "no adb -- enter nix develop <path-to-nixos-config>#android"
adb get-state >/dev/null 2>&1 || die "no device. Start one: ragedroid-emulator & ragedroid-wait-boot"
say "adb reverse tcp:$port (the app requires a loopback server, see header)"
adb reverse "tcp:$port" "tcp:$port" >/dev/null

# The journey starts at the welcome screen and signs in from scratch. AGP
# reinstalls the APK but does not clear app data, so a previous run's session
# would land the test on the vault list and every label lookup would miss.
say "uninstalling any previous $app_id so the app starts cold"
adb uninstall "$app_id" >/dev/null 2>&1 || true
adb uninstall "$app_id.test" >/dev/null 2>&1 || true

# --- 4. android journey ---------------------------------------------------
#
# `notPackage=ragewarden.ragedroid.journey` is applied by
# ragedroid/app/build.gradle.kts to every run that does NOT pass journeyServer,
# so a plain `gradle connectedFdroidDebugAndroidTest` skips this package instead
# of going red on missing arguments. Passing journeyServer below is what lifts
# that filter -- this script is the only way JourneyTest ever executes, which
# also means CI has to invoke this script or the assertions in it are
# decorative.
say "driving the app"
android_ok=1
( cd "$root/ragedroid" && gradle --no-daemon connectedFdroidDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.journey.JourneyTest \
    -Pandroid.testInstrumentationRunnerArguments.journeyServer="$server" \
    -Pandroid.testInstrumentationRunnerArguments.journeyEmail="$email" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPassword="$password" \
    -Pandroid.testInstrumentationRunnerArguments.journeyPhrase="$phrase" \
    -Pandroid.testInstrumentationRunnerArguments.journeyDecoyPhrase="$decoy_phrase" \
    -Pandroid.testInstrumentationRunnerArguments.journeyItem="$item" \
    -Pandroid.testInstrumentationRunnerArguments.journeySecret="$secret" \
    -Pandroid.testInstrumentationRunnerArguments.journeyRecipientCount="$recipient_count" \
    -Pandroid.testInstrumentationRunnerArguments.RAGEWARDEN_MOCK_HARDWARE=1 \
) >"$work/android.log" 2>&1 || android_ok=0

# BEFORE the failure branch, deliberately. The semantics tree captured at the
# moment of failure is the most informative record in the run, and it used to be
# the one record this script did not keep: the pull below sat after the `die`,
# so a red run left its trees only in ragedroid/app/build/outputs/, where the
# NEXT run silently overwrote them.
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
        # report.mjs renders a failed step with its `failure` field, so the page
        # is worth building even -- especially -- when the run is red.
        node "$here/report.mjs" "$out/journey.html" "$out/android" >/dev/null 2>&1 || true
        say "failure trees kept in $out/android (report: $out/journey.html)"
    fi
    die "android journey failed"
fi

[ -n "$pulled" ] || die "no journey artifacts were pulled back; see $work/android.log"

# --- 4b. registry-destruction guard ---------------------------------------
#
# A SECOND connectedAndroidTest, against the browser-seeded account from 2c.
# It exists because JourneyTest cannot reach `pushRecipientRegistry`: all four
# of that function's callers are enrolment paths, and the journey skips both
# enrolment steps ("skip passkey enrolment", "skip the backup recipient"), so
# until this run the most severe of the cross-client fixes had code that never
# executed under any test.
#
# THE TWO FILTERS. Each invocation names its own `class`, so the journey run
# cannot pull this test in and this run cannot pull the journey in. This one
# also passes no `journeyServer`, so ragedroid/app/build.gradle.kts additionally
# applies its `notPackage=ragewarden.ragedroid.journey` filter here -- belt and
# braces, in that order.
say "driving the registry-destruction guard"
adb uninstall "$app_id" >/dev/null 2>&1 || true
adb uninstall "$app_id.test" >/dev/null 2>&1 || true
registry_ok=1
( cd "$root/ragedroid" && gradle --no-daemon connectedFdroidDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.registry.RegistryPushInstrumentedTest \
    -Pandroid.testInstrumentationRunnerArguments.registryServer="$server" \
    -Pandroid.testInstrumentationRunnerArguments.registryEmail="$registry_email" \
    -Pandroid.testInstrumentationRunnerArguments.registryPassword="$registry_password" \
    -Pandroid.testInstrumentationRunnerArguments.registryBrowserEntryIds="$registry_entry_ids" \
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

# A GREEN gradle run is NOT enough. RegistryPushInstrumentedTest skips itself
# (JUnit assumption) when its instrumentation arguments are absent, so that a
# plain `gradle connectedFdroidDebugAndroidTest` does not go red for a reason
# that has nothing to do with the app -- and a skipped test reports success.
# Rename an argument above and, without this, the run stays green while nothing
# is being tested. That is the exact failure this whole pass exists to stop, so
# the result XML is read and one executed, non-skipped, passing case is
# required.
# Restricted to the XML, and to the XML that actually names this class: the same
# directory holds the journey's results and a plain-text runner log, and reading
# either of those would answer a question that was not asked.
registry_xml=$(find "$root/ragedroid/app/build/outputs/androidTest-results/connected" \
    -name '*.xml' -exec grep -l 'RegistryPushInstrumentedTest' {} + 2>/dev/null | head -n 1)
[ -n "$registry_xml" ] \
  || die "no androidTest result XML mentions RegistryPushInstrumentedTest -- the run reported
        success without the test existing on the device. See $work/registry.log"
cp "$registry_xml" "$out/registry-results.xml"
suite_line=$(grep -o '<testsuite [^>]*>' "$registry_xml")
suite_attr() {
    printf '%s' "$suite_line" | grep -o " $1=\"[^\"]*\"" | sed 's/^.*="//; s/"$//'
}
registry_tests=$(suite_attr tests)
registry_failures=$(suite_attr failures)
registry_errors=$(suite_attr errors)
registry_skipped=$(suite_attr skipped)
say "registry guard: tests=${registry_tests:-?} failures=${registry_failures:-?} errors=${registry_errors:-?} skipped=${registry_skipped:-?}"
[ "${registry_tests:-0}" -ge 1 ] \
  || die "the registry guard reported $registry_tests test cases. It did not run.
        See $out/registry-results.xml"
[ "${registry_skipped:-0}" -eq 0 ] \
  || die "the registry guard SKIPPED $registry_skipped of its $registry_tests case(s). That is
        its assumption firing, which means the instrumentation arguments above did not reach
        it -- the run is green and nothing was tested. See $out/registry-results.xml"
[ "${registry_failures:-0}" -eq 0 ] && [ "${registry_errors:-0}" -eq 0 ] \
  || die "the registry guard failed ($registry_failures failure(s), $registry_errors error(s)).
        See $out/registry-results.xml and $work/registry.log"

# The same server state, re-read as the BROWSER. Not redundant with the device
# assertion: `core::registry::find_marker_cipher` takes whichever marker the
# server returns FIRST, so with two markers on the server the phone and the
# browser can be reading different documents, and a device-only check could pass
# on the ordering. Two clients disagreeing is the failure being guarded against,
# so it is checked from both ends.
say "re-reading the seeded vault as the browser"
node "$here/seed-browser-registry.mjs" audit "$registry_state" \
    >"$work/registry-audit.log" 2>&1 || {
        tail -n 40 "$work/registry-audit.log" >&2
        cp "$work/registry-audit.log" "$out/registry-audit.log"
        die "the browser can no longer read its own registry after the phone enrolled;
        see $out/registry-audit.log"
    }
cp "$work/registry-audit.log" "$out/registry-audit.log"

# --- 5. browser half -- NOT IMPLEMENTED ------------------------------------
# This used to run `npx playwright test android-recovery`. No such spec exists --
# `--list` on that pattern returns "No tests found." It never fired because it
# was gated on a handoff file the Android journey does not write, so the script
# always took the skip branch and exited 0 with an honest-sounding message
# pointing at a target that was never there.
#
# Naming it again would be the same lie, so this section states the gap instead.
# Closing it needs two things that do not exist yet:
#
#   * ragemanifest/tests/playwright/tests/android-recovery.spec.ts -- sign the
#     extension in to $VAULTWARDEN_URL, enter a 24-word phrase, and reveal the
#     item, mirroring what JourneyTest does on the phone;
#   * a phone-generated phrase, if the goal is a ragedroid -> browser crossing
#     rather than a second consumer of the host's phrase. The device can mint one
#     (Settings -> "Recovery phrase"), but the journey does not walk that screen,
#     and a phrase this script already knows proves nothing about the phone.
#
# What IS proven above: rageterm wrote a secret, and ragedroid read it back from
# 24 typed words. That is one real direction of the cross-client story.
say "browser half: NOT IMPLEMENTED -- no android-recovery spec exists."
say "  The Android half above is complete and asserted; the browser half is a gap,"
say "  not a skip. See the comment at step 5 for exactly what is missing."

# --- 6. report ------------------------------------------------------------
say "rendering report"
node "$here/report.mjs" "$out/journey.html" "$out/android"

say "done: $out/journey.html"
