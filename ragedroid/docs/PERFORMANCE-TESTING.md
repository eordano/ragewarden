# Android performance testing -- playbook

How to measure ragedroid perf, change something, and prove the change actually
helped. Most of the rules below are scars from the bench loops in this repo;
they exist because the obvious approach silently produced wrong numbers.

## TL;DR loop

```
1. capture BASELINE numbers on the unchanged code
2. apply ONE change
3. capture NEW numbers under identical conditions
4. compare percentile-by-percentile
5. if no real win OR a regression -> revert; otherwise commit and iterate
```

Always measure before and after. Never claim a perf change without numbers, and
never claim numbers without acknowledging the noise floor.

---

## Tooling

* **`androidx.benchmark.macro`** -- drives the app via UIAutomator, captures
  `FrameTimingMetric` (per-frame durations + over-budget overruns),
  `StartupTimingMetric` (cold/warm start), and `TraceSectionMetric`
  (custom-named sections you instrument with `androidx.tracing`).
* **`:baselineprofile` Gradle module** -- already configured. Holds
  `Macrobenchmark.kt` (bench tests) and `BaselineProfileGenerator.kt`
  (AOT-profile capture, separate concern).
* **`androidx.tracing-ktx`** -- the in-app side: `trace("section.name") { ... }`
  emits ATrace markers that perfetto picks up and `TraceSectionMetric` reads.

The bench requires a `benchmark` build type on `:app` with
`isProfileable = true` and a debug-keyed signing config. That's already wired.
Don't try to bench the regular `release` build -- without `profileable` you'll
get "ERRORS (not suppressed): PROFILEABLE".

---

## Step 1 -- get a baseline

```bash
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_SDK_ROOT=$ANDROID_HOME
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/29.0.14206865
export ANDROID_NDK_ROOT=$ANDROID_NDK_HOME
export PATH=$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:~/.cargo/bin:$PATH
export ANDROID_SERIAL=emulator-5554
export ADB_MDNS=0          # see "emulator gotchas" below

cd ragedroid
./gradlew :baselineprofile:connectedStandardBenchmarkBenchmarkAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=ragewarden.ragedroid.baselineprofile.Macrobenchmark \
  -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.suppressErrors=EMULATOR \
  > /tmp/bench-before.log 2>&1
```

Result lands at:

```
ragedroid/baselineprofile/build/outputs/connected_android_test_additional_output/standardBenchmarkBenchmark/connected/<device>/ragewarden.ragedroid.baselineprofile-benchmarkData.json
```

Save that JSON aside (`cp .../*-benchmarkData.json /tmp/bench-before.json`)
before iterating -- gradle overwrites it on the next run.

### What's in the JSON

* `metrics["timeToInitialDisplayMs"].runs` -- one value per iteration, for
  cold-start tests.
* `metrics["ragewarden.<sectionName>SumMs"].runs` -- one value per iteration
  for `TraceSectionMetric`.
* `sampledMetrics["frameDurationCpuMs"].runs` -- nested array, one inner array
  per iteration with one entry per frame.

To compute percentiles cleanly, flatten `sampledMetrics`'s nested arrays into
one big list before taking p50/p75/p90/p95.

---

## Step 2 -- apply ONE change at a time

Multiple changes in flight = you can't tell which one moved the number.
Commit between changes so the working tree always matches a runnable state.

The kinds of changes that show up in macrobench:
* **moves work off Main** (sync->async, JNI on `Dispatchers.IO`, TOTP loop
  off the Compose frame clock) -- visible in `frameDurationCpuMs` /
  `frameOverrunMs` percentiles, especially the tail.
* **caches a redundant op** (in-flight `Deferred` for repeated
  `fetchVault`, snapshot dedup against the last response bytes) -- visible
  in `TraceSectionMetric` count and sum if the section is on the cached
  path.
* **changes UI structure** (replacing `Column.fillMaxSize` with
  `LazyColumn`, hoisting state out of composition) -- visible in
  `frameDurationCpuMs` and recomposition tracing.

The kinds that don't show up:
* removing a comment, renaming a variable, refactoring without changing the
  call graph -- don't bother running the bench.
* changes to a code path the bench doesn't traverse -- see "selectors that
  actually work" below.

---

## Step 3 -- capture new numbers

Run the same command. **Make sure the device state is the same**:
* same emulator, same AVD, same API level.
* no other heavy process on the host (browser tabs, Slack notifications all
  add to host-CPU contention which the emulator inherits).
* `adb devices` shows exactly the device you intend to bench. See
  "emulator gotchas".

If you're comparing against a previous commit, use `git worktree` instead
of `git checkout -- file`:

```bash
git worktree add /tmp/ragewarden-before <baseline-commit-sha>
# copy build files that aren't tracked (gradlew, wrapper jar)
cp ragedroid/gradlew /tmp/ragewarden-before/ragedroid/gradlew
cp ragedroid/gradle/wrapper/gradle-wrapper.jar /tmp/ragewarden-before/ragedroid/gradle/wrapper/
# also copy the bench code if you've added new tests since the baseline
cp ragedroid/baselineprofile/src/main/kotlin/.../Macrobenchmark.kt \
   /tmp/ragewarden-before/ragedroid/baselineprofile/src/main/kotlin/.../Macrobenchmark.kt
# now run the bench from the worktree without disturbing your main checkout
cd /tmp/ragewarden-before/ragedroid && ./gradlew ...
git worktree remove /tmp/ragewarden-before --force
```

Worktrees mean your main checkout is unaffected -- never `git checkout HEAD~5
-- file` on a working tree the user might be editing.

---

## Step 4 -- compare percentile by percentile

Don't compare averages. Don't eyeball the JSON. Compute p50/p75/p90/p95
for both runs and look at the deltas.

```python
def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p
    lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)
```

For sampled metrics, flatten across iterations first:
`flat = [x for run in metric["runs"] for x in run]`.

### Reading the deltas

* p50 changing by <= 5-10% on emulator: probably noise, not signal. Increase
  iterations or move to a real device.
* p95 changing more than p50: tail behavior changed -- typical sign of a
  thread-blocking fix (the worst frames got better, median didn't).
* a metric the change can't possibly affect (e.g. cold start when you only
  touched detail-screen code) shifting by 5-10%: that's your noise floor.
  Anything else needs to clear that bar to be a real signal.

---

## Step 5 -- iterate or rollback

Rollback is fast: `git revert <sha>` and rebuild. Don't try to "fix" a
change whose numbers came back ambiguous -- start clean and try a smaller
slice.

If a change shows a real win, commit it standalone, push the bench JSON
into git or a pinned scratch path, and move to the next one.

---

## Things to be conscious of

### Selectors that actually work

UIAutomator `By.descContains(...)` matches the Android `contentDescription`
attribute. Compose `Text(...)` composables produce **no** content
description by default; their text only flows through the semantic `text`
property. Use:

```kotlin
device.findObject(By.text("Reveal"))      // correct for Compose Text
```

...not `By.descContains("Reveal")` -- that finds nothing and returns null,
and your bench silently no-ops because `null?.click()` is fine.

To verify a selector reaches the right node, dump the live UI and grep:

```bash
adb -s emulator-5554 shell uiautomator dump /sdcard/ui.xml
adb -s emulator-5554 shell cat /sdcard/ui.xml > /tmp/ui.xml
grep -oE 'text="[^"]+"' /tmp/ui.xml | sort -u
```

If multiple sibling Composables show the same text (e.g. an action button
labeled "Reveal" and a row inside `InlineTapReveal` also labeled "Reveal
on screen"), pick the more specific text or wrap the target with
`Modifier.testTag(...)` and select via `By.res(packageName, "tag")`.

### Frame budgets vs. trace sections

`FrameTimingMetric` answers "did frames hit the 16.67 ms budget while the
bench was running?". `TraceSectionMetric` answers "how long did this
specific code path take?". They're complementary:

* a synchronous JNI call on Main can blow `frameOverrunMs` p95 even if its
  own `TraceSectionMetric` is sub-millisecond.
* moving the same call off Main keeps `TraceSectionMetric` identical
  (same work) but lifts `frameOverrun` percentiles.

Wrap any JNI/IO/crypto path you suspect is on the hot path with
`androidx.tracing.trace("ragewarden.<name>") { ... }`. Then add
`TraceSectionMetric("ragewarden.<name>", Mode.Sum)` to the bench. Without
the trace markers you're blind to where time goes.

### "Did the bench actually run my flow?"

If `ragewarden.<section>Count` is 0, the UI driving in your `measureBlock`
didn't reach the instrumented code path. Common causes:

* selector typo (returns null, click no-ops).
* missing prerequisite (e.g. fresh install lands on `OnboardingScreen` --
  see `skipOnboardingIfPresent()` in `Macrobenchmark.kt`).
* the action gated behind a state condition that's not met (e.g.
  `IdlePasswordCard` only opens `InlineTapReveal` when `item.rage == true`).

Confirm by manual repro: install the bench's target APK, drive the same
sequence by hand with `adb shell input tap`, and check `atrace --async_dump`
for the section you expect:

```bash
adb shell atrace --async_start -a ragewarden.ragedroid -b 4096 view input
# do the action manually
adb shell atrace --async_dump > /tmp/atrace.out
adb shell atrace --async_stop
grep ragewarden /tmp/atrace.out
```

If the section appears here but not in the macrobench output -> bench
flow problem. If neither has it -> the trace marker isn't reaching the
code path.

### UI sloppiness vs. data correctness

Macrobench measures UI smoothness. It does **not** assert that the data
shown after a tap is correct. A bench that drives Reveal -> Authorize ->
Hide for 3 cycles per iteration will still pass even if the password
revealed is the wrong one. Add an Espresso/UIAutomator assertion on the
revealed text content if you're touching the data path, not just dispatch.

### Transitions are noisy

Most p95 frame overruns happen during transitions (open detail pane,
collapse `InlineTapReveal`, dismiss soft keyboard). They are not "the
work I just made faster" -- they are Compose layout + animation cost.
Don't chase them as a perf win unless you also touched layout.

### Emulator gotchas

* **mDNS auto-connect for nearby devices**: a real Pixel on the LAN with
  `wireless debugging` enabled will auto-attach to `adb`. Gradle's
  `connectedAndroidTest` runs on every connected device, so a tenth of
  your bench iteration runs on a different device with different perf.
  `export ADB_MDNS=0` before running gradle, and `adb disconnect` any
  TLS-paired devices.
* **API 36 vs the macrobench parser**: `androidx.benchmark` 1.3.x parses
  `dumpsys gfxinfo framestats` and silently fails on API 36 emulators
  (returns `[]`, prints "Unable to confirm activity launch completion").
  Pin to **1.4.1+**.
* **`isProfileable` warning**: if you see `ERRORS (not suppressed): PROFILEABLE`,
  you're benching a build type that didn't get `isProfileable = true`. Use
  `:app:assembleStandardBenchmark`, not `assembleStandardRelease`.
* **Frame budget on emulator is fiction**: emulated GPUs render frames in
  ~2-4x real-device time. Use the emulator for *relative* before/after
  deltas. Use a real device for absolute "feels snappy at p95" claims.
* **Two consecutive runs jitter +/-5-10% on cold start** even with no code
  change. That's your noise floor; ignore deltas inside it.
* **Output piping**: never `gradle ... | tail -N` or pipe through `head`.
  When the build fails the diagnostic is 30-200 lines above the FAILURE
  banner; tail eats it. Redirect to a file: `> /tmp/bench.log 2>&1`, then
  `grep` over the file.

### Real device > emulator

Connect a Pixel over USB or wireless debugging, and the same `connectedAndroidTest`
task targets it. Variance drops 2-3x immediately. Use this when the emulator's
noise floor is masking your delta.

---

## Building + deploying for manual testing

Sometimes you need to drive the app by hand on a real device -- to verify
correctness, check IME insets, confirm autofill works on a real form.

```bash
# build the standard-debug APK
./gradlew :app:assembleStandardDebug

# install on a connected device
adb -s <serial> install -r app/build/outputs/apk/standard/debug/app-standard-debug.apk

# launch
adb -s <serial> shell am start -n ragewarden.ragedroid/.MainActivity

# screenshot back to the host (scaled for inline display)
adb -s <serial> exec-out screencap -p > /tmp/pixel.png
sips -Z 540 /tmp/pixel.png --out /tmp/pixel-half.png   # macOS

# logcat for the running app
APP_PID=$(adb -s <serial> shell pidof ragewarden.ragedroid | tr -d '\r\n')
adb -s <serial> logcat -d --pid=$APP_PID
```

A standard-debug build won't be representative for perf timing -- JIT, no
baseline profile, debuggable -- but it's exactly right for "does this UI
work end-to-end".

---

## Custom trace-section conventions

Always namespace with `ragewarden.`. That makes it trivial to grep the
perfetto trace and avoids collisions with system / framework markers:

```kotlin
import androidx.tracing.trace

trace("ragewarden.decrypt") { decryptPassword(itemId) }
trace("ragewarden.fetchVault") { RageNative.fetchVault(blob) }
trace("ragewarden.parseSnapshot") { VaultSnapshot.fromJsonObject(obj) }
trace("ragewarden.totp") { generateTotp(seed) }
```

In the bench:

```kotlin
import androidx.benchmark.macro.ExperimentalMetricApi
import androidx.benchmark.macro.TraceSectionMetric

@OptIn(ExperimentalMetricApi::class)
@Test fun foo() = rule.measureRepeated(
    metrics = listOf(
        FrameTimingMetric(),
        TraceSectionMetric("ragewarden.decrypt", TraceSectionMetric.Mode.Sum),
    ),
    iterations = 20,
    ...
)
```

`Mode.Sum` totals time across all invocations within one iteration.
`Mode.First` / `Mode.Min` / `Mode.Max` / `Mode.Average` are also available;
pick the one that maps to the question you want to answer.

---

## Iteration count and noise

* **20 iters** on emulator -- coarse, ~5-10% noise floor on aggregate
  metrics. Fine for "is this win > 15% or not?".
* **50 iters** on emulator -- ~3% noise floor. Most repo-resident benches
  use this.
* **20 iters on a real device** -- typically tighter than 50 on emulator.
* **100 iters** -- overnight run, rarely worth it unless chasing a
  sub-3% claimed win.

If you're not sure whether a delta is noise or signal, run the same
benchmark twice with no code change in between. The variance you see
between two consecutive runs of the same code IS your noise floor.

---

## When the numbers are mixed

Sometimes a change improves p50 and worsens p95, or vice versa. Don't
average them. Read what each percentile is telling you:

* **p50 better, p95 same or worse**: typical median frame is faster but
  the worst-case path didn't change. Often happens when a hot loop got
  faster but a rare allocation or first-frame setup didn't.
* **p50 same, p95 better**: tail latencies tightened -- typical of moving
  blocking work off Main, removing a redundant call on a slow path, or
  capping queue size.
* **p50 worse, p95 better**: rarer. Usually a coarser-grained fix
  (longer median timeslice but no extreme tails). Often acceptable for
  "feels snappy" goals -- you'd rather have many slightly slow frames
  than one frozen second.

Decide based on the user-perceived axis. "Tap-to-feedback" cares about
p95 more than p50. "Continuous scrolling smoothness" cares about p50
more than p95. Pick the metric that matches the experience and judge
the trade-off.
