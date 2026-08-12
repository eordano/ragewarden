package ragewarden.ragedroid.journey

import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Semantics-tree journal for the end-to-end journey.
 *
 * Every interaction goes through [step], which records the accessibility
 * (Compose semantics) tree BEFORE the action and again AFTER it settles. The
 * pair is the point: a single "after" dump tells you what the app is showing,
 * but only the pair tells you what the tap actually did -- and whether the screen
 * gave the user any signal that it did anything at all.
 *
 * WHY TEXT AND NOT SCREENSHOTS. This harness used to capture PNGs, and all
 * fourteen frames of a run came back byte-identical -- 7,657 bytes of black, the
 * same sha256 for every one. That was blamed on the
 * emulator's software GPU -- the claim was that under
 * `-gpu swiftshader_indirect -no-window` the screenshot APIs return a constant
 * frame while host-side `adb exec-out screencap` works. THAT DIAGNOSIS WAS
 * WRONG, and it is worth spelling out because it sent someone chasing an
 * emulator bug that does not exist.
 *
 * The real cause is `ui/SecureWindow.kt`: MainActivity sets `FLAG_SECURE`, and
 * Android blanks screen capture for secure windows BY DESIGN. It is not the
 * GPU, not the capture API, and not headless mode. `adb exec-out screencap`
 * only appeared to work because it was tested against the launcher and the
 * Settings app, never against ragedroid. Point it at ragedroid and it returns
 * the same black frame -- reproduced by launching the app, waiting for
 * `mCurrentFocus=...ragewarden.ragedroid...`, and comparing the capture against one
 * taken of the launcher seconds later on the same emulator with the same
 * command: 15,580 bytes of black versus a 1,374,884-byte screenshot.
 *
 * Two things pin the cause to the flag rather than to the capture. `dumpsys
 * window` lists the ragedroid window as `fl=LAYOUT_IN_SCREEN SECURE ...`, and at
 * the same moment a `uiautomator dump` of that window returns the whole welcome
 * screen -- "RageDroid", "Begin setup", the four body paragraphs. The content is
 * there and the pixels are not, which is exactly what FLAG_SECURE promises and
 * nothing a GPU could produce.
 *
 * FLAG_SECURE is correct for a password manager and stays. The two honest ways
 * to annotate a journey through a secure window are a debug-only exemption
 * (`SecureWindow.kt` deliberately refuses one -- "a flag that is off in the build
 * you test with is a flag whose breakage you discover in release") or capturing
 * something other than pixels. This journal does the latter: the artifact is the
 * semantics tree, which is also what you author steps against, and which diffs
 * far more usefully than two screenshots ever did.
 *
 * The blind spot is real and worth knowing: the Compose semantics tree covers
 * what the app composes -- screens, sheets, dialogs and this app's toasts, which
 * are Compose state (`RageApp.showToast`), not `android.widget.Toast`. It does
 * NOT cover genuinely system-owned windows: the IME, the system permission
 * dialog, the Recents switcher. A step that hangs on one of those shows up here
 * as an unchanged tree, not as a picture of the dialog.
 *
 * Output goes to the directory AGP names in the `additionalTestOutputDir`
 * instrumentation argument, which it pulls back to
 *
 *     app/build/outputs/connected_android_test_additional_output/<variant>/connected/
 *
 * automatically when the run finishes:
 *
 *     journey/<name>/manifest.json      ordered step records
 *     journey/<name>/001-before-<slug>.txt
 *     journey/<name>/001-after-<slug>.txt
 *
 * Writing to `getExternalFilesDir()` instead looks like it works -- the files
 * appear, the test passes -- and then AGP UNINSTALLS the app when the run ends,
 * taking /sdcard/Android/data/<applicationId>/ with it. The artifacts are gone
 * before anyone can `adb pull` them, and the only symptom is an empty
 * directory. The fallback below is kept for running under a bare `am instrument`
 * where AGP is not orchestrating, but the AGP path is the one that survives.
 *
 * `manifest.json` is what `tests/journey/report.mjs` renders into the annotated
 * HTML.
 *
 * @param tree supplies the current semantics tree as text. It is the caller's
 *   job to make it idle-safe -- [JourneyTest] waits for Compose to settle inside
 *   the supplier, because the journal has no handle on the Compose rule.
 */
class Journal(private val name: String, private val tree: () -> String) {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private val dir: File = run {
        val agpDir = InstrumentationRegistry.getArguments()
            .getString("additionalTestOutputDir")
            ?.takeIf { it.isNotBlank() }
        val base = if (agpDir != null) {
            File(agpDir, "journey")
        } else {
            File(
                instrumentation.targetContext.getExternalFilesDir("journey")
                    ?: error(
                        "no additionalTestOutputDir argument and no external files dir -- " +
                            "the journey harness has nowhere to write its artifacts"
                    ),
                ""
            )
        }
        File(base, name).apply {
            deleteRecursively()
            mkdirs()
        }
    }

    private val steps = JSONArray()
    private var counter = 0

    /** Free-text annotation attached to the next step, e.g. a UX observation. */
    private var pendingNote: String? = null

    fun note(text: String) {
        pendingNote = if (pendingNote == null) text else "${pendingNote}\n$text"
    }

    /**
     * Record one interaction.
     *
     * [action] should be a single user-visible act -- one tap, one text entry.
     * Splitting a flow into fine steps is the whole value of the artifact; a
     * step that does five things produces a before/after pair that explains
     * nothing.
     */
    fun <T> step(label: String, action: () -> T): T {
        counter += 1
        val slug = slug(label)
        val before = capture("%03d-before-%s".format(counter, slug))
        val startedAt = System.currentTimeMillis()
        var failure: String? = null
        val result = try {
            action()
        } catch (t: Throwable) {
            failure = "${t.javaClass.simpleName}: ${t.message ?: "(no message)"}"
            // Capture the failed state before rethrowing -- the tree at the moment
            // of failure is usually the most informative record in the run, and it
            // is the one that says which label the test was looking for and what
            // the screen was actually offering instead.
            record(label, before, capture("%03d-after-%s".format(counter, slug)), startedAt, failure)
            write()
            throw t
        }
        val after = capture("%03d-after-%s".format(counter, slug))
        record(label, before, after, startedAt, null)
        write()
        return result
    }

    /** A screen state worth recording that no interaction produced. */
    fun snapshot(label: String) {
        counter += 1
        val slug = slug(label)
        val shot = capture("%03d-state-%s".format(counter, slug))
        record(label, null, shot, System.currentTimeMillis(), null)
        write()
    }

    private fun record(label: String, before: String?, after: String, at: Long, failure: String?) {
        steps.put(
            JSONObject().apply {
                put("n", counter)
                put("label", label)
                put("before", before ?: JSONObject.NULL)
                put("after", after)
                put("at", at)
                put("durationMs", System.currentTimeMillis() - at)
                put("note", pendingNote ?: JSONObject.NULL)
                put("failure", failure ?: JSONObject.NULL)
            }
        )
        pendingNote = null
    }

    /** Capture the current semantics tree. */
    private fun capture(fileName: String): String {
        val out = File(dir, "$fileName.txt")
        val text = tree()
        // An empty dump means the activity is gone or the root has no semantics --
        // fail here rather than write a file that the report will happily render
        // as "nothing changed".
        check(text.isNotBlank()) {
            "empty semantics tree at step $counter ($fileName) -- the activity is " +
                "probably not in the foreground"
        }
        out.writeText(text)
        return out.name
    }

    private fun write() {
        File(dir, "manifest.json").writeText(
            JSONObject().apply {
                put("journey", name)
                // The browser half of the journey emits PNG artifacts; this one emits
                // semantics trees. report.mjs renders whichever it is given, so say
                // which rather than making it guess from file extensions alone.
                put("artifact", "semantics")
                put("steps", steps)
            }.toString(2)
        )
    }

    /**
     * Hand a value back to the orchestrator.
     *
     * Used for the trees a human needs in order to author the NEXT steps, and
     * for anything a second client would consume. Safe ONLY because this runs
     * against a throwaway account on a loopback server -- see the header of
     * JourneyTest.
     */
    fun handoff(key: String, value: String) {
        File(dir, "handoff-$key.txt").writeText(value)
    }

    private fun slug(label: String): String =
        label.lowercase()
            .map { if (it.isLetterOrDigit()) it else '-' }
            .joinToString("")
            .replace(Regex("-+"), "-")
            .trim('-')
            .take(48)
}
