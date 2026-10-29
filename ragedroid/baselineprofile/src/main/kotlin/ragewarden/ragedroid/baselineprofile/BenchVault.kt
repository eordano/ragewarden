package ragewarden.ragedroid.baselineprofile

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until

/**
 * Brings the app to its vault list on a real account: the journey's Vaultwarden
 * account and its unprotected item, passed by tests/journey/run.sh as the
 * bench* instrumentation arguments. Every selector is a test tag exposed as a
 * resource id (MainActivity sets testTagsAsResourceId) or visible text, and a
 * selector that finds nothing fails the run instead of skipping the step.
 */
object BenchVault {
    private val args get() = InstrumentationRegistry.getArguments()

    /** The app under test; each flavour of this module sets its own (build.gradle.kts). */
    val packageName: String get() = arg("benchPackage")
    /** Spaces travel as underscores: AGP hands `am instrument` its arguments unquoted. */
    val item: String get() = arg("benchItem").replace('_', ' ')
    private val server get() = arg("benchServer")
    private val email get() = arg("benchEmail")
    private val password get() = arg("benchPassword")

    const val LIST = "vault-list"
    const val REVEAL = "action-reveal"
    const val HIDE = "password-hide"
    const val UI_TIMEOUT_MS = 20_000L
    private const val SIGN_IN_TIMEOUT_MS = 90_000L

    fun launch(device: UiDevice) {
        device.executeShellCommand("am start -W -n $packageName/ragewarden.ragedroid.MainActivity")
    }

    fun openVault(device: UiDevice) {
        val deadline = System.currentTimeMillis() + SIGN_IN_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            when {
                device.hasObject(By.res(LIST)) && itemInView(device) != null -> return
                device.hasObject(By.text("Begin setup")) -> device.findObject(By.text("Begin setup")).click()
                device.hasObject(By.res("signin-server")) -> {
                    device.findObject(By.res("signin-server")).text = server
                    device.findObject(By.res("signin-email")).text = email
                    device.findObject(By.res("signin-password")).text = password
                    device.findObject(By.text("Sign in & continue")).click()
                    device.wait(Until.gone(By.res("signin-server")), SIGN_IN_TIMEOUT_MS)
                }
                device.hasObject(By.text("Skip -- set up later")) -> device.findObject(By.text("Skip -- set up later")).click()
                device.hasObject(By.text("Skip -- I'll add later")) -> device.findObject(By.text("Skip -- I'll add later")).click()
                device.hasObject(By.text("Open vault")) -> device.findObject(By.text("Open vault")).click()
                device.hasObject(By.res("lock-password")) -> {
                    val box = device.findObject(By.res("lock-password"))
                    (box.findObject(By.clazz("android.widget.EditText")) ?: box).text = password
                    device.findObject(By.text("Unlock")).click()
                    device.wait(Until.gone(By.res("lock-password")), SIGN_IN_TIMEOUT_MS)
                }
                device.hasObject(By.text("Not now")) -> device.findObject(By.text("Not now")).click()
                else -> device.wait(Until.hasObject(By.res(LIST)), 1_000)
            }
            device.waitForIdle()
        }
        error("the vault list with '$item' did not appear within ${SIGN_IN_TIMEOUT_MS}ms")
    }

    /** The item's row, scrolled into view during setup: the seeded list is longer than a screen. */
    fun itemRow(device: UiDevice): UiObject2 =
        itemInView(device) ?: error("'$item' is not in the vault list")

    private fun itemInView(device: UiDevice): UiObject2? {
        val row = By.text(item)
        device.findObject(row)?.let { return it }
        val list = device.findObject(By.res(LIST)) ?: return null
        return list.scrollUntil(Direction.UP, Until.findObject(row)) ?: list.scrollUntil(Direction.DOWN, Until.findObject(row))
    }

    fun find(device: UiDevice, selector: BySelector, what: String): UiObject2 =
        device.wait(Until.findObject(selector), UI_TIMEOUT_MS) ?: error("$what did not appear within ${UI_TIMEOUT_MS}ms")

    private fun arg(name: String): String =
        args.getString(name)?.takeIf { it.isNotBlank() }
            ?: error("instrumentation argument '$name' is missing; tests/journey/run.sh (JOURNEY_BENCH=1) supplies it")
}
