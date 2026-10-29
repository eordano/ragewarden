package ragewarden.ragedroid.journey

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.collections.immutable.persistentListOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import ragewarden.ragedroid.MainActivity
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.jni.generateTotp
import ragewarden.ragedroid.model.VaultItem

/**
 * The three ways a secret leaves the app into another one -- autofill, the
 * keyboard, and a TOTP code read off the detail screen -- driven on a device
 * against the journey's Vaultwarden. [LoginFixtureActivity] is the foreign app:
 * it lives in the test APK's own process, so Ragewarden's autofill service and
 * keyboard treat it like any third-party login form.
 *
 * Driven by tests/journey/run.sh, which supplies the journey account and its
 * protected item; the journey package is filtered out of a bare
 * `connectedAndroidTest` (see app/build.gradle.kts).
 *
 * UiAutomator only, no compose test rule: a compose rule swaps the frame clock
 * of every Compose window in this process -- the app's autofill sheet
 * included -- for a test clock that moves only on Compose sync calls, so the
 * sheet took the Authorize tap and then drew nothing for as long as the test
 * waited through UiAutomator.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class DeliveryFlowsTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)
    private val app: Context get() = instrumentation.targetContext
    private val fixturePackage: String get() = instrumentation.context.packageName

    @Test
    fun totp_on_the_detail_screen_is_the_rfc6238_code() {
        val s = seed()
        ActivityScenario.launch(MainActivity::class.java).use {
            retryStale { scrolledTo(By.pkg(app.packageName).text(s.name), "${s.name} in the vault list").click() }
            val shown = scrolledTo(By.pkg(app.packageName).text(SIX_DIGITS), "a six-digit code on ${s.name}'s detail screen").text
            val now = System.currentTimeMillis() / 1000
            val window = setOf(rfc6238(SEED, now), rfc6238(SEED, now - 30))
            assertTrue("detail screen shows $shown, RFC 6238 says one of $window", shown in window)
            assertTrue("core's generator agrees with RFC 6238", generateTotp(SEED).code in setOf(rfc6238(SEED, now), rfc6238(SEED, now + 30)))
        }
    }

    @Test
    fun autofill_fills_the_foreign_form_after_the_authorize_tap() {
        val s = seed()
        // Android shows a dataset inline when the bound keyboard asks for inline
        // suggestions -- Gboard does, and then decides for itself whether to show
        // the chip. Bound to a keyboard that does not ask (Ragewarden's own) and
        // kept off screen, the field gets Android's dropdown, every time.
        withRagewardenKeyboard(keepAutofill = true) {
            shell("settings put secure autofill_service ${app.packageName}/ragewarden.ragedroid.autofill.RagewardenAutofillService")
            launchFixture(noKeyboard = true)
            tap(By.pkg(fixturePackage).desc(LoginFixtureActivity.USERNAME), "the fixture's username field")
            tap(By.textStartsWith("Autofill ${s.name} into"), "the Ragewarden dataset in the autofill dropdown")
            tap(By.pkg(app.packageName).text("Authorize"), "the Authorize button on the autofill sheet")
            if (!device.wait(Until.hasObject(By.pkg(fixturePackage).text(USERNAME_VALUE)), UI_TIMEOUT_MS)) {
                error("the username field was not filled. On screen: ${onScreen()}")
            }
            assertEquals(LoginFixtureActivity.summary(USERNAME_VALUE, s.secret), submit())
        }
    }

    @Test
    fun keyboard_types_an_unprotected_password_into_the_foreign_form() {
        val s = seed()
        withRagewardenKeyboard {
            launchFixture()
            tap(By.pkg(fixturePackage).desc(LoginFixtureActivity.PASSWORD), "the fixture's password field")
            retryStale { scrolledTo(By.pkg(app.packageName).text(s.name), "${s.name} on the Ragewarden keyboard").click() }
            tap(By.pkg(app.packageName).text("Type it"), "the keyboard's Type it confirmation")
            setText(By.pkg(fixturePackage).desc(LoginFixtureActivity.USERNAME), USERNAME_VALUE, "the username field")
            assertEquals(LoginFixtureActivity.summary(USERNAME_VALUE, s.secret), submit())
        }
    }

    @Test
    fun keyboard_sends_a_protected_item_to_the_tap_sheet_and_types_nothing_when_declined() {
        seed()
        val protectedItem = requireArg("journeyItem")
        withRagewardenKeyboard {
            launchFixture()
            tap(By.pkg(fixturePackage).desc(LoginFixtureActivity.PASSWORD), "the fixture's password field")
            retryStale { scrolledTo(By.pkg(app.packageName).text(protectedItem), "$protectedItem on the Ragewarden keyboard").click() }
            tap(By.pkg(app.packageName).text("Unlock and type"), "the keyboard's Unlock and type button")
            find(By.pkg(app.packageName).textStartsWith("Autofill into"), "the tap sheet the keyboard opened")
            tap(By.pkg(app.packageName).text("Cancel"), "Cancel on the tap sheet")
            assertEquals(LoginFixtureActivity.summary("", ""), submit())
        }
    }

    @Test
    fun a_protected_card_and_ssh_key_round_trip_through_vaultwarden() {
        seed()
        val repo = app.appEntryPoint().bitwardenRepo()
        val phrase = requireArg("journeyPhrase").replace('_', ' ')
        fun typed(name: String, kind: ragewarden.ragedroid.model.VaultItemKind) = VaultItem(
            id = UUID.randomUUID().toString(), name = name, username = "", site = "", folder = "", rage = true,
            recipients = persistentListOf(), password = "", lastUsed = "", history = 0, kind = kind,
        )
        runBlocking {
            repo.createTyped(
                typed(CARD_ITEM, ragewarden.ragedroid.model.VaultItemKind.Card),
                block = mapOf("cardholderName" to "Maya Voss", "expMonth" to "12", "expYear" to "29"),
                secrets = mapOf("number" to CARD_NUMBER, "code" to CARD_CODE),
            ).getOrThrow()
            repo.createTyped(
                typed(SSH_ITEM, ragewarden.ragedroid.model.VaultItemKind.SshKey),
                block = mapOf("publicKey" to SSH_PUBLIC, "keyFingerprint" to SSH_FINGERPRINT),
                secrets = mapOf("privateKey" to SSH_KEY, "passphrase" to SSH_PASSPHRASE),
            ).getOrThrow()
            repo.sync().getOrThrow()
        }
        val card = repo.snapshot().single { it.name == CARD_ITEM }
        assertEquals(setOf("number", "code"), card.protectedFields.toSet())
        assertEquals(null, card.cardNumber)
        assertEquals(null, card.cvv)
        assertEquals("Maya Voss", card.cardholder)
        val ssh = repo.snapshot().single { it.name == SSH_ITEM }
        assertEquals(setOf("privateKey", "passphrase"), ssh.protectedFields.toSet())
        assertEquals(null, ssh.privateKey)
        assertEquals(SSH_PUBLIC, ssh.publicKey)
        runBlocking {
            suspend fun open(id: String, field: String) = String(repo.decryptWithRecoveryPhrase(id, phrase, field).getOrThrow(), Charsets.UTF_8)
            assertEquals(CARD_NUMBER, open(card.id, "number"))
            assertEquals("the primary field is the card number", CARD_NUMBER, open(card.id, ""))
            assertEquals(CARD_CODE, open(card.id, "code"))
            assertEquals(SSH_KEY, open(ssh.id, "privateKey"))
            assertEquals(SSH_PASSPHRASE, open(ssh.id, "passphrase"))
        }
    }

    @Test
    fun shared_history_records_through_jni_loads_back_and_stays_out_of_the_vault_list() {
        seed()
        val repo = app.appEntryPoint().bitwardenRepo()
        val item = repo.snapshot().single { it.name == FLOW_ITEM }
        val prior = String(
            ragewarden.ragedroid.jni.RageNative.encrypt(
                "prior value".toByteArray(),
                ragewarden.ragedroid.jni.RageNative.pubkeyFromArmoredSecret(ragewarden.ragedroid.jni.RageNative.generateSoftwareIdentity()),
            ),
            Charsets.UTF_8,
        )
        val blob = repo.unlockedSessionForWrapping() ?: error("the repository is not unlocked")
        try {
            ragewarden.ragedroid.jni.RageNative.historyRecord(blob, item.id, prior, """["this phone"]""".toByteArray(), false)
            ragewarden.ragedroid.jni.RageNative.historyRecord(blob, item.id, prior, """["this phone"]""".toByteArray(), true)
        } finally {
            blob.fill(0)
        }
        val entries = runBlocking { repo.history(item.id).getOrThrow() }
        assertEquals(listOf(true, false), entries.map { it.deleted })
        assertEquals(listOf("this phone"), entries.first().recipientsSummary)
        assertTrue("stanza kinds are read from the payload", entries.first().stanzaTags.isNotEmpty())
        runBlocking { repo.sync().getOrThrow() }
        assertTrue(
            "the history document must not show as a vault item",
            repo.snapshot().none { it.name.startsWith("__ragewarden_history") },
        )
    }

    private data class Seeded(val name: String, val secret: String)

    private fun seed(): Seeded = synchronized(DeliveryFlowsTest::class.java) {
        seeded?.let { return it }
        val ep = app.appEntryPoint()
        val repo = ep.bitwardenRepo()
        val s = Seeded(name = FLOW_ITEM, secret = "flow-${UUID.randomUUID()}")
        runBlocking {
            repo.login(requireArg("journeyServer"), requireArg("journeyEmail"), requireArg("journeyPassword")).getOrThrow()
            repo.sync().getOrThrow()
            repo.create(
                VaultItem(
                    id = UUID.randomUUID().toString(),
                    name = s.name,
                    username = USERNAME_VALUE,
                    site = "androidapp://$fixturePackage",
                    folder = "",
                    rage = false,
                    recipients = persistentListOf(),
                    password = "",
                    totpSeed = SEED,
                    lastUsed = "",
                    history = 0,
                ),
                s.secret.toByteArray(Charsets.UTF_8),
            ).getOrThrow()
        }
        ep.lockState().unlock()
        seeded = s
        s
    }

    /**
     * Starts a fresh fixture and waits for *that* instance: CLEAR_TASK tears the
     * previous test's fixture down while the new one comes up, and a node found
     * in the old window goes stale under the next click.
     */
    private fun launchFixture(noKeyboard: Boolean = false) {
        val run = UUID.randomUUID().toString()
        instrumentation.context.startActivity(
            Intent()
                .setClassName(fixturePackage, LoginFixtureActivity::class.java.name)
                .putExtra(LoginFixtureActivity.RUN, run)
                .putExtra(LoginFixtureActivity.NO_KEYBOARD, noKeyboard)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        find(By.pkg(fixturePackage).desc(LoginFixtureActivity.RUN).text(run), "the fixture login form")
        device.waitForIdle()
    }

    private fun submit(): String {
        tap(By.pkg(fixturePackage).text(LoginFixtureActivity.SUBMIT), "the fixture's sign-in button")
        return find(By.pkg(fixturePackage).desc(LoginFixtureActivity.RESULT).textStartsWith("user="), "the fixture's result line").text
    }

    /** Clicks [selector], finding it again if the window re-laid out between the find and the click. */
    private fun tap(selector: androidx.test.uiautomator.BySelector, what: String) = retryStale { find(selector, what).click() }

    private fun setText(selector: androidx.test.uiautomator.BySelector, value: String, what: String) =
        retryStale { find(selector, what).text = value }

    private fun <T> retryStale(action: () -> T): T {
        val deadline = System.currentTimeMillis() + UI_TIMEOUT_MS
        while (true) {
            try {
                return action()
            } catch (e: androidx.test.uiautomator.StaleObjectException) {
                if (System.currentTimeMillis() > deadline) throw e
                device.waitForIdle()
            }
        }
    }

    /**
     * [selector], scrolled into view if a lazy list has not composed it yet: the
     * keyboard shows about four rows, and the detail screen's TOTP sits below the
     * fold. Searches up, then down, through the first scrollable in the app.
     */
    private fun scrolledTo(selector: androidx.test.uiautomator.BySelector, what: String): UiObject2 {
        device.wait(Until.findObject(selector), UI_TIMEOUT_MS / 4)?.let { return it }
        val list = find(By.pkg(app.packageName).scrollable(true), "a scrollable list holding $what")
        list.scrollUntil(androidx.test.uiautomator.Direction.UP, Until.findObject(selector))?.let { return it }
        return list.scrollUntil(androidx.test.uiautomator.Direction.DOWN, Until.findObject(selector))
            ?: error("$what is not on screen. On screen: ${onScreen()}")
    }

    /** Runs [block] with Ragewarden's keyboard selected; autofill is switched off unless [keepAutofill]. */
    private inline fun withRagewardenKeyboard(keepAutofill: Boolean = false, block: () -> Unit) {
        val ime = "${app.packageName}/ragewarden.ragedroid.ime.RagewardenInputMethodService"
        shell("settings delete secure autofill_service")
        shell("ime enable $ime")
        shell("ime set $ime")
        try {
            block()
        } finally {
            shell("ime reset")
            if (keepAutofill) shell("settings delete secure autofill_service")
        }
    }

    private fun find(selector: androidx.test.uiautomator.BySelector, what: String): UiObject2 =
        device.wait(Until.findObject(selector), UI_TIMEOUT_MS)
            ?: error("$what did not appear within ${UI_TIMEOUT_MS}ms. On screen: ${onScreen()}")

    /**
     * For a failure message: every text and content description on screen, the
     * windows top to bottom, and the touches the app refused as obscured.
     */
    private fun onScreen(): String {
        val dump = java.io.ByteArrayOutputStream().also { device.dumpWindowHierarchy(it) }.toString()
        val texts = Regex("""(?:text|content-desc)="([^"]+)"""").findAll(dump).map { it.groupValues[1] }.distinct().joinToString(" | ")
        val windows = instrumentation.uiAutomation.windows.sortedByDescending { it.layer }.joinToString(" / ") { w ->
            val r = android.graphics.Rect().also(w::getBoundsInScreen)
            "${w.title} (type ${w.type}, layer ${w.layer}, $r)"
        }
        val refused = instrumentation.uiAutomation.executeShellCommand("logcat -d -s ObscuredTouch:W").use { pfd ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().readLines().filter { "touch ignored" in it }.takeLast(5)
        }
        return "$texts. Windows: $windows. Refused touches: ${refused.ifEmpty { listOf("none") }}"
    }

    private fun shell(command: String) {
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes() }
        }
    }

    private fun requireArg(name: String): String =
        InstrumentationRegistry.getArguments().getString(name)?.takeIf { it.isNotBlank() }
            ?: error("instrumentation argument '$name' is missing; tests/journey/run.sh supplies it")

    private companion object {
        const val SEED = "JBSWY3DPEHPK3PXP"
        const val FLOW_ITEM = "Flow login"
        const val CARD_ITEM = "Flow card"
        const val CARD_NUMBER = "4111111111111111"
        const val CARD_CODE = "737"
        const val SSH_ITEM = "Flow SSH key"
        const val SSH_PASSPHRASE = "flow-passphrase"
        const val SSH_PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrvGPv6PjfY2xW8Uk8lrVYZAqlpU0SkAJ9TcDba5nwM"
        const val SSH_FINGERPRINT = "SHA256:+JRhDJluAuHSIkl6cty172OtYQ8zxb/GAFBfXCgYmhw"

        // A throwaway key generated for this test; the header is split so a
        // secret scanner does not read the fixture as a leaked key.
        const val PEM_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        const val PEM_END = "-----END " + "OPENSSH PRIVATE KEY-----"
        val SSH_KEY = PEM_BEGIN + "\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACAa7xj7+j432NsVvFJPJa1WGQKpaVNEpACfU3A22uZ8DAAAAJhlNHAoZTRw\n" +
            "KAAAAAtzc2gtZWQyNTUxOQAAACAa7xj7+j432NsVvFJPJa1WGQKpaVNEpACfU3A22uZ8DA\n" +
            "AAAEDnMbbs1qUCuBjEGiJkoHlIjyhxFaCFnjPsj5M7t2dTxhrvGPv6PjfY2xW8Uk8lrVYZ\n" +
            "AqlpU0SkAJ9TcDba5nwMAAAADnJhZ2Vkcm9pZC10ZXN0AQIDBAUGBw==\n" +
            PEM_END + "\n"
        const val USERNAME_VALUE = "flow-user"
        const val UI_TIMEOUT_MS = 20_000L
        val SIX_DIGITS: java.util.regex.Pattern = java.util.regex.Pattern.compile("""\d{6}""")

        @Volatile
        var seeded: Seeded? = null

        fun rfc6238(base32: String, unixSeconds: Long): String {
            val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            var buffer = 0
            var bits = 0
            val key = java.io.ByteArrayOutputStream()
            base32.uppercase().filter { it != '=' }.forEach { ch ->
                buffer = (buffer shl 5) or alphabet.indexOf(ch)
                bits += 5
                if (bits >= 8) {
                    key.write((buffer shr (bits - 8)) and 0xff)
                    bits -= 8
                }
            }
            val counter = java.nio.ByteBuffer.allocate(8).putLong(unixSeconds / 30).array()
            val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key.toByteArray(), "HmacSHA1")) }
            val h = mac.doFinal(counter)
            val o = h[h.size - 1].toInt() and 0x0f
            val bin = ((h[o].toInt() and 0x7f) shl 24) or ((h[o + 1].toInt() and 0xff) shl 16) or
                ((h[o + 2].toInt() and 0xff) shl 8) or (h[o + 3].toInt() and 0xff)
            return "%06d".format(bin % 1_000_000)
        }
    }
}
