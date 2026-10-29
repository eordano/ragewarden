package ragewarden.ragedroid

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import kotlinx.collections.immutable.persistentListOf
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.LocalLiveRecipients
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.screens.AddItemKind
import ragewarden.ragedroid.ui.screens.AddItemScreen
import ragewarden.ragedroid.ui.screens.ItemDetailScreen
import ragewarden.ragedroid.ui.screens.LockScreen
import ragewarden.ragedroid.ui.screens.RecipientRow
import ragewarden.ragedroid.ui.screens.RecipientRowCard
import ragewarden.ragedroid.ui.screens.VaultListScreen
import ragewarden.ragedroid.ui.screens.WelcomeStep
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp-night")
class ScreenSnapshots {

    @get:Rule
    val composeRule = createComposeRule()

    private val deckShots: String = "../../deck/shots/ragedroid"

    private val roboOptions: RoborazziOptions = RoborazziOptions(
        recordOptions = RoborazziOptions.RecordOptions(resizeScale = 2.625),
    )

    private val demoRecipients = persistentListOf(
        Recipient(
            id = "rcpt-yk-13",
            kind = RecipientKind.YubiKey,
            name = "YubiKey 5C NFC",
            serial = "13371337",
            fingerprint = "ab:cd:ef:01:23:45",
            enrolled = "Today",
            lastUsed = "5m ago",
            slot = "PIV 95",
            firmware = "5.4.3",
            coverage = 12,
        ),
        Recipient(
            id = "rcpt-strongbox",
            kind = RecipientKind.StrongBox,
            name = "This phone (StrongBox)",
            serial = "ANDR-PIXEL",
            fingerprint = "98:76:54:32:10:fe",
            enrolled = "Today",
            lastUsed = "now",
        ),
    )

    private val demoItems = persistentListOf(
        VaultItem(
            id = "i-1",
            name = "Stripe Dashboard",
            username = "maya@feldspar.fm",
            site = "dashboard.stripe.com",
            folder = "Work",
            rage = true,
            recipients = persistentListOf("rcpt-yk-13", "rcpt-strongbox"),
            password = "********",
            lastUsed = "5m ago",
            history = 7,
            favorite = true,
        ),
        VaultItem(
            id = "i-2",
            name = "GitHub",
            username = "maya-voss",
            site = "github.com",
            folder = "Work",
            rage = true,
            recipients = persistentListOf("rcpt-yk-13"),
            password = "********",
            lastUsed = "Yesterday",
            history = 3,
        ),
        VaultItem(
            id = "i-3",
            name = "1Password import",
            username = "maya@personal.example",
            site = "1password.com",
            folder = "Personal",
            rage = false,
            recipients = persistentListOf(),
            password = "p@ssw0rd",
            lastUsed = "Last week",
            history = 1,
        ),
        VaultItem(
            id = "i-4",
            name = "Hetzner Cloud",
            username = "ops@feldspar.fm",
            site = "console.hetzner.cloud",
            folder = "Infrastructure",
            rage = true,
            recipients = persistentListOf("rcpt-yk-13", "rcpt-strongbox"),
            password = "********",
            lastUsed = "2d ago",
            history = 2,
        ),
        VaultItem(
            id = "i-5",
            name = "Family Wi-Fi",
            username = "router-admin",
            site = "203.0.113.1",
            folder = "Family",
            rage = false,
            recipients = persistentListOf(),
            password = "lorem-ipsum",
            lastUsed = "Last month",
            history = 0,
        ),
    )

    private val demoFolders = persistentListOf("All", "Work", "Personal", "Infrastructure", "Family")

    private val detailItem: VaultItem = demoItems[0]

    private fun stubClipboard(): Clipboard = Clipboard(
        context = ApplicationProvider.getApplicationContext(),
    )

    private fun setRageContent(block: @Composable () -> Unit) {
        composeRule.setContent {
            RageTheme(darkTheme = true) {
                CompositionLocalProvider(LocalLiveRecipients provides demoRecipients) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(rageColors.background),
                    ) {
                        block()
                    }
                }
            }
        }
    }

    private fun capture(name: String) {
        composeRule.onRoot().captureRoboImage(
            filePath = "$deckShots/$name.png",
            roborazziOptions = roboOptions,
        )
    }

    @Test
    fun lockScreen() {
        setRageContent {
            LockScreen(
                onUnlock = {},
                onSignOut = {},
            )
        }
        composeRule.waitForIdle()
        capture("lock")
    }

    @Test
    fun firstRunWelcome() {
        setRageContent {
            WelcomeStep(onBegin = {})
        }
        composeRule.waitForIdle()
        capture("first-run")
    }

    @Test
    fun vaultList() {
        setRageContent {
            VaultListScreen(
                items = demoItems,
                folders = demoFolders,
                onOpen = {},
                onSettings = {},
            )
        }
        composeRule.waitForIdle()
        capture("vault")
    }

    @Test
    fun addItem() {
        setRageContent {
            AddItemScreen(
                itemKind = AddItemKind.Login,
                repo = null,
                onBack = {},
                onSave = { _, _ -> },
            )
        }
        composeRule.waitForIdle()
        capture("add")
    }

    @Test
    fun itemDetailRevealPrompt() {
        setRageContent {
            ItemDetailScreen(
                item = detailItem,
                decryptPassword = { _, _, _, _ -> ByteArray(0) },
                clipboard = stubClipboard(),
                showToast = {},
                onBack = {},
                onEdit = {},
                onHistory = {},
                onRotate = { _ -> },
                onDelete = { },
            )
        }
        composeRule.waitForIdle()
        capture("detail-with-reveal-prompt")
    }

    @Test
    fun recipientList() {
        val rows = listOf(
            RecipientRow(
                id = "rcpt-yk-13",
                kind = RecipientKind.YubiKey,
                displayName = "YubiKey 5C NFC",
                deviceLabel = "Maya's main key",
                fingerprint = "ab:cd:ef:01:23:45",
                local = false,
            ),
            RecipientRow(
                id = "rcpt-strongbox",
                kind = RecipientKind.StrongBox,
                displayName = "This phone (StrongBox)",
                deviceLabel = "Pixel 8 Pro",
                fingerprint = "98:76:54:32:10:fe",
                local = true,
            ),
            RecipientRow(
                id = "rcpt-fido2",
                kind = RecipientKind.Fido2,
                displayName = "Laptop FIDO2",
                deviceLabel = "MacBook Pro M3",
                fingerprint = "55:aa:55:aa:55:aa",
                local = false,
            ),
            RecipientRow(
                id = "rcpt-recovery",
                kind = RecipientKind.Recovery,
                displayName = "Paper recovery",
                deviceLabel = "Safe deposit box",
                fingerprint = "00:11:22:33:44:55",
                local = false,
            ),
        )
        setRageContent {
            Column(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                AppBar(
                    title = "Recipients",
                    leading = {
                        IconBtn(
                            icon = Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = "Back",
                            onClick = {},
                        )
                    },
                )
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 18.dp, vertical = 12.dp),
                ) {
                    item("intro") {
                        Text(
                            text = "Every recipient enrolled on any of your devices. " +
                                "Removing one re-publishes the registry without it; " +
                                "future encrypts won't include it.",
                            style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 20.sp),
                            color = rageColors.fgSecondary,
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                    }
                    items(rows.size) { i ->
                        RecipientRowCard(row = rows[i], enabled = true, onRemove = {})
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }
            }
        }
        composeRule.waitForIdle()
        capture("recipient-list")
    }

    @Test
    fun rotateSheet() {
        setRageContent {
            ItemDetailScreen(
                item = detailItem,
                decryptPassword = { _, _, _, _ -> ByteArray(0) },
                clipboard = stubClipboard(),
                showToast = {},
                onBack = {},
                onEdit = {},
                onHistory = {},
                onRotate = { _ -> },
                onDelete = { },
            )
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithContentDescription("More actions").performClick()
        composeRule.waitForIdle()
        capture("rotate-sheet")
    }

    /**
     * Delete must not be offered when it cannot be gated.
     *
     * This used to open the confirm sheet and snapshot it. It cannot any more,
     * and that is the point: `MasterPasswordConfirm` now requires a non-null
     * repository, because the nullable one let `RecipientDetailScreen` build a
     * sheet whose else-branch called `onConfirm()` after `delay(150)` -- one
     * arbitrary character revoked a recipient. With the fail-open branch gone,
     * a screen holding no repository can no longer construct the gate, so
     * `ItemDetailScreen` withholds the affordance instead of showing an
     * ungated one (ItemDetailScreen.kt:548-550).
     *
     * `VaultBridge.repository()` really can be null in production
     * (RageApp.kt:801), so this is a reachable state and not just a test
     * artifact. Asserting the absence is worth more than the screenshot was:
     * it fails if anyone restores the ungated path.
     *
     * The confirm sheet itself is left uncovered here on purpose -- rendering it
     * needs a real BitwardenVaultRepository, whose constructor takes six stores
     * and calls sessionStore.load() eagerly. That belongs in an instrumented
     * test with a real vault, not in a Roborazzi screenshot.
     */
    @Test
    fun deleteIsWithheldWhenItCannotBeGated() {
        setRageContent {
            ItemDetailScreen(
                item = detailItem,
                decryptPassword = { _, _, _, _ -> ByteArray(0) },
                clipboard = stubClipboard(),
                showToast = {},
                onBack = {},
                onEdit = {},
                onHistory = {},
                onRotate = { _ -> },
                onDelete = { },
                // repository deliberately omitted -- that is the condition here.
            )
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithContentDescription("More actions").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("Delete item").assertDoesNotExist()
        capture("delete-withheld-ungated")
    }
}
