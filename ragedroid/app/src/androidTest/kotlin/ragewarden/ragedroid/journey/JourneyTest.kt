package ragewarden.ragedroid.journey

import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.printToString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import ragewarden.ragedroid.MainActivity

/**
 * End-to-end journey through the shipped debug APK, annotated with the
 * accessibility (Compose semantics) tree before and after every interaction.
 *
 * WHY THIS EXISTS: until the Android toolchain could cross-compile the JNI
 * crate, no ragedroid code had ever run on a device -- the JVM unit tests never
 * load `libragedroid_jni.so`. Every path below is being executed for real.
 *
 * WHAT IT PROVES: a secret written by rageterm on the host, wrapped to a 24-word
 * paper recovery identity, is decrypted on the phone by typing those 24 words.
 * The BIP-39 phrase is a real age key and is the only thing that crosses -- the
 * emulator has no security key, so anything enrolled here would be a MOCK
 * identity, and `BitwardenVaultRepository.pushRecipientRegistry` filters mocks
 * out of the published registry (`filterNot { it.mock }`). The phrase is the
 * honest cross-client path, and this test walks it end to end: it does not stop
 * at sign-in, and it asserts the recovered plaintext by value.
 *
 * The direction proven here is rageterm -> ragedroid. The reverse (a phrase
 * generated ON the phone and consumed by another client) is NOT covered; see
 * step 5 of `tests/journey/run.sh`, which says so plainly rather than invoking a
 * browser spec that does not exist.
 *
 * THREE MORE THINGS ARE ASSERTED HERE, and each one is here rather than in a
 * cheaper test because a cheaper test could not fail:
 *
 *   * THE NEGATIVE CONTROL. Before the real 24 words, the same screen is given
 *     a DECOY phrase: a valid BIP-39 mnemonic deriving a real age identity that
 *     simply is not a recipient of the item. The reveal must be refused. Without
 *     it, every clause below would still pass if the screen rendered the
 *     instrumentation argument instead of a decrypted blob. A checksum-broken
 *     phrase is not a substitute -- the "24 of 24 words" gate and
 *     `RecoverFromPhraseScreen`'s mnemonic branch catch that long before any
 *     unwrap, so it proves nothing about the unwrap.
 *
 *   * THE RECIPIENT PIP. The vault row's `RAGE · N` is `item.recipients.size`,
 *     and those come from `jni/src/lib.rs::rage_recipient_descriptors` parsing
 *     the blob's own age header. age writes a GREASE stanza into every header;
 *     counting it as a recipient made every item overstate its coverage by one.
 *     Only a device can prove this, because only a device loads the packaged
 *     `libragedroid_jni.so` -- the JVM unit tests never do.
 *
 *   * FAIL-CLOSED ON WRITE. With nothing enrolled here and only foreign
 *     recipients in the registry, `AddItemScreen` must say so and Save must not
 *     write silently. This cannot be a JVM test: `rememberWrapTargets` needs the
 *     Hilt graph, a bound `VaultBridge.repository()` and a JNI policy call, and
 *     off-device it falls back to the LOCAL recipient list -- which is exactly
 *     the pre-fix input, so a Robolectric render would pass with the gate
 *     removed.
 *
 * WHY NO SCREENSHOTS: MainActivity sets `FLAG_SECURE` (ui/SecureWindow.kt), so
 * Android blanks every screen capture of this app -- host-side `adb exec-out
 * screencap` included. See the header of [Journal] for the reproduction; the
 * short version is that pixels are unavailable by design and the semantics tree
 * is the artifact instead.
 *
 * RUN IT VIA `tests/journey/run.sh`, which supplies the instrumentation
 * arguments read in [arg] and does five things this test cannot:
 *   * starts a throwaway Vaultwarden on the HOST;
 *   * registers the account, because the app has no registration screen --
 *     `BitwardenVaultRepository.register()` and `RageNative.register()` both
 *     exist and nothing in ui/ calls either;
 *   * enrols a paper recovery identity with rageterm and stores an item wrapped
 *     to it, which is the fixture this test recovers;
 *   * counts the recipients that item was wrapped to (`journeyRecipientCount`)
 *     and mints the decoy phrase on a SECOND throwaway account
 *     (`journeyDecoyPhrase`) -- see the two headers above;
 *   * `adb reverse`, because `core::sync::host_is_loopback` and
 *     `FirstRunScreen.signInFormProblem` both refuse anything but localhost /
 *     ::1 / 127.*, so the emulator's 10.0.2.2 host alias is rejected by the
 *     product itself.
 *
 * MOCK HARDWARE: the system property is still set from the runner's argument so
 * the switch keeps working, but this route deliberately SKIPS both enrolment
 * steps, so no mock identity is created and nothing below depends on
 * identities/MockHardware.kt.
 *
 * SECRETS: a throwaway account on a loopback server, destroyed by the runner.
 * The recovery phrase is passed in as an instrumentation argument and the
 * recovered plaintext lands in the artifacts. Never point this at a real vault.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class JourneyTest {

    init {
        // Before the @Rule launches MainActivity: MockHardware.enabled() is read
        // on demand, but anything the activity caches at construction would see
        // the wrong value if this ran later.
        System.setProperty(
            "RAGEWARDEN_MOCK_HARDWARE",
            arg("RAGEWARDEN_MOCK_HARDWARE") ?: "0",
        )
    }

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    // The journal has no handle on the Compose rule, so the idle wait belongs
    // here, in the supplier: every capture is taken against a settled tree.
    private val journal = Journal("android") { treeText() }

    private val server get() = requireArg("journeyServer")
    private val email get() = requireArg("journeyEmail")
    private val password get() = requireArg("journeyPassword")
    private val phrase get() = requireArg("journeyPhrase")
    private val item get() = requireArg("journeyItem")
    private val secret get() = requireArg("journeySecret")

    /**
     * A second, valid 24-word mnemonic, minted by run.sh on a THROWAWAY SECOND
     * ACCOUNT so that it derives a real age identity which is not a recipient of
     * [item]. See the class header: this is the negative control, and it is the
     * only reason the positive assertion below means anything.
     */
    private val decoyPhrase get() = requireArg("journeyDecoyPhrase")

    /**
     * How many recipients rageterm actually wrapped [item] to. run.sh derives
     * it from the fixture it built -- the enrolled recipients `rageterm
     * recipients list` prints, plus the identity.age that
     * `recipients::load_encrypt_plan` appends and that table never shows -- so
     * changing the fixture moves this number instead of silently weakening the
     * assertion. The pip on the vault row must equal it exactly; one more means
     * the age GREASE stanza is being counted as a recipient again.
     */
    private val recipientCount get() = requireArg("journeyRecipientCount").toInt()

    @Test
    fun signInSkipEnrolmentThenRecoverFromPaperPhrase() {
        compose.waitForIdle()

        journal.note(
            "Cold start. The activity reaching this frame at all proves " +
                "libragedroid_jni.so loaded -- before today it did not exist in any APK."
        )
        journal.snapshot("app launched")

        // --- welcome -------------------------------------------------------
        journal.step("tap Begin setup") {
            compose.onNodeWithText("Begin setup").performClick()
        }

        // --- sign in -------------------------------------------------------
        // Three text fields in document order: Server, Email, Master password.
        // ragedroid sets no testTag anywhere in main/, so positional lookup over
        // hasSetTextAction() is the only stable handle. If the form gains a
        // field this breaks loudly, which is the right failure.
        journal.note("Sign-in form. Server must be loopback; see the class header.")
        journal.step("fill the server field") {
            fields()[0].performTextReplacement(server)
        }
        journal.step("fill the email field") {
            fields()[1].performTextReplacement(email)
        }
        journal.step("fill the master password field") {
            fields()[2].performTextReplacement(password)
        }

        journal.step("tap Sign in & continue") {
            compose.onNodeWithText("Sign in & continue").performClick()
            // The sign-in does argon2/PBKDF2 key derivation and a network round
            // trip. waitForIdle() returns as soon as compose is idle, which
            // happens long before the response lands, so poll for the screen to
            // actually change instead of asserting into a still-loading UI.
            // The three sign-in fields disappearing is the proof the sign-in
            // landed rather than silently sitting on the form. Translate the
            // timeout, because ComposeTimeoutException on its own says nothing
            // about which of the two usual causes it was.
            try {
                compose.waitUntil(timeoutMillis = SIGN_IN_TIMEOUT_MS) { fieldCount() != 3 }
            } catch (e: ComposeTimeoutException) {
                error(
                    "still on the sign-in form after ${SIGN_IN_TIMEOUT_MS}ms -- sign-in did " +
                        "not complete. Either the server is unreachable from the device " +
                        "(check adb reverse) or it rejected the credentials; the after-tree " +
                        "of this step shows which error the form is displaying."
                )
            }
        }

        journal.handoff("semantics-after-signin", treeText())

        // --- skip both enrolments ------------------------------------------
        // Step 2 of 3 offers "This phone" (secure element) and "A security key".
        // Neither exists on an emulator, and enrolling the mock identity here
        // would produce a recipient that never leaves the device anyway. Skipping
        // is what a user without a key does, and it is the state the paper-backup
        // route is FOR.
        journal.step("skip passkey enrolment") {
            compose.onNodeWithText("Skip -- set up later").performClick()
        }
        journal.step("skip the backup recipient") {
            compose.onNodeWithText("Skip -- I'll add later").performClick()
        }
        journal.step("tap Open vault") {
            compose.onNodeWithText("Open vault").performClick()
        }

        // --- the vault list holds user items, not ragewarden's own bookkeeping ----
        journal.note(
            "All three clients park their own machinery in the shared vault as ordinary " +
                "ciphers: rageterm's private recipient list ('$RAGETERM_RECIPIENT_LIST', " +
                "rageterm/src/recipients.rs:20), the browser's per-item history markers " +
                "('$HISTORY_MARKER:<cipherId>', ragemanifest/src/wasm/sync.rs:1045) and " +
                "ragedroid's own registry marker ('${RAGEDROID_MARKER}recipients_v1__'). " +
                "The phone filtered ONLY the last of those, so a vault any other client " +
                "had touched rendered machinery as user items -- offering to edit it and " +
                "inflating the header count. This fixture is polluted by construction: " +
                "run.sh's `rageterm enroll-software-identity` writes the recipient-list " +
                "cipher before the journey starts, so the row is genuinely on the server " +
                "and the only question is whether this screen shows it."
        )
        journal.step("the vault list holds user items only") {
            // Every clause is checked before any is reported, so one run names
            // ALL of what leaked rather than the first thing that did.
            val problems = buildList {
                if (nodes(RAGETERM_RECIPIENT_LIST).isNotEmpty()) {
                    add(
                        "a row named '$RAGETERM_RECIPIENT_LIST' is in the list. That is " +
                            "rageterm's PRIVATE recipient list, not an item the user made."
                    )
                }
                // Substring, not equality: the browser names one marker per
                // cipher it has edited, '$HISTORY_MARKER:<cipherId>', so there
                // is no fixed string to compare against. rageterm's single
                // history document uses the bare name, and both must be gone.
                if (nodes(HISTORY_MARKER, substring = true).isNotEmpty()) {
                    add("a row whose name carries '$HISTORY_MARKER' is in the list.")
                }
                if (nodes(RAGEDROID_MARKER, substring = true).isNotEmpty()) {
                    add("a row whose name carries '$RAGEDROID_MARKER' is in the list.")
                }
                // BY VALUE, and this is the whole reason this step exists.
                //
                // The vault header is also read twice later in this journey, and
                // compared as a DELTA between the two readings -- which is blind
                // to exactly the bug above. Meta ciphers inflate the count by a
                // CONSTANT, so both readings move together and the delta is
                // unchanged: with the filter reverted the journey still passed
                // 35/35 while the header read '2 items · 1 protected' in every
                // capture. A delta cannot see a constant offset. Only an
                // absolute value can, so this one is absolute.
                val counts = vaultCounts()
                if (counts != FIXTURE_VAULT) {
                    add(
                        "the header reads '${counts.items} items · ${counts.protected} " +
                            "protected'; the fixture is exactly one protected item, so it " +
                            "must read '${FIXTURE_VAULT.items} items · " +
                            "${FIXTURE_VAULT.protected} protected'. A count HIGHER than " +
                            "that with no extra row visible above means a meta cipher is " +
                            "reaching VaultListScreen's `items` -- the header counts what " +
                            "it is handed, so it inflates even when the row itself is off " +
                            "screen."
                    )
                }
            }
            check(problems.isEmpty()) {
                "the vault list is showing ragewarden's own bookkeeping as user items:\n" +
                    problems.joinToString("\n") { "  - $it" } +
                    "\nBitwardenVaultRepository.snapshot() must exclude the whole meta " +
                    "family (VaultMetaNames.isMeta), not just ragedroid's own marker. " +
                    "The full tree is in the after-capture of this step."
            }
        }

        // --- the recipient pip counts recipients, not GREASE ----------------
        journal.note(
            "The pip on the vault row is `item.recipients.size`, and those strings come " +
                "from jni/src/lib.rs::rage_recipient_descriptors parsing this blob's own " +
                "age header -- the packaged libragedroid_jni.so, not a host build. age " +
                "writes a GREASE stanza into every header it produces; the parser's old " +
                "catch-all arm named it like a recipient, so every item in the app " +
                "claimed one more recipient than could ever open it. rageterm wrapped " +
                "'$item' to $recipientCount, so the row must read exactly that."
        )
        journal.step("read the recipient pip on the vault row") {
            val matching = compose
                .onAllNodes(hasText(item) and hasText("· $recipientCount"))
                .fetchSemanticsNodes()
            check(matching.size == 1) {
                "the '$item' row does not report exactly $recipientCount recipient(s). " +
                    "The row is one merged semantics node carrying its name, 'RAGE' and " +
                    "the pip together, and the whole tree is in the after-capture of " +
                    "this step. A pip of ${recipientCount + 1} means the age GREASE " +
                    "stanza is being counted as a recipient again -- see " +
                    "jni/src/lib.rs::stanza_descriptor and its " +
                    "grease_stanza_is_not_a_recipient test."
            }
        }

        // --- recover with the paper phrase ---------------------------------
        journal.note(
            "The vault list below shows the item rageterm stored. This device enrolled " +
                "nothing, so the paper phrase under Settings is the only way into it."
        )
        journal.step("open Settings") {
            compose.onNodeWithContentDescription("Settings").performClick()
        }
        journal.step("tap Recover from paper backup") {
            // Settings is one long verticalScroll; scroll the row into view rather
            // than assuming a screen height.
            compose.onNodeWithText("Recover from paper backup").performScrollTo().performClick()
        }

        // --- negative control: a valid phrase that is not a recipient -------
        // This runs BEFORE the real phrase, on the same screen, in the same
        // session, against the same item. The only difference between the
        // refusal below and the reveal after it is the 24 words, which is what
        // makes the reveal evidence of an age unwrap rather than of a screen
        // echoing an instrumentation argument back at the test.
        journal.note(
            "NEGATIVE CONTROL. These 24 words are a VALID BIP-39 mnemonic -- run.sh " +
                "minted them with `rageterm enroll-recovery` on a second throwaway " +
                "account, so they derive a real age identity. That identity is simply " +
                "not a recipient of '$item'. A phrase with a broken checksum would prove " +
                "nothing here: the '24 of 24 words' gate and RecoverFromPhraseScreen's " +
                "own mnemonic branch reject it before any unwrap is attempted."
        )
        // One BasicTextField on this screen, so no positional guessing needed.
        journal.step("type a DECOY 24-word phrase") {
            typePhrase(decoyPhrase)
        }
        journal.step("tap Recover with the decoy phrase") {
            compose.onNodeWithText("Recover").performClick()
        }
        journal.step("tap the protected item with the decoy phrase") {
            tapItemRow()
            // Wait for whichever comes first -- a reveal or the refusal toast --
            // instead of burning the timeout on an absence. A reveal and a
            // refusal are mutually exclusive: the row expands only when
            // decryptWithRecoveryPhrase succeeds, and the toast fires only when
            // it fails.
            try {
                compose.waitUntil(timeoutMillis = REVEAL_TIMEOUT_MS) {
                    nodes(secret).isNotEmpty() || nodes(REFUSAL_TOAST, substring = true).isNotEmpty()
                }
            } catch (e: ComposeTimeoutException) {
                error(
                    "the decoy tap produced neither a reveal nor a refusal within " +
                        "${REVEAL_TIMEOUT_MS}ms. The row is only clickable while the " +
                        "phrase field is non-blank, so the likeliest cause is that the " +
                        "tap never reached the row; the after-tree of this step shows " +
                        "the screen unchanged if so."
                )
            }
            check(nodes(secret).isEmpty()) {
                "A PHRASE THAT IS NOT A RECIPIENT OPENED '$item'. Either the item is " +
                    "wrapped to something both phrases derive, or the screen is not " +
                    "decrypting at all and is rendering text it was handed. Everything " +
                    "the positive assertion below claims is void until this is explained."
            }
            check(nodes(REFUSAL_TOAST, substring = true).isNotEmpty()) {
                "the decoy was refused, but silently: no toast containing " +
                    "'$REFUSAL_TOAST' is in the tree. RecoverFromPhraseScreen's failure " +
                    "branch is the user's only signal that the phrase was wrong, and " +
                    "this app's toasts are Compose state (RageApp.showToast), so a " +
                    "missing one is a real regression and not a capture blind spot."
            }
        }

        // --- the real phrase ------------------------------------------------
        journal.step("type the 24-word recovery phrase") {
            typePhrase(phrase)
        }
        journal.step("tap Recover") {
            compose.onNodeWithText("Recover").performClick()
        }

        journal.note(
            "Tapping the item derives the age identity from the typed words and " +
                "unwraps the cipher. Nothing is persisted: the identity lives only as " +
                "long as the reveal, which auto-clears after 8 seconds."
        )
        journal.step("tap the protected item to reveal it") {
            tapItemRow()
            // Decrypt is a JNI round trip through age; poll for the plaintext to
            // appear rather than racing it. The reveal auto-clears, so the
            // after-capture that follows is inside that window by construction.
            //
            // Sampling this screen on a timer instead of polling is how you get a
            // false negative: driving the same route from the host with
            // `uiautomator dump` (~3s per sample) missed the 8-second window and
            // only found the "Plaintext cleared from screen" toast that
            // RecoverFromPhraseScreen emits AFTER the reveal has already come and
            // gone. waitUntil returns on the frame the text appears.
            try {
                compose.waitUntil(timeoutMillis = REVEAL_TIMEOUT_MS) {
                    nodes(secret).isNotEmpty()
                }
            } catch (e: ComposeTimeoutException) {
                error(
                    "no plaintext ${REVEAL_TIMEOUT_MS}ms after tapping '$item'. " +
                        "REVEAL_TIMEOUT_MS is deliberately under RageApp's 3s toast " +
                        "lifetime, so if decryptWithRecoveryPhrase failed the refusal " +
                        "toast IS still in the after-tree of this step; if the after-tree " +
                        "shows a collapsed row and no toast, the tap did not reach the " +
                        "row. The decoy step above ruled the row out as unreachable, so " +
                        "a failure here that late is a decrypt failure."
                )
            }
        }

        // The assertion the whole journey exists for: a secret written by
        // rageterm on the host, read back on the phone from 24 typed words --
        // and refused, moments earlier, for 24 different valid words.
        check(nodes(secret).isNotEmpty()) {
            "the item did not reveal '$secret' -- the phrase did not unwrap the cipher. " +
                "The after-tree of the last step shows what the screen said instead."
        }

        // --- fail-closed on write -------------------------------------------
        journal.step("leave the recovery screen") {
            compose.onNodeWithContentDescription("Back").performClick()
        }
        journal.step("leave Settings") {
            compose.onNodeWithContentDescription("Back").performClick()
        }

        val before = vaultCounts()
        // Anchored by value, for the same reason as the step after the vault
        // opened: everything below compares `before` against `after`, and a
        // delta cannot see a constant offset. Pinning `before` is what makes
        // the two deltas below mean "one item was added" rather than "the count
        // moved by one from wherever it happened to be".
        check(before == FIXTURE_VAULT) {
            "the vault reads $before on the way into the composer, not $FIXTURE_VAULT. " +
                "Nothing between here and the vault-list check above adds an item -- the " +
                "recovery screen only reads -- so a different count means a cipher became " +
                "visible mid-journey."
        }
        journal.note(
            "This device enrolled NOTHING -- both first-run steps were skipped -- so every " +
                "recipient the shared policy will wrap to belongs to rageterm. The " +
                "composer used to render only the LOCAL recipient list, show 'pick at " +
                "least one recipient' with nothing to pick, and save anyway: the item " +
                "went to the server wrapped to another machine's keys and the phone that " +
                "wrote it could never open it. The composer must now name the foreign " +
                "set and refuse to write without a deliberate confirmation."
        )
        journal.step("open the item composer") {
            compose.onNodeWithContentDescription("Add item").performClick()
        }
        journal.step("choose Login") {
            compose.onNodeWithText("Login").performClick()
        }
        journal.step("name the new item") {
            fields()[COMPOSER_NAME_FIELD].performTextReplacement(COMPOSER_ITEM)
        }
        journal.step("type a password, so there is a secret to wrap") {
            // Not the `Protect` toggle: BitwardenVaultRepository.create calls
            // encryptForActiveRecipients unconditionally, so having a secret at
            // all is what decides whether this save wraps.
            fields()[COMPOSER_PASSWORD_FIELD].performTextReplacement(COMPOSER_SECRET)
        }
        journal.step("read the composer's recipient summary") {
            check(nodes(FOREIGN_CHIP_SUFFIX, substring = true).isNotEmpty()) {
                "the composer names no recipient as belonging to another device. With " +
                    "nothing enrolled here every wrap target is foreign, so at least one " +
                    "chip must carry '$FOREIGN_CHIP_SUFFIX'. A composer showing only the " +
                    "local list -- which is empty here -- is the pre-fix screen."
            }
            check(nodes(UNOPENABLE_WARNING).isNotEmpty()) {
                "the composer does not warn '$UNOPENABLE_WARNING' even though this " +
                    "device holds no key in the wrap set."
            }
        }
        journal.step("tap Save with nothing enrolled here") {
            compose.onNodeWithText("Save").performClick()
            try {
                compose.waitUntil(timeoutMillis = UI_SETTLE_TIMEOUT_MS) {
                    nodes(UNOPENABLE_DIALOG_TITLE).isNotEmpty()
                }
            } catch (e: ComposeTimeoutException) {
                error(
                    "Save raised no confirmation. The write gate in " +
                        "AddItemScreen.onSaveClick is open again: this device is about " +
                        "to store an item it cannot read back, with no signal to the " +
                        "user. Check the vault count in the next step -- if it went up, " +
                        "the write already happened."
                )
            }
        }
        journal.step("tap Cancel in the confirmation") {
            compose.onNodeWithText("Cancel").performClick()
            compose.waitUntil(timeoutMillis = UI_SETTLE_TIMEOUT_MS) {
                nodes(UNOPENABLE_DIALOG_TITLE).isEmpty()
            }
        }
        journal.step("back out of the composer") {
            compose.onNodeWithContentDescription("Cancel").performClick()
        }
        journal.step("back out of the type picker") {
            compose.onNodeWithContentDescription("Back").performClick()
        }
        journal.step("the cancelled item was never written") {
            // The load-bearing clause. "A dialog appeared" is cheap; "the server
            // has no such item" is the thing the fix is for.
            check(nodes(COMPOSER_ITEM).isEmpty()) {
                "'$COMPOSER_ITEM' is in the vault after the save was CANCELLED."
            }
            check(vaultCounts() == before) {
                "the vault went from $before to ${vaultCounts()} across a save the user " +
                    "cancelled -- the item was written before the confirmation was answered."
            }
        }

        journal.note(
            "The other half of the same gate: the confirmation is a confirmation, not a " +
                "refusal. Saving an item only other devices can open is a legitimate " +
                "thing to do deliberately -- it must simply never happen silently."
        )
        journal.step("re-open the composer") {
            compose.onNodeWithContentDescription("Add item").performClick()
        }
        journal.step("choose Login again") {
            compose.onNodeWithText("Login").performClick()
        }
        journal.step("re-enter the item") {
            fields()[COMPOSER_NAME_FIELD].performTextReplacement(COMPOSER_ITEM)
            fields()[COMPOSER_PASSWORD_FIELD].performTextReplacement(COMPOSER_SECRET)
        }
        journal.step("tap Save, then Save anyway") {
            compose.onNodeWithText("Save").performClick()
            compose.waitUntil(timeoutMillis = UI_SETTLE_TIMEOUT_MS) {
                nodes(UNOPENABLE_DIALOG_TITLE).isNotEmpty()
            }
            compose.onNodeWithText("Save anyway").performClick()
            // The save is an encrypt plus a server round trip, and it lands the
            // app back on the vault list. `Save` disappearing is what says the
            // composer is gone: the item name alone would match the composer's
            // own name field, which still holds it.
            try {
                compose.waitUntil(timeoutMillis = SAVE_TIMEOUT_MS) {
                    nodes("Save").isEmpty() && nodes(COMPOSER_ITEM).isNotEmpty()
                }
            } catch (e: ComposeTimeoutException) {
                error(
                    "'Save anyway' did not land an item in the vault within " +
                        "${SAVE_TIMEOUT_MS}ms. AddItemScreen surfaces a create failure as " +
                        "a 'Save failed: ...' toast, which is Compose state and so IS in " +
                        "the after-tree of this step."
                )
            }
        }
        journal.step("the confirmed item was written") {
            val after = vaultCounts()
            check(after == VaultCounts(before.items + 1, before.protected + 1)) {
                "the vault went from $before to $after after a confirmed save of one " +
                    "protected item; expected exactly one more of each."
            }
        }
    }

    /** Type a recovery phrase into the one text field on the recover screen. */
    private fun typePhrase(words: String) {
        compose.onNode(hasSetTextAction()).performTextReplacement(words)
        // The counter is the screen's own validation of the phrase; if the words
        // did not land this fails here rather than at the decrypt.
        compose.waitUntil(timeoutMillis = UI_SETTLE_TIMEOUT_MS) {
            nodes("24 of 24 words").isNotEmpty()
        }
    }

    /**
     * Tap the item's row on the recover screen.
     *
     * `performScrollTo` is not decoration. The row is in a LazyColumn under a
     * 160dp phrase field with the soft keyboard up; measured on a 1080x2400
     * emulator it cleared the IME by 24px with 100px of unscrolled content still
     * below it. A shorter device, a taller keyboard, one more line of intro
     * copy, or -- as happens later in this very journey -- a second item in the
     * vault puts it under the keyboard, and the test then dies with "no node
     * found", which reads like a product regression and is not one.
     */
    private fun tapItemRow() {
        compose.onNodeWithText(item).performScrollTo().performClick()
    }

    private data class VaultCounts(val items: Int, val protected: Int)

    /**
     * The vault list's own subtitle, `"$N items · $M protected"`, read back out
     * of the semantics tree. Derived rather than assumed: the assertions that
     * use it compare two readings of the same screen, so they hold whatever the
     * fixture happens to contain, and they do not quietly pass if the list stops
     * rendering a count at all.
     */
    private fun vaultCounts(): VaultCounts {
        val m = VAULT_SUBTITLE.find(treeText())
            ?: error(
                "no '<n> items · <m> protected' subtitle in the tree -- this is not the " +
                    "vault list. The capture for this step shows which screen it is."
            )
        return VaultCounts(m.groupValues[1].toInt(), m.groupValues[2].toInt())
    }

    private fun nodes(text: String, substring: Boolean = false) =
        compose.onAllNodesWithText(text, substring = substring).fetchSemanticsNodes()

    /**
     * The whole semantics tree, settled -- EVERY root, not `onRoot()`.
     *
     * A Compose `Dialog` composes into its own window with its own semantics
     * root, so the moment AddItemScreen's "This device can't open this item"
     * confirmation is up there are two, and `onRoot()` throws "Expected exactly
     * '1' node but found '2'". That threw inside the journal's capture, which
     * failed the run at the exact step whose tree is the evidence for the write
     * gate. Dumping all roots keeps the dialog in the artifact instead of
     * turning it into a crash.
     */
    private fun treeText(): String {
        compose.waitForIdle()
        return compose.onAllNodes(isRoot()).printToString(maxDepth = 100)
    }

    private companion object {
        /** Argon2/PBKDF2 derivation plus a network round trip. */
        const val SIGN_IN_TIMEOUT_MS = 60_000L

        /** A local recompose; anything slower than this is a hang, not latency. */
        const val UI_SETTLE_TIMEOUT_MS = 10_000L

        /** An encrypt plus a create round trip to the loopback server. */
        const val SAVE_TIMEOUT_MS = 30_000L

        /**
         * One age unwrap over JNI -- measured at ~150ms -- and deliberately UNDER
         * RageApp.kt's `delay(3000)` toast lifetime.
         *
         * This used to be 5s, which made the timeout message a lie: it told the
         * operator that a decrypt failure "IS in the after-tree of this step",
         * while the toast saying so had been auto-dismissed two seconds before
         * the capture was taken. Anyone reading it went hunting a hit-testing
         * bug that was not there. Raising this above 3_000 puts that lie back;
         * if it ever needs raising, the message has to stop promising the toast.
         */
        const val REVEAL_TIMEOUT_MS = 2_500L

        /**
         * RecoverFromPhraseScreen's refusal, minus the item name it is prefixed
         * with. Matched as a substring so the item name does not have to be
         * spliced in, but matched by value so a screen that silently does
         * nothing cannot pass for one that refused.
         */
        const val REFUSAL_TOAST = "can't be unlocked by this phrase"

        /** AddItemScreen's warning under the recipient chips. */
        const val UNOPENABLE_WARNING = "None of these are keys this device can unlock with."

        /** AddItemScreen's pre-save confirmation. */
        const val UNOPENABLE_DIALOG_TITLE = "This device can't open this item"

        /** What a chip for a registry-only recipient is suffixed with. */
        const val FOREIGN_CHIP_SUFFIX = "· other device"

        /**
         * The three families of meta cipher, spelled out here as LITERALS.
         *
         * Deliberately not `VaultMetaNames.RAGETERM_RECIPIENT_LIST` and
         * friends, even though this source set compiles against main/. These
         * are cross-client wire constants owned by the OTHER two clients --
         * `rageterm/src/recipients.rs:20`, `core/src/history.rs:15` and
         * `core/src/sync.rs:1056` -- and an assertion that imports ragedroid's
         * copy is an assertion that follows ragedroid's copy wherever it is
         * edited. Renaming the constant would then keep this green while the
         * filter stopped matching what rageterm actually writes.
         */
        const val RAGETERM_RECIPIENT_LIST = "Ragewarden Recipients (do not edit)"
        const val HISTORY_MARKER = "__ragewarden_history_v1__"
        const val RAGEDROID_MARKER = "__ragedroid_"

        /**
         * What run.sh's fixture makes the vault header say, by value.
         *
         * run.sh stores exactly ONE item (`journey-item`, wrapped to the paper
         * recipient) and this device enrols nothing, so the list is one item,
         * protected. Every other cipher on that server -- the recipient list
         * `enroll-software-identity` writes, plus anything a later client
         * leaves -- is machinery and must not be counted.
         *
         * Hardcoded rather than passed in as an instrumentation argument on
         * purpose: a number the runner derives from the same vault it is
         * checking would move with the pollution instead of catching it.
         */
        val FIXTURE_VAULT = VaultCounts(items = 1, protected = 1)

        /**
         * The composer's own fixture. Not an instrumentation argument: run.sh
         * neither creates nor reads it, and the account is thrown away after the
         * run.
         */
        const val COMPOSER_ITEM = "composer-fail-open-item"
        const val COMPOSER_SECRET = "composer-fail-open-secret"

        /**
         * Positions of Name and Password among a Login composer's text fields
         * (Name, Website, Username, Password). Same reasoning as the sign-in
         * form: main/ sets no testTag anywhere, so position over
         * hasSetTextAction() is the only stable handle, and a field appearing or
         * moving breaks this loudly rather than quietly typing into the wrong
         * box.
         */
        const val COMPOSER_NAME_FIELD = 0
        const val COMPOSER_PASSWORD_FIELD = 3

        val VAULT_SUBTITLE = Regex("""(\d+) items · (\d+) protected""")
    }

    private fun fields() = compose.onAllNodes(hasSetTextAction())
    private fun fieldCount() = compose.onAllNodes(hasSetTextAction()).fetchSemanticsNodes().size

    private fun arg(name: String): String? =
        InstrumentationRegistry.getArguments().getString(name)?.takeIf { it.isNotBlank() }

    private fun requireArg(name: String): String = arg(name)
        ?: error(
            "instrumentation argument '$name' is missing. This test is driven by " +
                "tests/journey/run.sh, which supplies it; running it bare from an IDE " +
                "or `gradle connectedAndroidTest` alone will not work."
        )
}
