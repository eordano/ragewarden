package ragewarden.ragedroid.registry

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.HistoryStore
import ragewarden.ragedroid.data.RecipientRegistry
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.RotationTracker
import ragewarden.ragedroid.data.SessionStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.identities.MockHardware
import ragewarden.ragedroid.identities.enrollKeystoreIdentity
import ragewarden.ragedroid.model.RecipientKind

/**
 * Enrol a recipient on the device against a vault another client already
 * published a registry into, and require the vault to still hold exactly ONE
 * `__ragedroid_recipients_v1__` marker afterwards.
 *
 * WHY THIS EXISTS. `BitwardenVaultRepository.pushRecipientRegistry` is the one
 * cross-client fix in this app whose code never ran under any test. Its four
 * callers are all enrolment paths -- `AddRecipientViewModel.persist`,
 * `FirstRunScreen`, and two in `RageApp` -- and `journey/JourneyTest` walks past
 * both enrolment steps on purpose ("skip passkey enrolment", "skip the backup
 * recipient"), because the emulator has no security key. So the journey, which
 * is otherwise the only test that runs the real app against a real server,
 * cannot reach this function at all. Nothing else in the repository instantiates
 * it either. An unasserted fix is bad; a fix whose code never executes is worse,
 * and this file is the fix for that.
 *
 * THE BUG. The push used to build its payload from `cached.snapshot` and
 * `sync()` only AFTER writing. On the ordinary first-run path -- login, enrol,
 * `persist()` -- nothing syncs in between, so the cache is EMPTY: `remoteEntries`
 * came back empty and `markerCipherId` came back null, the write took the
 * `createCipher` branch, and the vault ended up with a SECOND marker cipher
 * holding only this phone's key. `core::registry::find_marker_cipher` takes
 * whichever marker the SERVER returns first, so from that moment on different
 * clients read different registries: the browser's own Software and passkey
 * entries stopped being recipients, it could no longer open its own writes, and
 * withdrawing an entry became a no-op against a marker nobody was reading.
 *
 * The fix is `sync().getOrThrow()` as the first statement of the push, plus
 * `RecipientRegistry.readEntries` refusing a duplicated or unparseable marker
 * rather than replacing it.
 *
 * WHAT THIS TEST DOES, and why each part is load-bearing:
 *
 *   * `tests/journey/seed-browser-registry.mjs` registers a throwaway account
 *     and publishes two entries into it by running the SHIPPED
 *     `ragemanifest/ext/wasm` bundle under node -- the same module the browser
 *     extension loads. The precondition is a vault that ALREADY has another
 *     client's marker; a phone pushing into an empty vault cannot duplicate a
 *     marker that is not there, which is exactly why no existing test could
 *     catch this.
 *
 *   * This test then signs in FROM COLD and never syncs before the push. That
 *     is not a shortcut, it is the reproduction: `login()` does not sync (see
 *     `BitwardenVaultRepository.login`), so the first-run path really does reach
 *     the push with an empty cache. [coldCacheProof] asserts the cache is empty
 *     at that moment, so a future change that starts syncing during login turns
 *     this test red instead of quietly making it prove nothing.
 *
 *   * The recipient enrolled here is a REAL AndroidKeyStore key from
 *     `enrollKeystoreIdentity` -- no ceremony, no security key, nothing mocked,
 *     so it is genuinely published and can be asserted for by id. A second,
 *     MOCK recipient is enrolled beside it and must NOT appear on the wire; that
 *     is the unconditional `filterNot { it.mock }` in the same function, and it
 *     costs one assertion to hold onto.
 *
 *   * The assertions are made against a fresh `sync()` -- the server's state, not
 *     this repository's idea of it.
 *
 * The two lines below the push are the ones that matter:
 * `assertEquals(1, markers.size)` and the browser entries surviving. Under the
 * pre-fix code the first sees 2.
 *
 * WHY IT CALLS THE REPOSITORY DIRECTLY rather than driving the enrolment UI:
 * the ceremony screens need a real authenticator (out of scope -- see the brief's
 * "hardware ceremonies out of scope"), and `AddRecipientViewModel.persist` is
 * literally `recipientStore.add(accountId, recipient)` followed by
 * `VaultBridge.repository()?.pushRecipientRegistry()`, which is what happens
 * here, in that order. The defect is in the repository method, and the repository
 * method is what runs.
 *
 * RUN IT VIA `tests/journey/run.sh`, which starts the loopback Vaultwarden, runs
 * the seeding script, does the `adb reverse` (the app refuses any non-loopback
 * server -- `core::sync::host_is_loopback`), and passes the arguments read below.
 * Without those arguments the test cannot mean anything, so it is skipped rather
 * than failed for a reason that has nothing to do with the app -- and run.sh
 * checks the AGP result XML for exactly one executed, non-skipped test case so
 * that "skipped" can never be mistaken for "passed".
 *
 * SECRETS: a throwaway account on a loopback server, destroyed by the runner.
 * Never point this at a real vault.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class RegistryPushInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val ctx: Context get() = instrumentation.targetContext

    private fun arg(name: String): String? =
        InstrumentationRegistry.getArguments().getString(name)?.takeIf { it.isNotBlank() }

    @Test
    fun enrolling_into_a_browser_seeded_vault_leaves_exactly_one_registry_marker() {
        val server = arg("registryServer")
        assumeTrue(
            "registryServer/registryEmail/registryPassword/registryBrowserEntryIds were not " +
                "passed. This test needs a Vaultwarden with a browser-published registry in " +
                "it; tests/journey/run.sh builds that and passes them.",
            server != null,
        )
        runBlocking { enrolIntoSeededVault(server!!) }
    }

    private suspend fun enrolIntoSeededVault(server: String) {
        val email = requireArg("registryEmail")
        val password = requireArg("registryPassword")
        val browserEntryIds = requireArg("registryBrowserEntryIds")
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        assertTrue(
            "registryBrowserEntryIds must name the entries the browser published; " +
                "an empty list would make the survival assertion vacuous",
            browserEntryIds.isNotEmpty(),
        )

        // A debug build gates mock hardware on this property as well as on
        // BuildConfig (identities/MockHardware.kt). It has to be set before the
        // mock recipient below is stored, or RecipientStore.forAccount would drop
        // it and the "mocks never reach the wire" assertion would pass with the
        // filter deleted.
        System.setProperty(MockHardware.ENV_VAR, "1")
        assertTrue(
            "this must be a debug build with mock hardware allowed, otherwise the mock " +
                "recipient below is dropped before pushRecipientRegistry ever sees it",
            MockHardware.enabled(),
        )

        val recipientStore = RecipientStore(ctx)
        val registry = RecipientRegistry(recipientStore)
        // Constructed by hand rather than injected: this test wants a repository
        // whose cache has never been warmed, which is the state the first-run
        // enrolment path is in and the state the bug needs.
        val repo = BitwardenVaultRepository(
            sessionStore = SessionStore(ctx),
            recipientStore = recipientStore,
            auditFeed = AuditFeed(ctx),
            rotationTracker = RotationTracker(ctx, recipientStore),
            historyStore = HistoryStore(ctx),
            recipientRegistry = registry,
            lockState = ragewarden.ragedroid.data.LockState(
                ctx,
                ragewarden.ragedroid.data.LockPolicy(ctx),
                hasSession = { false },
            ),
            vaultCache = ragewarden.ragedroid.data.VaultCache(ctx),
            deviceIdentity = ragewarden.ragedroid.data.DeviceIdentity(ctx),
            kdfPins = ragewarden.ragedroid.data.KdfPinStore(ctx),
        )

        repo.login(server, email, password).getOrThrow()
        val accountId = repo.accountId
        assertTrue("login produced no userId, so there is no account to enrol into", accountId.isNotBlank())

        // The reproduction condition, asserted rather than assumed. See the class
        // header: if login ever starts syncing, this goes red and whoever changed
        // it learns that this test depended on the cold cache.
        val coldCacheProof = repo.snapshotWithRegistryMarker()
        assertEquals(
            "the repository was expected to reach pushRecipientRegistry with an EMPTY cache, " +
                "the way login -> enrol -> persist() reaches it; it already held " +
                "${coldCacheProof.size} item(s), so this test is no longer reproducing the " +
                "cold-cache push and its result means nothing",
            0,
            coldCacheProof.size,
        )
        assertTrue(
            "this account already has recipients enrolled on this device; the test needs a " +
                "device that has never enrolled into it",
            recipientStore.forAccount(accountId).isEmpty(),
        )

        // Enrolment, exactly as AddRecipientViewModel.persist does it: store the
        // recipient, then push. The keystore key is real -- StrongBox if the device
        // has it, a software-backed AndroidKeyStore key otherwise (the emulator
        // takes that fallback), and either way not a mock, so it is published.
        val (real, _) = enrollKeystoreIdentity(
            displayName = "Registry push test key",
            requireBiometric = false,
        )
        val mock = StoredRecipient(
            id = "mock-registry-push-test",
            kind = RecipientKind.StrongBox,
            displayName = MockHardware.label("Simulated authenticator", isMock = true),
            createdAt = System.currentTimeMillis(),
            lastUsedAt = 0L,
            // 33 bytes of SEC1-compressed-looking material: RecipientStore.forAccount
            // drops StrongBox entries of any other length, and this one has to
            // survive that far to be worth filtering at push time.
            keystorePubkey = ByteArray(33) { if (it == 0) 0x02 else it.toByte() },
            keystoreHandle = "mock-registry-push-test-handle",
            mock = true,
        )
        recipientStore.add(accountId, mock)
        recipientStore.add(accountId, real)

        repo.pushRecipientRegistry().getOrThrow()

        // The server's answer, not this repository's memory of it.
        repo.sync().getOrThrow()
        val snapshot = repo.snapshotWithRegistryMarker()
        val markers = registry.markerItems(snapshot)
        dumpArtifacts(snapshot.map { it.name }, markers.map { it.id }, browserEntryIds)

        assertEquals(
            "the vault must hold exactly one `${RecipientRegistry.MARKER_NAME}` cipher. " +
                "It holds ${markers.size} (ids: ${markers.map { it.id }}). A second marker " +
                "means the push wrote a registry it had not just read: " +
                "core::registry::find_marker_cipher takes whichever the server returns " +
                "first, so from here on different clients read different registries and " +
                "the entries in the loser are gone.",
            1,
            markers.size,
        )

        // readEntries (not extractFromSnapshot) on purpose: it throws on a
        // duplicated or unparseable marker instead of reporting an empty
        // registry, which is the distinction the fix turns on.
        val entries = registry.readEntries(snapshot)
        val publishedIds = entries.map { it.id }.toSet()
        for (browserId in browserEntryIds) {
            assertTrue(
                "the browser published $browserId before this device ever signed in, and it " +
                    "is not in the registry any more. Published now: $publishedIds. The " +
                    "phone's push overwrote entries it never read.",
                browserId in publishedIds,
            )
        }
        assertTrue(
            "the recipient enrolled on this device (${real.id}) was not published, so the " +
                "push did not merge -- it would leave this phone unable to be wrapped to. " +
                "Published now: $publishedIds",
            real.id in publishedIds,
        )
        assertTrue(
            "the MOCK recipient ${mock.id} reached the shared registry. Simulated hardware " +
                "must never be published: every other client would wrap real secrets to a " +
                "key that does not exist. Published now: $publishedIds",
            mock.id !in publishedIds,
        )
    }

    private fun requireArg(name: String): String =
        arg(name) ?: error(
            "missing instrumentation argument `$name`. Run this through " +
                "tests/journey/run.sh, which seeds the browser registry and passes it."
        )

    /**
     * The evidence a failed run is diagnosed from, in the directory AGP pulls
     * back (`additionalTestOutputDir`). Screen captures are not an option:
     * ragedroid sets FLAG_SECURE in ui/SecureWindow.kt and every capture of this
     * app comes back blank by design.
     */
    private fun dumpArtifacts(
        itemNames: List<String>,
        markerIds: List<String>,
        browserEntryIds: List<String>,
    ) {
        val base = InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")
            ?.takeIf { it.isNotBlank() }
            ?.let { File(it, "registry") }
            ?: File(ctx.getExternalFilesDir("registry") ?: return, "")
        base.mkdirs()
        File(base, "markers.json").writeText(
            JSONObject()
                .put("markerName", RecipientRegistry.MARKER_NAME)
                .put("markerCipherIds", JSONArray(markerIds))
                .put("markerCount", markerIds.size)
                .put("vaultItemNames", JSONArray(itemNames))
                .put("browserEntryIds", JSONArray(browserEntryIds))
                .toString(2)
        )
    }
}
