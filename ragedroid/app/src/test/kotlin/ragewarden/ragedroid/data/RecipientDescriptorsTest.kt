package ragewarden.ragedroid.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import ragewarden.ragedroid.model.RecipientKind
import org.junit.Test

/**
 * Cross-language contract with `jni/src/lib.rs::rage_recipient_descriptors`.
 *
 * The `GOLDEN_*` lists below are the descriptor vectors the Rust producer
 * actually emits: each one is copied from the `assert_eq!` of the Rust test
 * named beside it, and those tests pin the *whole* vector -- order, contents and
 * length -- against a blob they encrypt with `ragewarden_core` for real. Feeding
 * `resolve()` anything else is how this file used to lie: it hand-wrote an input
 * containing two `"X25519"` entries at a time when the producer deduped
 * descriptors and could only ever emit one, so both halves of the "contract"
 * were green while disagreeing with each other.
 *
 * The copy is not left to good intentions: the Rust golden tests `include_str!`
 * this file and fail if a descriptor they emit is not a literal in it
 * (`assert_kotlin_goldens_agree`), so an encoding change cannot land on one side
 * alone. Keep the descriptor strings below as literals -- a computed one would be
 * invisible to that check.
 *
 * Anything asserted here must therefore be asserted by length as well as by
 * content. A `contains`-shaped assertion on either side is what let age's random
 * GREASE stanza ride along as a phantom recipient -- visible to users as
 * "RAGE · 2" on a single-recipient item, and non-reproducible because the grease
 * tag is fresh per encryption.
 */
class RecipientDescriptorsTest {

    private companion object {
        // Single source of truth for both halves of this file: the `forStored`
        // tests derive these strings locally, the `resolve` tests consume them as
        // they arrive from the producer. Drift in either direction is one edit
        // away from being caught, instead of two literals that can disagree.
        const val PIV = "piv-p256:S7Bvjg"
        const val KEYSTORE = "ragedroid-keystore-v1:OJQWOZLXMFZGIZLOFVVWK6LTORXXEZJNMZUXQ5DVOJSQ"
        const val PASSKEY = "webauthn-prf-v1:dGVzdC1jcmVkZW50aWFs"
        const val FIDO2 = "fido2-hmac:dGVzdC1jcmVkZW50aWFs"

        /** From Rust `recipient_descriptors_are_stable_for_fixed_inputs`. */
        val GOLDEN_MIXED = listOf("X25519", "X25519", PIV, KEYSTORE)

        /** From Rust `recipient_descriptors_name_the_real_recipients`. */
        val GOLDEN_PASSKEY_AND_SOFTWARE = listOf("X25519", PASSKEY)

        /** From Rust `grease_stanza_is_not_a_recipient`: one recipient, one entry. */
        val GOLDEN_SINGLE_SOFTWARE = listOf("X25519")

        /** From Rust `two_software_recipients_are_two_descriptors`. */
        val GOLDEN_TWO_SOFTWARE = listOf("X25519", "X25519")

        val ALL_GOLDEN = listOf(
            GOLDEN_MIXED,
            GOLDEN_PASSKEY_AND_SOFTWARE,
            GOLDEN_SINGLE_SOFTWARE,
            GOLDEN_TWO_SOFTWARE,
        )
    }

    private fun stored(
        kind: RecipientKind,
        pivPubkey: ByteArray? = null,
        keystoreHandle: String? = null,
        fido2CredentialId: ByteArray? = null,
        passkeyCredentialId: ByteArray? = null,
    ) = StoredRecipient(
        id = "id-${kind.name}",
        kind = kind,
        displayName = kind.name,
        createdAt = 0L,
        lastUsedAt = 0L,
        pivPubkey = pivPubkey,
        keystoreHandle = keystoreHandle,
        keystorePubkey = if (keystoreHandle != null) ByteArray(33).also { it[0] = 0x02 } else null,
        fido2CredentialId = fido2CredentialId,
        fido2RpId = if (fido2CredentialId != null) "ragewarden" else null,
        passkeyCredentialId = passkeyCredentialId,
        passkeyRpId = if (passkeyCredentialId != null) "ragewarden" else null,
    )

    private val yubi = stored(RecipientKind.YubiKey, pivPubkey = ByteArray(32) { 0x07.toByte() })
    private val keystore =
        stored(RecipientKind.StrongBox, keystoreHandle = "ragewarden-keystore-fixture")

    @Test
    fun piv_descriptor_matches_the_rust_golden_value() {
        assertEquals(listOf(PIV), RecipientDescriptors.forStored(yubi))
    }

    @Test
    fun keystore_descriptor_matches_the_rust_golden_value() {
        assertEquals(listOf(KEYSTORE), RecipientDescriptors.forStored(keystore))
    }

    @Test
    fun fido2_descriptor_uses_url_safe_unpadded_base64() {
        val r = stored(RecipientKind.Fido2, fido2CredentialId = "test-credential".toByteArray())
        assertEquals(listOf(FIDO2), RecipientDescriptors.forStored(r))
    }

    @Test
    fun software_and_recovery_recipients_are_deliberately_unmatchable() {
        // An age X25519 stanza's only argument is the ephemeral share, so these
        // genuinely cannot be identified from a header. Returning nothing is the
        // honest result; inventing an id would be a fabricated attribution.
        assertTrue(RecipientDescriptors.forStored(stored(RecipientKind.Recovery)).isEmpty())
        assertTrue(RecipientDescriptors.forStored(stored(RecipientKind.Software)).isEmpty())
    }

    /**
     * The producer emits one descriptor per recipient stanza and nothing else, so
     * every entry must land in exactly one bucket. If a future producer change
     * reintroduces a phantom entry (grease, an unknown plugin tag) or drops a
     * real one, this equality breaks even when each individual bucket still looks
     * plausible.
     *
     * Valid only because no two descriptors in these vectors resolve to the same
     * stored recipient -- `matched` is keyed by recipient id, so a recipient that
     * satisfied two descriptors would legitimately contribute one entry.
     */
    private fun assertAccountsForEveryDescriptor(
        descriptors: List<String>,
        result: RecipientDescriptors.Resolution,
    ) {
        assertEquals(
            "every descriptor must be matched, anonymous or unknown: $descriptors -> $result",
            descriptors.size,
            result.matched.size + result.anonymousSoftwareCount + result.unknownHardware.size,
        )
    }

    @Test
    fun resolve_separates_matched_anonymous_and_unknown() {
        // Only the YubiKey is enrolled on this device, so the keystore stanza in
        // the same blob is a real recipient we cannot name: unknown hardware, not
        // an anonymous software key and not a match.
        val result = RecipientDescriptors.resolve(
            descriptors = GOLDEN_MIXED,
            stored = listOf(yubi),
        )
        assertEquals(listOf(yubi), result.matched)
        assertEquals(2, result.anonymousSoftwareCount)
        assertEquals(listOf(KEYSTORE), result.unknownHardware)
        assertAccountsForEveryDescriptor(GOLDEN_MIXED, result)
    }

    @Test
    fun resolve_names_every_hardware_recipient_that_is_enrolled() {
        val result = RecipientDescriptors.resolve(
            descriptors = GOLDEN_MIXED,
            stored = listOf(yubi, keystore),
        )
        assertEquals(listOf(yubi, keystore), result.matched)
        assertEquals(2, result.anonymousSoftwareCount)
        assertEquals(emptyList<String>(), result.unknownHardware)
        assertAccountsForEveryDescriptor(GOLDEN_MIXED, result)
    }

    /**
     * Two software or paper keys must count as two. Descriptors are a list, not a
     * set: the producer used to dedup them, which made "wrapped to my software
     * key and my paper key" render as one recipient -- and, with `recipients.size`
     * back down to 1, kept `ItemDetailScreen`'s multi-identity picker shut.
     */
    @Test
    fun resolve_counts_each_anonymous_recipient_separately() {
        val result = RecipientDescriptors.resolve(GOLDEN_TWO_SOFTWARE, stored = emptyList())
        assertEquals(emptyList<StoredRecipient>(), result.matched)
        assertEquals(2, result.anonymousSoftwareCount)
        assertEquals(emptyList<String>(), result.unknownHardware)
        assertAccountsForEveryDescriptor(GOLDEN_TWO_SOFTWARE, result)
    }

    @Test
    fun resolve_matches_a_passkey_recipient_alongside_an_anonymous_one() {
        val passkey =
            stored(RecipientKind.Fido2, passkeyCredentialId = "test-credential".toByteArray())
        val result = RecipientDescriptors.resolve(
            descriptors = GOLDEN_PASSKEY_AND_SOFTWARE,
            stored = listOf(passkey),
        )
        assertEquals(listOf(passkey), result.matched)
        assertEquals(1, result.anonymousSoftwareCount)
        assertEquals(emptyList<String>(), result.unknownHardware)
        assertAccountsForEveryDescriptor(GOLDEN_PASSKEY_AND_SOFTWARE, result)
    }

    /**
     * A one-recipient item must read as one recipient. This is the "RAGE · 2"
     * bug stated in the consumer's own terms: age writes a random
     * `"<junk>-grease"` stanza into every header, the producer's catch-all turned
     * it into a descriptor, and `unknownHardware` would then have shown the user a
     * hardware key that does not exist.
     */
    @Test
    fun a_single_software_recipient_resolves_to_exactly_one() {
        val result = RecipientDescriptors.resolve(GOLDEN_SINGLE_SOFTWARE, stored = listOf(yubi))
        assertEquals(emptyList<StoredRecipient>(), result.matched)
        assertEquals(1, result.anonymousSoftwareCount)
        assertEquals(emptyList<String>(), result.unknownHardware)
        assertAccountsForEveryDescriptor(GOLDEN_SINGLE_SOFTWARE, result)
    }

    @Test
    fun no_golden_vector_carries_a_grease_descriptor() {
        ALL_GOLDEN.forEach { golden ->
            val grease = golden.filter { it.substringBefore(':').endsWith("-grease") }
            assertEquals("grease leaked into a golden vector: $golden", emptyList<String>(), grease)
        }
    }
}
