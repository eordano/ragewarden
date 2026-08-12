package ragewarden.ragedroid.data

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import ragewarden.ragedroid.data.RecipientPolicy.toPolicyWire
import ragewarden.ragedroid.model.RecipientKind

/**
 * Kotlin half of the cross-client recipient-policy conformance check.
 *
 * The policy itself now lives in one place (`core/src/policy.rs`) and ragedroid
 * reaches it over JNI, so the three clients cannot disagree about *which*
 * recipients to use. What can still drift, and used to be untested, is the
 * encoding of the answer as it crosses the language boundary: if Kotlin's
 * [WireRecipient] and Rust's `Recipient` ever stop agreeing on field names,
 * discriminators or byte encoding, the app silently wraps to the wrong set
 * again.
 *
 * The Rust side pins those bytes in `core/tests/vectors/recipient_policy_v1.json`
 * (`core/tests/recipient_policy_cross_client.rs::wire_vectors_match_the_checked_in_file`).
 * This test reads the same file. Regenerate both together with
 * `RAGEWARDEN_BLESS_VECTORS=1 cargo test -p ragewarden-core`.
 */
class RecipientPolicyConformanceTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun vectors(): String {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "core/tests/vectors/recipient_policy_v1.json")
            if (f.isFile) return f.readText()
            dir = dir.parentFile
        }
        throw AssertionError(
            "core/tests/vectors/recipient_policy_v1.json not found above " +
                System.getProperty("user.dir") +
                "; regenerate with RAGEWARDEN_BLESS_VECTORS=1 cargo test -p ragewarden-core",
        )
    }

    private fun selection(field: String): RecipientPolicy.Selection {
        val root = json.parseToJsonElement(vectors()).jsonObject
        val sel = root[field] ?: throw AssertionError("vectors have no `$field`")
        return RecipientPolicy.decodeSelection(sel.toString())
    }

    @Test
    fun kotlin_decodes_the_recipient_set_core_produces() {
        val sel = selection("no_local_authenticator")

        // Software + Recovery both become software_passphrase; plus the
        // YubiKey and the StrongBox key. ragedroid used to drop Software
        // entirely, so this count was 3 on Android and 2 in the browser for the
        // very same registry.
        assertEquals("recipients: ${sel.recipients}", 4, sel.recipients.size)

        val software = sel.recipients.filterIsInstance<WireRecipient.SoftwarePassphrase>()
        assertEquals(2, software.size)
        assertTrue(
            "the Software entry must survive into ragedroid's wrap set",
            software.any {
                it.armored_pubkey ==
                    "age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k"
            },
        )

        val piv = sel.recipients.filterIsInstance<WireRecipient.YubiKeyPiv>().single()
        assertEquals(32, piv.public_key.size)
        assertEquals(0x123456L, piv.serial)
        assertEquals(0x95, piv.slot)

        val keystore = sel.recipients.filterIsInstance<WireRecipient.AndroidKeystore>().single()
        assertEquals(33, keystore.public_key.size)
        assertEquals("ragewarden-keystore-fixture", keystore.key_handle)
    }

    @Test
    fun every_skip_arrives_with_a_reason_kotlin_recognises() {
        val sel = selection("no_local_authenticator")
        val known = setOf(
            RecipientPolicy.Reasons.DEFAULT_ENCRYPT_OFF,
            RecipientPolicy.Reasons.UNKNOWN_KIND,
            RecipientPolicy.Reasons.MALFORMED_KEY_MATERIAL,
            RecipientPolicy.Reasons.NO_LOCAL_AUTHENTICATOR,
        )
        assertTrue("no skips in the fixture", sel.skipped.isNotEmpty())
        for (skip in sel.skipped) {
            assertTrue("unrecognised skip reason ${skip.reason}", skip.reason in known)
        }
        assertEquals(
            listOf("e-fido2"),
            sel.unreachableAuthenticators().map { it.id },
        )
    }

    /**
     * The one sanctioned per-client divergence, seen from Kotlin: holding the
     * authenticator adds a recipient and never removes one.
     */
    @Test
    fun holding_the_authenticator_only_adds_the_prf_recipient() {
        val without = selection("no_local_authenticator").recipients
        val with = selection("holds_fido2").recipients

        assertEquals(without.size + 1, with.size)
        assertTrue(with.containsAll(without))

        val fido = with.filterIsInstance<WireRecipient.Fido2HmacSecret>().single()
        assertEquals("ragewarden", fido.rp_id)
        assertEquals(32, fido.salt.size)
        assertTrue(without.none { it is WireRecipient.Fido2HmacSecret })
    }

    /**
     * The live Kotlin-side transform: a locally stored recipient must project
     * onto a registry entry the policy understands, or a key enrolled on this
     * phone quietly stops being wrapped to.
     */
    @Test
    fun stored_recipients_project_onto_registry_entries_without_loss() {
        val stored = StoredRecipient(
            id = "local-strongbox",
            kind = RecipientKind.StrongBox,
            displayName = "This phone",
            createdAt = 42L,
            lastUsedAt = 0L,
            keystorePubkey = ByteArray(33) { if (it == 0) 0x03 else 0x11 },
            keystoreHandle = "handle-1",
        )
        val wire = stored.toPolicyWire("Pixel")
        assertEquals("local-strongbox", wire.id)
        assertEquals("StrongBox", wire.kind)
        assertEquals("handle-1", wire.keystoreHandle)
        assertEquals(66, wire.keystorePubkey?.length)
        assertTrue("hex must be lower case", wire.keystorePubkey!!.none { it.isUpperCase() })
        assertTrue(wire.defaultEncrypt)
    }

    /**
     * Android passkeys are stored under `passkey*` but have always been wrapped
     * as `fido2-hmac`. The projection must keep doing that: reading only the
     * `fido2*` fields would drop the recipient, and switching the tag would
     * orphan every item already written.
     */
    @Test
    fun passkey_fields_fall_back_onto_the_fido2_wire_fields() {
        val stored = StoredRecipient(
            id = "local-passkey",
            kind = RecipientKind.Fido2,
            displayName = "Phone passkey",
            createdAt = 7L,
            lastUsedAt = 0L,
            passkeyCredentialId = byteArrayOf(1, 2, 3),
            passkeyRpId = "ragewarden",
            passkeySalt = ByteArray(32) { 0x22 },
        )
        val wire = stored.toPolicyWire("Pixel")
        assertEquals("Fido2", wire.kind)
        assertEquals("010203", wire.fido2CredentialId)
        assertEquals("ragewarden", wire.fido2RpId)
        assertEquals(64, wire.fido2Salt?.length)

        assertEquals(
            listOf("local-passkey"),
            RecipientPolicy.localPrfEntryIds(listOf(stored)),
        )
    }

    @Test
    fun a_disabled_stored_recipient_stays_disabled_through_the_projection() {
        val stored = StoredRecipient(
            id = "off",
            kind = RecipientKind.Recovery,
            displayName = "Paper",
            createdAt = 1L,
            lastUsedAt = 0L,
            defaultEncrypt = false,
            recoveryArmoredPubkey = "age1example",
        )
        assertEquals(false, stored.toPolicyWire("Pixel").defaultEncrypt)
    }
}
