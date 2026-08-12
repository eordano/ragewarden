package ragewarden.ragedroid.identities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-language contract with `core/src/stanza_format.rs::check_prf_stanza_arity`.
 *
 * `fido2-hmac` and `webauthn-prf-v1` stanzas gained a fourth argument -- a fresh
 * per-encryption wrap salt -- while blobs written before that change still carry
 * three. Core accepts both. A Kotlin identity that hard-rejects anything but 3
 * does not report an error: it returns null, which the age layer reads as "this
 * stanza belongs to some other recipient", so every secret written by a current
 * core looks like "no matching identity" on Android instead of failing loudly.
 *
 * These assertions are cheap insurance against that regressing back into a
 * literal `== 3`.
 */
class PrfStanzaArityTest {
    @Test
    fun arity_constants_match_core() {
        assertEquals(3, StanzaTags.PRF_ARGS_LEGACY)
        assertEquals(4, StanzaTags.PRF_ARGS_CURRENT)
    }

    @Test
    fun both_legacy_and_current_prf_arities_are_accepted() {
        assertTrue("legacy 3-arg PRF stanzas must stay decryptable", StanzaTags.isPrfArity(3))
        assertTrue("current 4-arg (wrap-salt) PRF stanzas must be accepted", StanzaTags.isPrfArity(4))
    }

    @Test
    fun other_arities_are_rejected() {
        assertFalse(StanzaTags.isPrfArity(0))
        assertFalse(StanzaTags.isPrfArity(2))
        assertFalse(StanzaTags.isPrfArity(5))
    }
}
