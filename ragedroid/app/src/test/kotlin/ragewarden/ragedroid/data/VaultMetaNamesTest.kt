package ragewarden.ragedroid.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultMetaNamesTest {
    @Test
    fun every_clients_bookkeeping_cipher_is_meta() {
        listOf(
            "__ragewarden_history_v2__",
            "__ragewarden_history_v1__",
            "__ragewarden_history_v1__:0b6a3c1e",
            RecipientRegistry.MARKER_NAME,
            VaultMetaNames.RAGETERM_RECIPIENT_LIST,
        ).forEach { assertTrue(it, VaultMetaNames.isMeta(it)) }
    }

    @Test
    fun a_users_item_is_not() {
        assertFalse(VaultMetaNames.isMeta("GitHub"))
        assertFalse(VaultMetaNames.isMeta("ragewarden history notes"))
    }
}
