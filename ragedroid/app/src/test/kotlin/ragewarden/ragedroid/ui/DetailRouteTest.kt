package ragewarden.ragedroid.ui

import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Test
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind

class DetailRouteTest {
    private fun item(name: String, kind: VaultItemKind, rage: Boolean = false, notes: String? = null) = VaultItem(
        id = name, name = name, username = "", site = "", folder = "All", rage = rage,
        recipients = persistentListOf(), password = "", notes = notes, lastUsed = "", history = 0, kind = kind,
    )

    @Test
    fun a_login_named_like_a_card_still_opens_the_login_screen() {
        assertEquals(DetailRoute.Login, detailRouteFor(item("Cardano wallet", VaultItemKind.Login)))
        assertEquals(DetailRoute.Login, detailRouteFor(item("SSH jump host", VaultItemKind.Login)))
    }

    @Test
    fun non_login_kinds_open_the_kind_screen_whatever_their_name() {
        assertEquals(DetailRoute.Kind, detailRouteFor(item("GitHub", VaultItemKind.Note, notes = "text")))
        assertEquals(DetailRoute.Kind, detailRouteFor(item("GitHub", VaultItemKind.Card)))
        assertEquals(DetailRoute.Kind, detailRouteFor(item("GitHub", VaultItemKind.SshKey)))
        assertEquals(DetailRoute.Kind, detailRouteFor(item("GitHub", VaultItemKind.Identity)))
    }

    @Test
    fun a_protected_note_with_only_the_rage_payload_opens_through_the_tap_gate() {
        assertEquals(DetailRoute.Login, detailRouteFor(item("bank", VaultItemKind.Note, rage = true)))
    }
}
