package ragewarden.ragedroid.ui

import kotlinx.collections.immutable.persistentListOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.screens.rewrapAll

class RewrapAllTest {
    private fun item(id: String) = VaultItem(
        id = id, name = "Item $id", username = "", site = "", folder = "All", rage = true,
        recipients = persistentListOf(), password = "", lastUsed = "", history = 0,
    )

    @Test
    fun every_stale_item_is_tried_in_order_and_a_failure_does_not_stop_the_rest() = runBlocking {
        val opened = mutableListOf<String>()
        var last: Triple<String?, Int, List<Pair<String, String>>>? = null
        rewrapAll(listOf(item("a"), item("b"), item("c")), open = { i ->
            opened += i.id
            if (i.id == "b") throw IllegalStateException("tap declined")
        }) { current, processed, failed -> last = Triple(current, processed, failed) }
        assertEquals(listOf("a", "b", "c"), opened)
        assertEquals(Triple(null, 3, listOf("b" to "tap declined")), last)
    }
}
