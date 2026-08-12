package ragewarden.ragedroid.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultSnapshotJsonTest {
    @Test
    fun parses_a_minimal_vault() {
        val json = """
            {
              "items": [
                {
                  "id": "id-1",
                  "name": "name-1",
                  "username": "user-1",
                  "site": "site-1.example",
                  "folder": "folder-1",
                  "rage": true,
                  "recipients": ["rcpt-1"],
                  "lastUsed": "ts-1",
                  "history": 4,
                  "rageBlob": "blob-1",
                  "plainPassword": "",
                  "totpSeed": null,
                  "notes": null,
                  "favorite": true
                }
              ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val snap = VaultSnapshot.fromJson(json)
        assertEquals(1, snap.items.size)
        val item = snap.items[0]
        assertEquals("id-1", item.id)
        assertEquals("name-1", item.name)
        assertTrue(item.rage)
        assertEquals("", item.password)
        assertNull(item.totpSeed)
        assertEquals(true, item.favorite)
    }

    @Test
    fun rage_blob_map_filters_non_rage_items() {
        val json = """
            {
              "items": [
                {"id":"a","name":"x","username":"u","site":"s","folder":"f","rage":true,"recipients":[],"lastUsed":"","history":0,"rageBlob":"BLOB-A","plainPassword":""},
                {"id":"b","name":"y","username":"u","site":"s","folder":"f","rage":false,"recipients":[],"lastUsed":"","history":0,"rageBlob":null,"plainPassword":"plain-pw"}
              ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val map = CipherRageBlobMap.fromJson(json)
        assertEquals(setOf("a"), map.byItemId.keys)
        assertEquals("BLOB-A", map.byItemId["a"])
    }

    @Test
    fun non_rage_items_carry_plaintext_password() {
        val json = """
            {
              "items": [
                {"id":"id-2","name":"name-2","username":"user-2","site":"site-2.example","folder":"folder-2","rage":false,"recipients":[],"lastUsed":"","history":0,"plainPassword":"pw-2"}
              ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val snap = VaultSnapshot.fromJson(json)
        val item = snap.items[0]
        assertFalse(item.rage)
        assertEquals("pw-2", item.password)
        assertNotNull(item)
    }
}
