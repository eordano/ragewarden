package ragewarden.ragedroid.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RotationProgressTest {
    @Test
    fun vault_stays_stale_until_every_item_is_rotated() {
        var stored: RotationProgress.Stored? = RotationProgress.fresh("r1")
        assertFalse(RotationProgress.isStale(stored, "r1"))
        assertTrue(RotationProgress.isStale(stored, "r1+r2"))

        stored = RotationProgress.itemRotated(stored, "r1+r2", "item-a")
        assertTrue(RotationProgress.isStale(stored, "r1+r2"))
        assertEquals(setOf("item-a"), RotationProgress.rotatedIds(stored, "r1+r2"))

        stored = RotationProgress.itemRotated(stored, "r1+r2", "item-b")
        assertEquals(setOf("item-a", "item-b"), RotationProgress.rotatedIds(stored, "r1+r2"))
        assertTrue(RotationProgress.isStale(stored, "r1+r2"))

        stored = RotationProgress.fresh("r1+r2")
        assertFalse(RotationProgress.isStale(stored, "r1+r2"))
    }

    @Test
    fun recipient_change_mid_rotation_resets_progress() {
        var stored: RotationProgress.Stored? = RotationProgress.itemRotated(RotationProgress.fresh("r1"), "r1+r2", "item-a")
        stored = RotationProgress.itemRotated(stored, "r1+r2+r3", "item-b")
        assertEquals(setOf("item-b"), RotationProgress.rotatedIds(stored, "r1+r2+r3"))
        assertTrue(RotationProgress.isStale(stored, "r1+r2+r3"))
    }

    @Test
    fun legacy_record_written_after_the_first_rotated_item_reads_as_in_progress() {
        val legacy = """{"fingerprint":"r1+r2","rotatedIds":["item-a"]}"""
        val stored = RotationProgress.decode(legacy)
        assertTrue(RotationProgress.isStale(stored, "r1+r2"))
        assertEquals(setOf("item-a"), RotationProgress.rotatedIds(stored, "r1+r2"))
        val freshLegacy = RotationProgress.decode("""{"fingerprint":"r1","rotatedIds":[]}""")
        assertFalse(RotationProgress.isStale(freshLegacy, "r1"))
    }

    @Test
    fun round_trips_through_encode_decode() {
        val stored = RotationProgress.itemRotated(RotationProgress.fresh("r1"), "r2", "x")
        assertEquals(stored, RotationProgress.decode(RotationProgress.encode(stored)))
    }
}
