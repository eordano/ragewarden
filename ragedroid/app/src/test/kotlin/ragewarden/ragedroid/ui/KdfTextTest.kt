package ragewarden.ragedroid.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.KdfSummary

/** The lock and account screens name the account's real KDF, not a hardcoded PBKDF2. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class KdfTextTest {
    private val res get() = ApplicationProvider.getApplicationContext<Context>().resources

    @Test
    fun an_argon2id_account_is_described_as_argon2id() {
        assertEquals(
            "Argon2id, 64 MiB, 3 passes, 4 lanes",
            KdfSummary(KdfSummary.ARGON2ID, iterations = 3, memoryMib = 64, parallelism = 4).describe(res),
        )
    }

    @Test
    fun a_pbkdf2_account_shows_its_rounds() {
        assertEquals(
            "PBKDF2-SHA256, 600 000 rounds",
            KdfSummary(KdfSummary.PBKDF2, iterations = 600_000, memoryMib = 0, parallelism = 0).describe(res),
        )
    }
}
