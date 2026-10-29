package ragewarden.ragedroid.ui

import android.content.res.Resources
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.KdfSummary

/** "Argon2id, 64 MiB, 3 passes" or "PBKDF2-SHA256, 600 000 rounds": the account's real stretching. */
fun KdfSummary.describe(res: Resources): String = if (isArgon2id) {
    res.getString(R.string.kdf_argon2id, memoryMib, iterations, parallelism)
} else {
    res.getString(R.string.kdf_pbkdf2, groupDigits(iterations))
}

internal fun groupDigits(n: Int): String = n.toString().reversed().chunked(3).joinToString(" ").reversed()
