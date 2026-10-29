package ragewarden.ragedroid.data

/** How the account's master password is stretched, as the session recorded it at login. */
data class KdfSummary(
    val type: Int,
    val iterations: Int,
    val memoryMib: Int,
    val parallelism: Int,
) {
    val isArgon2id: Boolean get() = type == ARGON2ID

    companion object {
        const val PBKDF2 = 0
        const val ARGON2ID = 1
    }
}
