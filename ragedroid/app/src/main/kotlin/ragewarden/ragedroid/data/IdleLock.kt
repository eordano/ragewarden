package ragewarden.ragedroid.data

class IdleLock(private val timeoutMs: () -> Long, private val now: () -> Long = System::currentTimeMillis) {
    @Volatile
    private var lastInteraction: Long = now()

    fun touch() {
        lastInteraction = now()
    }

    fun expired(): Boolean {
        val limit = timeoutMs()
        return limit > 0 && now() - lastInteraction >= limit
    }
}
