package ragewarden.ragedroid.ime

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import ragewarden.ragedroid.model.VaultItem

data class ImeSession(val packageName: String, val fieldId: Int)

internal interface ImeAuthBroker {
    suspend fun authorize(item: VaultItem, session: ImeSession): ByteArray?

    suspend fun awaitReturn(session: ImeSession): Boolean
}

internal object NoImeAuth : ImeAuthBroker {
    override suspend fun authorize(item: VaultItem, session: ImeSession): ByteArray? = null

    override suspend fun awaitReturn(session: ImeSession): Boolean = false
}

/**
 * One-shot hand-off from [ImeAuthActivity] back to the keyboard. A nonce names
 * each request, so a sheet left over from an earlier request cannot answer a
 * later one; whoever completes a nonce that is no longer pending gets `false`
 * and must zero what it holds.
 */
internal object ImeAuthChannel {
    private val pending = ConcurrentHashMap<String, CompletableDeferred<ByteArray?>>()
    private val random = SecureRandom()

    fun open(): Pair<String, CompletableDeferred<ByteArray?>> {
        val bytes = ByteArray(16).also(random::nextBytes)
        val nonce = bytes.joinToString("") { "%02x".format(it) }
        val result = CompletableDeferred<ByteArray?>()
        pending[nonce] = result
        return nonce to result
    }

    fun isPending(nonce: String): Boolean = pending.containsKey(nonce)

    fun complete(nonce: String, plaintext: ByteArray?): Boolean =
        pending.remove(nonce)?.complete(plaintext) ?: false

    fun close(nonce: String) {
        pending.remove(nonce)?.cancel()
    }
}
