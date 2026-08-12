package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity
import com.yubico.yubikit.core.keys.EllipticCurveValues
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind
import java.math.BigInteger
import java.security.interfaces.XECPublicKey
import java.util.UUID

class YubiKeyX25519UnsupportedException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

suspend fun enrollYubiKeyPivX25519(
    activity: FragmentActivity,
    slot: Slot = Slot.AUTHENTICATION,
    pin: CharArray,
    displayName: String? = null,
): Pair<StoredRecipient, YubiKeyPivIdentity> {
    val device = YubiKitTransport.awaitYubiKey(activity)
    return YubiKitTransport.withSmartCard(device) { connection ->
        withContext(Dispatchers.IO) {
            val piv = PivSession(connection)
            piv.verifyPin(pin)
            val pubValues = try {
                piv.generateKeyValues(slot, KeyType.X25519, PinPolicy.ONCE, TouchPolicy.ALWAYS)
            } catch (t: Throwable) {
                throw YubiKeyX25519UnsupportedException(
                    "YubiKey firmware doesn't support X25519; need 5.7+",
                    t,
                )
            }
            val pubBytes = extractX25519Pub32FromValues(pubValues)
            val serial = piv.serialNumber
            val name = displayName ?: "YubiKey #$serial"
            val now = System.currentTimeMillis()
            val recipient = StoredRecipient(
                id = UUID.randomUUID().toString(),
                kind = RecipientKind.YubiKey,
                displayName = name,
                createdAt = now,
                lastUsedAt = now,
                defaultEncrypt = true,
                pivPubkey = pubBytes,
                pivSerial = serial,
                pivSlot = slot.value.toByte(),
            )
            val identity = YubiKeyPivIdentity(
                mockSecret = null,
                expectedPublicKey = pubBytes,
                serial = serial.toUInt(),
                slot = slot.value.toUByte(),
                activity = activity,
                pinProvider = { pin.copyOf() },
            )
            recipient to identity
        }
    }
}

internal fun extractX25519Pub32FromValues(values: PublicKeyValues): ByteArray {
    if (values is PublicKeyValues.Cv25519 && values.curveParams == EllipticCurveValues.X25519) {
        val raw = values.bytes
        if (raw.size == 32) return raw.copyOf()
        throw YubiKeyX25519UnsupportedException(
            "YubiKey returned X25519 public key with wrong size (${raw.size}); need 32 bytes",
        )
    }
    val pk = runCatching { values.toPublicKey() }.getOrNull()
    if (pk is XECPublicKey) {
        return bigIntegerToLittleEndian32Local(pk.u)
    }
    throw YubiKeyX25519UnsupportedException(
        "YubiKey returned a non-X25519 public key (${values::class.simpleName}); firmware 5.7+ with X25519 PIV slot required",
    )
}

private fun bigIntegerToLittleEndian32Local(bi: BigInteger): ByteArray {
    val be = bi.toByteArray()
    val unsigned = if (be.size == 33 && be[0] == 0.toByte()) be.copyOfRange(1, 33) else be
    val padded = if (unsigned.size < 32) ByteArray(32 - unsigned.size) + unsigned else unsigned
    return padded.reversedArray()
}
