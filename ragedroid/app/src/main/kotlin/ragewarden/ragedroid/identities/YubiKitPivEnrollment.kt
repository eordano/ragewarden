package ragewarden.ragedroid.identities

import android.util.Log
import androidx.fragment.app.FragmentActivity
import com.yubico.yubikit.core.keys.EllipticCurveValues
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
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

/** A PIV slot's curve: P-256 (any PIV YubiKey; age-plugin-yubikey's format and rageterm's default) or X25519 (firmware 5.7+). */
enum class PivCurve { P256, X25519 }

suspend fun enrollYubiKeyPiv(
    activity: FragmentActivity,
    slot: Slot = Slot.AUTHENTICATION,
    pin: CharArray,
    displayName: String? = null,
    curve: PivCurve = PivCurve.P256,
): Pair<StoredRecipient, YubiKeyPivIdentity> {
    val device = YubiKitTransport.awaitYubiKey(activity)
    return YubiKitTransport.withSmartCard(device) { connection ->
        withContext(Dispatchers.IO) { enrollOnCard(connection, slot, pin, displayName, curve, activity) }
    }
}

/**
 * Generates the slot's key with `TouchPolicy.ALWAYS`, then reads the policy
 * back ([SlotTouch]) and refuses the slot if the card reports anything weaker:
 * the recipient is not created. A card that cannot report it (firmware before
 * 5.3) is accepted on the policy just requested, and logged.
 */
internal fun enrollOnCard(
    connection: SmartCardConnection,
    slot: Slot,
    pin: CharArray,
    displayName: String?,
    curve: PivCurve,
    activity: FragmentActivity?,
): Pair<StoredRecipient, YubiKeyPivIdentity> {
    val piv = PivSession(connection)
    piv.verifyPin(pin)
    val pubBytes = when (curve) {
        PivCurve.P256 -> extractP256Compressed(piv.generateKey(slot, KeyType.ECCP256, PinPolicy.ONCE, TouchPolicy.ALWAYS))
        PivCurve.X25519 -> {
            val pubValues = try {
                piv.generateKey(slot, KeyType.X25519, PinPolicy.ONCE, TouchPolicy.ALWAYS)
            } catch (t: Throwable) {
                throw YubiKeyX25519UnsupportedException(
                    "YubiKey firmware doesn't support X25519; need 5.7+",
                    t,
                )
            }
            extractX25519Pub32FromValues(pubValues)
        }
    }
    val serial = piv.serialNumber
    val name = displayName ?: "YubiKey #$serial"
    when (val touch = SlotTouch.read(piv, slot)) {
        SlotTouch.Always -> Unit
        is SlotTouch.Weaker -> throw PivTouchPolicyException(name, slot, touch.policy)
        SlotTouch.Unreadable -> Log.w(
            "YubiKitPivEnrollment",
            "$name cannot report the touch policy of slot ${slot.value} (no GET METADATA before firmware 5.3)",
        )
    }
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
    return recipient to identity
}

internal fun extractP256Compressed(values: PublicKeyValues): ByteArray {
    val pk = values.toPublicKey() as? java.security.interfaces.ECPublicKey
        ?: error("YubiKey returned a non-EC public key (${values::class.simpleName}) for a P-256 slot")
    return P256.compress(pk)
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
