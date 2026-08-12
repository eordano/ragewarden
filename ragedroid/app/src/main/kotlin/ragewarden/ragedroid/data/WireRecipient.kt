package ragewarden.ragedroid.data

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator

object UnsignedByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = listSerialDescriptor<Int>()

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeStructure(descriptor) {
            value.forEachIndexed { i, b ->
                encodeIntElement(descriptor, i, b.toInt() and 0xFF)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        val ints = decoder.decodeStructure(descriptor) {
            val list = mutableListOf<Byte>()
            while (true) {
                val idx = decodeElementIndex(descriptor)
                if (idx == CompositeDecoder.DECODE_DONE) break
                val v = decodeIntElement(descriptor, idx)
                require(v in 0..255) { "byte out of range: $v" }
                list.add(v.toByte())
            }
            list
        }
        return ints.toByteArray()
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("type")
sealed class WireRecipient {

    @Serializable
    @kotlinx.serialization.SerialName("x25519")
    data class X25519(
        @Serializable(with = UnsignedByteArraySerializer::class) val public_key: ByteArray,
    ) : WireRecipient() {
        override fun equals(other: Any?): Boolean =
            other is X25519 && public_key.contentEquals(other.public_key)
        override fun hashCode(): Int = public_key.contentHashCode()
    }

    @Serializable
    @kotlinx.serialization.SerialName("yubi_key_piv")
    data class YubiKeyPiv(
        @Serializable(with = UnsignedByteArraySerializer::class) val public_key: ByteArray,
        val serial: Long,
        val slot: Int,
    ) : WireRecipient() {
        override fun equals(other: Any?): Boolean = other is YubiKeyPiv &&
            public_key.contentEquals(other.public_key) && serial == other.serial && slot == other.slot
        override fun hashCode(): Int = 31 * (31 * public_key.contentHashCode() + serial.hashCode()) + slot
    }

    @Serializable
    @kotlinx.serialization.SerialName("fido2_hmac_secret")
    data class Fido2HmacSecret(
        @Serializable(with = UnsignedByteArraySerializer::class) val credential_id: ByteArray,
        @Serializable(with = UnsignedByteArraySerializer::class) val salt: ByteArray,
        val rp_id: String,
    ) : WireRecipient() {
        override fun equals(other: Any?): Boolean = other is Fido2HmacSecret &&
            credential_id.contentEquals(other.credential_id) &&
            salt.contentEquals(other.salt) && rp_id == other.rp_id
        override fun hashCode(): Int =
            31 * (31 * credential_id.contentHashCode() + salt.contentHashCode()) + rp_id.hashCode()
    }

    @Serializable
    @kotlinx.serialization.SerialName("passkey_prf")
    data class PasskeyPrf(
        @Serializable(with = UnsignedByteArraySerializer::class) val credential_id: ByteArray,
        @Serializable(with = UnsignedByteArraySerializer::class) val salt: ByteArray,
        val rp_id: String,
        val label: String,
    ) : WireRecipient() {
        override fun equals(other: Any?): Boolean = other is PasskeyPrf &&
            credential_id.contentEquals(other.credential_id) &&
            salt.contentEquals(other.salt) && rp_id == other.rp_id && label == other.label
        override fun hashCode(): Int = 31 * (31 * (31 *
            credential_id.contentHashCode() + salt.contentHashCode()) + rp_id.hashCode()) + label.hashCode()
    }

    @Serializable
    @kotlinx.serialization.SerialName("android_keystore")
    data class AndroidKeystore(
        @Serializable(with = UnsignedByteArraySerializer::class) val public_key: ByteArray,
        val key_handle: String,
    ) : WireRecipient() {
        override fun equals(other: Any?): Boolean = other is AndroidKeystore &&
            public_key.contentEquals(other.public_key) && key_handle == other.key_handle
        override fun hashCode(): Int = 31 * public_key.contentHashCode() + key_handle.hashCode()
    }

    @Serializable
    @kotlinx.serialization.SerialName("software_passphrase")
    data class SoftwarePassphrase(val armored_pubkey: String) : WireRecipient()
}

@Serializable
data class WirePrfInput(
    val rp_id: String,
    @Serializable(with = UnsignedByteArraySerializer::class) val salt: ByteArray,
    @Serializable(with = UnsignedByteArraySerializer::class) val prf_output: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is WirePrfInput &&
        rp_id == other.rp_id && salt.contentEquals(other.salt) && prf_output.contentEquals(other.prf_output)
    override fun hashCode(): Int =
        31 * (31 * rp_id.hashCode() + salt.contentHashCode()) + prf_output.contentHashCode()
}

val WireJson: Json = Json {
    classDiscriminator = "type"
    encodeDefaults = true
    ignoreUnknownKeys = true
}

val WireRecipientListSerializer: KSerializer<List<WireRecipient>> =
    ListSerializer(WireRecipient.serializer())

val WirePrfInputListSerializer: KSerializer<List<WirePrfInput>> =
    ListSerializer(WirePrfInput.serializer())
