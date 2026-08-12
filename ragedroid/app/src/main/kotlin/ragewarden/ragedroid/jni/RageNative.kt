package ragewarden.ragedroid.jni

import ragewarden.ragedroid.identities.KotlinIdentity

object RageNative {
    init {
        System.loadLibrary("ragedroid_jni")
    }

    @JvmStatic
    external fun initTls(context: android.content.Context)

    @JvmStatic
    external fun smoke(): String

    @JvmStatic
    external fun encrypt(plaintext: ByteArray, recipientPubkey: ByteArray): ByteArray

    @JvmStatic
    external fun encryptToRecipients(
        plaintext: ByteArray,
        recipientsJson: ByteArray,
        prfInputsJson: ByteArray,
    ): ByteArray

    /**
     * The canonical recipient-selection policy (`ragewarden_core::policy`),
     * shared with rageterm and ragemanifest. Do not reimplement the selection
     * in Kotlin -- three separate filters is what made items written on one
     * client cryptographically unopenable on another.
     *
     * [registryJson] and [localJson] are `registry::WireDocument` JSON;
     * [localPrfIdsJson] is a JSON array of registry ids whose authenticator
     * this device can evaluate during a wrap. Returns `policy::Selection` JSON:
     * `{"recipients": [...], "skipped": [{"id","kind","reason"}]}`.
     */
    @JvmStatic
    external fun selectEncryptRecipients(
        registryJson: ByteArray,
        localJson: ByteArray,
        localPrfIdsJson: ByteArray,
    ): ByteArray

    @JvmStatic
    external fun decryptWithSoftwareSecret(blob: ByteArray, armoredSecret: String): ByteArray

    @JvmStatic
    external fun generateSoftwareIdentity(): String

    @JvmStatic
    external fun pubkeyFromArmoredSecret(armoredSecret: String): ByteArray

    @JvmStatic
    external fun totpGenerate(uriOrSecret: String): String

    @JvmStatic
    external fun register(
        serverUrl: String,
        email: String,
        password: String,
        name: String,
        kdfIterations: Int,
    ): ByteArray

    @JvmStatic
    external fun login(
        serverUrl: String,
        email: String,
        password: String,
        deviceName: String,
    ): ByteArray

    @JvmStatic
    external fun fetchVault(sessionBlob: ByteArray): ByteArray

    @JvmStatic
    external fun extractRageBlob(sessionBlob: ByteArray, cipherJson: String): ByteArray?

    @JvmStatic
    external fun buildRageCipher(
        sessionBlob: ByteArray,
        name: String,
        armoredBlob: String,
    ): ByteArray

    @JvmStatic
    external fun buildRageCipherInFolder(
        sessionBlob: ByteArray,
        name: String,
        armoredBlob: String,
        folderId: String?,
    ): ByteArray

    @JvmStatic
    external fun buildMetaCipher(
        sessionBlob: ByteArray,
        name: String,
        notes: String,
    ): ByteArray

    @JvmStatic
    external fun createCipher(sessionBlob: ByteArray, cipherInJson: ByteArray): ByteArray

    @JvmStatic
    external fun updateCipher(
        sessionBlob: ByteArray,
        cipherId: String,
        cipherInJson: ByteArray,
    ): ByteArray

    @JvmStatic
    external fun decryptWithIdentities(
        blob: ByteArray,
        identities: Array<KotlinIdentity>,
    ): ByteArray

    @JvmStatic
    external fun unwrapStanza(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
        secret: ByteArray,
    ): ByteArray

    @JvmStatic
    external fun x25519Diffie(privateKey: ByteArray, publicKey: ByteArray): ByteArray

    @JvmStatic
    external fun x25519PublicFromPrivate(privateKey: ByteArray): ByteArray

    @JvmStatic
    external fun generateRecoveryMnemonic(): ByteArray

    @JvmStatic
    external fun recoveryFromPhrase(phrase: String): ByteArray

    @JvmStatic
    external fun listFolders(sessionBlob: ByteArray): ByteArray

    @JvmStatic
    external fun createFolder(sessionBlob: ByteArray, name: String): ByteArray

    @JvmStatic
    external fun updateFolder(sessionBlob: ByteArray, folderId: String, name: String): ByteArray

    @JvmStatic
    external fun deleteFolder(sessionBlob: ByteArray, folderId: String): ByteArray

    @JvmStatic
    external fun deleteCipher(sessionBlob: ByteArray, cipherId: String): ByteArray
}

data class TotpCode(val code: String, val secondsRemaining: Int, val period: Int)

fun generateTotp(uriOrSecret: String): TotpCode {
    val parts = RageNative.totpGenerate(uriOrSecret).split(' ')
    check(parts.size == 3) { "totpGenerate returned malformed string" }
    return TotpCode(parts[0], parts[1].toInt(), parts[2].toInt())
}
