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
    external fun selfTestPanic(): Int

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

    /** A fresh age X25519 secret key in its text form; [pubkeyFromArmoredSecret] gives its public key. */
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
    external fun loginWithDevice(
        serverUrl: String,
        email: String,
        password: String,
        deviceName: String,
        deviceId: String,
        kdfPinJson: String?,
        allowLegacyKdf: Boolean,
    ): ByteArray

    /** New access/refresh tokens for [sessionBlob]; everything else is kept. */
    @JvmStatic
    external fun refreshSession(sessionBlob: ByteArray): ByteArray

    /** Raises the account's KDF to the current default server-side; returns the new session. */
    @JvmStatic
    external fun upgradeKdf(sessionBlob: ByteArray, password: String, deviceName: String): ByteArray

    /** Unlocked session blob, or an empty array when [password] is wrong. */
    @JvmStatic
    external fun unlockSession(lockedSessionBlob: ByteArray, password: String): ByteArray

    @JvmStatic
    external fun fetchVaultRaw(sessionBlob: ByteArray): ByteArray

    @JvmStatic
    external fun decryptVault(sessionBlob: ByteArray, rawVault: ByteArray): ByteArray

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

    /** [unwrapStanza] that also knows the recipient's public key, which the v2 stanzas bind into their HKDF salt. */
    @JvmStatic
    external fun unwrapStanzaForRecipient(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
        secret: ByteArray,
        recipientPublicKey: ByteArray,
    ): ByteArray

    /** How many PRF stanzas in [armored] still use the legacy per-recipient salt. */
    @JvmStatic
    external fun legacyPrfWraps(armored: String): Int

    @JvmStatic
    external fun generatePassword(length: Int, lowercase: Boolean, uppercase: Boolean, digits: Boolean, symbols: Boolean): String

    @JvmStatic
    external fun generatePassphrase(words: Int, separator: String): String

    @JvmStatic
    external fun buildCipher(
        sessionBlob: ByteArray,
        draftJson: ByteArray,
        armoredBlob: String?,
    ): ByteArray

    @JvmStatic
    external fun updateCipherPreserving(
        sessionBlob: ByteArray,
        cipherId: String,
        armoredBlob: String?,
        editJson: ByteArray,
    ): ByteArray

    @JvmStatic
    external fun setFolder(
        sessionBlob: ByteArray,
        cipherId: String,
        folderId: String?,
    ): ByteArray

    /** The plaintext a rage blob seals for [fieldsJson] (field name -> value):
     *  the bare value for the item type's primary field alone, a v2 field map
     *  otherwise. Encrypt the result as the item's rage blob. */
    @JvmStatic
    external fun sealProtectedFields(cipherType: Int, fieldsJson: ByteArray): ByteArray

    /** One field out of a decrypted rage payload; "" is the primary field. */
    @JvmStatic
    external fun protectedField(cipherType: Int, plaintext: ByteArray, field: String): ByteArray

    /** JSON array of the fields the item's rage blob holds; no tap needed. */
    @JvmStatic
    external fun protectedFieldNames(sessionBlob: ByteArray, cipherJson: String): ByteArray

    /** An unprotected field's plaintext, or null when the item has none. */
    @JvmStatic
    external fun outerField(sessionBlob: ByteArray, cipherJson: String, field: String): ByteArray?

    @JvmStatic
    external fun historyRecord(
        sessionBlob: ByteArray,
        cipherId: String,
        priorPayloadArmored: String,
        recipientsSummaryJson: ByteArray,
        deleted: Boolean,
    ): ByteArray

    @JvmStatic
    external fun historyLoad(sessionBlob: ByteArray, cipherId: String): ByteArray

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
