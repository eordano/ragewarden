package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind

/**
 * The set of identities a given surface can actually drive right now, plus an
 * honest account of everything it could not.
 *
 * [skipped] is load-bearing, not diagnostics decoration: the prompt must be able
 * to say "your YubiKey is enrolled but this keyboard cannot reach it" instead of
 * silently handing age a shorter list and letting it fall through to whatever
 * software recipient is left.
 */
data class IdentitySet(
    val identities: List<KotlinIdentity>,
    val skipped: List<SkippedRecipient>,
) {
    /** At least one identity costs a deliberate physical action. */
    val hardwareTapRequired: Boolean get() = identities.any { it.requiresPhysicalPresence }

    /**
     * A biometric/device-credential prompt must succeed before decrypt, because
     * an auth-bound Keystore key is in the list and its 30-second window has to
     * be fresh.
     */
    val biometricRequired: Boolean get() =
        identities.any { it is AndroidKeystoreIdentity && it.authBound && !it.perUse }

    val containsMock: Boolean get() = identities.any { it.isMock }

    /** Label for the tap prompt: prefer the identity that costs a real action. */
    val promptLabel: String get() =
        identities.firstOrNull { it.requiresPhysicalPresence }?.displayLabel
            ?: identities.firstOrNull()?.displayLabel
            ?: "no usable recipient"

    val transportHint: String? get() =
        identities.firstOrNull { it.requiresPhysicalPresence }?.transportHint

    val isEmpty: Boolean get() = identities.isEmpty()
}

/**
 * Turns stored recipients into live identities.
 *
 * Before this existed, `localIdentities` returned *only* `AndroidKeystoreIdentity`
 * and its KDoc claimed the UI orchestrated the hardware kinds separately -- no UI
 * did, so `YubiKeyPivIdentity`, `Fido2HmacIdentity` and `PasskeyIdentity` were
 * constructed at enrolment and thrown away, and the only enforceable second
 * factor in the product was a TEE key behind a 30-second biometric window.
 *
 * [resolve] is the one place that decides what a surface can do. It takes the
 * [activity] explicitly because a YubiKey needs an Activity to start NFC
 * discovery and Credential Manager needs one to show its sheet; passing null is
 * how a non-Activity surface (the IME) declares its limits and gets told, per
 * recipient, what it cannot do.
 */
object IdentityResolver {

    /**
     * @param onlyRecipientIds when non-null, restrict to these recipient ids --
     *   used by the multi-identity picker so "unlock with *this* key" means it.
     * @param pinProvider suspends to collect a PIV PIN. Null means no PIN can be
     *   collected on this surface; YubiKey recipients are then reported as
     *   skipped rather than being handed an identity that returns null and
     *   silently defers to the next recipient.
     */
    fun resolve(
        recipientStore: RecipientStore,
        accountId: String,
        activity: FragmentActivity?,
        pinProvider: (suspend () -> CharArray)? = null,
        onlyRecipientIds: Set<String>? = null,
    ): IdentitySet {
        if (accountId.isBlank()) {
            return IdentitySet(emptyList(), emptyList())
        }
        val identities = mutableListOf<KotlinIdentity>()
        val skipped = mutableListOf<SkippedRecipient>()

        for (stored in recipientStore.forAccount(accountId)) {
            if (onlyRecipientIds != null && stored.id !in onlyRecipientIds) continue
            when (stored.kind) {
                RecipientKind.StrongBox -> addKeystore(stored, activity, identities, skipped)
                RecipientKind.YubiKey -> addYubiKey(stored, activity, pinProvider, identities, skipped)
                // Both passkey kinds land in the same builder. It already emits
                // whichever identity families the stored material supports, and
                // each one only claims stanzas whose credential id matches -- so
                // a PasskeyPrf recipient yields the `webauthn-prf-v1` identity
                // and nothing else. Routing it to a Fido2-only path instead
                // would reintroduce the mistag this kind was added to fix.
                RecipientKind.Fido2,
                RecipientKind.PasskeyPrf,
                -> addFido2(stored, activity, identities, skipped)
                RecipientKind.Recovery -> skipped += SkippedRecipient(
                    recipientId = stored.id,
                    label = stored.displayName,
                    // Deliberate: the paper identity is the software fallback of
                    // last resort. It must never be silently available during a
                    // routine reveal, or every "hardware tap" becomes optional.
                    reason = "Paper recovery is only usable through Settings -> Recover from phrase.",
                )
                RecipientKind.Software -> skipped += SkippedRecipient(
                    recipientId = stored.id,
                    label = stored.displayName,
                    reason = "Software-only recipient; not usable as a hardware factor.",
                )
            }
        }
        return IdentitySet(identities, skipped)
    }

    private fun addKeystore(
        stored: StoredRecipient,
        activity: FragmentActivity?,
        out: MutableList<KotlinIdentity>,
        skipped: MutableList<SkippedRecipient>,
    ) {
        val pub = stored.keystorePubkey
        val handle = stored.keystoreHandle
        if (pub == null || pub.size != KEYSTORE_PUBKEY_LEN || handle.isNullOrBlank()) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "Legacy Keystore entry (${pub?.size ?: 0}-byte pubkey); re-enrol this device.",
            )
            return
        }
        // `keystoreAuthBound` is null for recipients enrolled before the flag
        // existed. Guessing "not auth-bound" would drop the biometric prompt that
        // the previous `anyBiometricRequired` (any StrongBox recipient => prompt)
        // always raised -- a silent weakening on upgrade. Guessing "auth-bound"
        // unconditionally would instead block decrypt on a phone with no screen
        // lock, where the key is almost certainly *not* auth-bound because
        // `enrollKeystoreIdentity` falls back to a non-auth-bound key there.
        // So: unknown => auth-bound iff this device can actually prompt.
        val authBound = stored.keystoreAuthBound
            ?: (activity != null && BiometricGate.isEnrolled(activity))
        out += AndroidKeystoreIdentity(
            mockKey = null,
            expectedPublicKey = pub,
            keyHandle = handle,
            label = stored.displayName,
            authBound = authBound,
            perUse = stored.keystorePerUse && android.os.Build.VERSION.SDK_INT >= 35,
            activity = activity,
        )
    }

    private fun addYubiKey(
        stored: StoredRecipient,
        activity: FragmentActivity?,
        pinProvider: (suspend () -> CharArray)?,
        out: MutableList<KotlinIdentity>,
        skipped: MutableList<SkippedRecipient>,
    ) {
        val pub = stored.pivPubkey
        if (pub == null || (pub.size != PIV_X25519_LEN && !P256.isCompressedPoint(pub))) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "Stored PIV public key is ${pub?.size ?: 0} bytes; expected a 32-byte X25519 or 33-byte P-256 key.",
            )
            return
        }
        if (activity == null) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "This surface has no Activity, so no NFC/USB reader can be started. " +
                    "Open the item in Ragewarden.",
            )
            return
        }
        if (pinProvider == null) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "No PIV PIN prompt is available on this surface.",
            )
            return
        }
        out += YubiKeyPivIdentity(
            mockSecret = null,
            expectedPublicKey = pub,
            serial = (stored.pivSerial ?: 0).toUInt(),
            slot = (stored.pivSlot ?: 0.toByte()).toUByte(),
            label = stored.displayName,
            activity = activity,
            pinProvider = pinProvider,
        )
    }

    /**
     * Handles `RecipientKind.Fido2` AND `RecipientKind.PasskeyPrf`, which is
     * why the name is narrower than the job. Enrolment
     * (`PasskeyEnrollmentReal.enrollPasskeyWithPrf`) writes the `fido2*` fields
     * and `collectActiveRecipients` maps them to `WireRecipient.Fido2HmacSecret`,
     * i.e. `fido2-hmac` stanzas -- so [Fido2HmacIdentity] is what unwraps them.
     * The `passkey*` fields exist for `webauthn-prf-v1` blobs (nothing in this
     * app writes them today, but core emits that tag and other clients may).
     * Build whichever identities the stored material supports; each one only
     * claims stanzas whose credential id matches, so listing both is safe.
     */
    private fun addFido2(
        stored: StoredRecipient,
        activity: FragmentActivity?,
        out: MutableList<KotlinIdentity>,
        skipped: MutableList<SkippedRecipient>,
    ) {
        if (activity == null) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "Credential Manager needs an Activity; this surface has none. " +
                    "Open the item in Ragewarden.",
            )
            return
        }
        val unavailable = passkeyUnavailableReason()
        var added = false

        val fidoCred = stored.fido2CredentialId
        val fidoRp = stored.fido2RpId
        if (fidoCred != null && fidoCred.isNotEmpty() && !fidoRp.isNullOrBlank()) {
            out += Fido2HmacIdentity(
                mockHmacKey = null,
                credentialId = fidoCred,
                rpId = fidoRp,
                activity = activity,
                label = stored.displayName,
            )
            added = true
        }

        val pkCred = stored.passkeyCredentialId
        val pkRp = stored.passkeyRpId
        if (pkCred != null && pkCred.isNotEmpty() && !pkRp.isNullOrBlank()) {
            val identity = passkeyIdentityForUse(
                credentialId = pkCred,
                rpId = pkRp,
                label = stored.displayName,
                activity = activity,
            )
            if (identity != null) {
                out += identity
                added = true
            } else {
                skipped += SkippedRecipient(
                    stored.id,
                    stored.displayName,
                    unavailable ?: "This build cannot drive WebAuthn PRF passkeys.",
                )
            }
        }

        if (!added && skipped.none { it.recipientId == stored.id }) {
            skipped += SkippedRecipient(
                stored.id,
                stored.displayName,
                "Stored FIDO2 recipient has no credential id / rp id.",
            )
        }
    }

    private const val KEYSTORE_PUBKEY_LEN = 33
    private const val PIV_X25519_LEN = 32
}
