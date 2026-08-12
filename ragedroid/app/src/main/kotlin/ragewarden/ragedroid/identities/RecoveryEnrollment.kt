package ragewarden.ragedroid.identities

import ragewarden.ragedroid.data.GeneratedRecovery
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind
import java.util.UUID

fun enrollRecovery(
    generated: GeneratedRecovery,
    displayName: String = "Paper recovery",
): StoredRecipient {
    val now = System.currentTimeMillis()
    return StoredRecipient(
        id = UUID.randomUUID().toString(),
        kind = RecipientKind.Recovery,
        displayName = displayName,
        createdAt = now,
        lastUsedAt = now,
        defaultEncrypt = true,
        recoveryArmoredPubkey = generated.armoredPubkey,
    )
}
