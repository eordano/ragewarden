package ragewarden.ragedroid.identities

/**
 * The WebAuthn relying party passkeys are created for. Credential Manager only
 * creates or asserts a passkey for an RP whose `/.well-known/assetlinks.json`
 * names this app and its signing certificate; `globals/ragedroid.nix` in the
 * fleet repo holds the same RP id, package and certificate, and vpnhead serves
 * the file.
 *
 * A passkey asserts only with the RP it was created for, so every stored
 * recipient keeps its own RP id. Entries written before the RP id was stored
 * were made for [LEGACY_ID].
 */
object PasskeyRp {
    const val ID = "ragewarden.decent.foundation"
    const val LEGACY_ID = "ragewarden.local"
}
