package ragewarden.ragedroid.ui

import android.app.Activity
import android.view.WindowManager

/**
 * Marks this Activity's window as `FLAG_SECURE`.
 *
 * Every surface that can put a decrypted secret on screen lives in one of two
 * Activities -- `MainActivity` (which hosts `ItemDetailScreen`'s
 * `RevealedPasswordCard`, the note/card/SSH bodies, the paper-recovery word grid,
 * and the edit screen's pre-filled password field) and `AutofillAuthActivity`
 * (which renders the consent sheet for a use that is about to deliver plaintext).
 * `RevealedPasswordCard` holds plaintext on screen for
 * `REVEAL_AUTO_CLEAR_SECS` = 8 seconds; without this flag those 8 seconds are
 * screenshot-able, screen-recordable, capturable by any app holding
 * `MediaProjection`, and thumbnailed into the Recents switcher, where the
 * thumbnail outlives the reveal.
 *
 * Applied at the window level rather than per-composable on purpose. Compose has
 * no per-view FLAG_SECURE: the flag belongs to the window, so toggling it around
 * an individual reveal would mean flipping window flags mid-interaction (which
 * recreates the surface and flickers) and would still leave the Recents
 * thumbnail unprotected, because that snapshot is taken when the Activity stops,
 * not while the secret is visible.
 *
 * The cost is real and deliberate: no screenshots of the app at all, and the app
 * will not render on non-secure external displays or in some screen-sharing
 * flows. For a password vault that is the correct trade. There is intentionally
 * no debug-build escape hatch -- a flag that is off in the build you test with is
 * a flag whose breakage you discover in release.
 */
fun Activity.secureWindow() {
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
    )
}
