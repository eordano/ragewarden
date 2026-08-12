package ragewarden.ragedroid.identities

import ragewarden.ragedroid.BuildConfig

/**
 * The single gate for every simulated-hardware code path in the app.
 *
 * Two independent conditions must hold before any mock identity can exist:
 *
 *  1. `BuildConfig.MOCK_HARDWARE_ALLOWED` -- a compile-time constant that is
 *     `true` only for the `debug` build type. `release` and `benchmark` compile
 *     it to `false`, so `allowedByBuild` folds to a constant `false` and the
 *     runtime probe below is dead code in a shipped APK. A runtime-only gate
 *     (the previous `System.getenv`/`System.getProperty` pair) was not enough:
 *     `System.setProperty` is callable from any code running in-process, and
 *     with `isMinifyEnabled = false` nothing strips the mock constructors.
 *  2. `RAGEWARDEN_MOCK_HARDWARE=1` in the environment or as a JVM system
 *     property -- so even a debug build does not silently mock.
 *
 * Anything a mock produces must be *visibly* labelled everywhere it surfaces,
 * and must never leave the device. See [LABEL_PREFIX], `StoredRecipient.mock`,
 * and the unconditional mock filter in
 * `BitwardenVaultRepository.pushRecipientRegistry`.
 */
object MockHardware {
    const val ENV_VAR: String = "RAGEWARDEN_MOCK_HARDWARE"

    /** Prefix stamped onto every user-visible label that came from a mock. */
    const val LABEL_PREFIX: String = "⚠ MOCK -- "

    /** Compile-time: `false` in every non-debug build type. */
    val allowedByBuild: Boolean get() = BuildConfig.MOCK_HARDWARE_ALLOWED

    fun enabled(): Boolean =
        allowedByBuild &&
            (System.getenv(ENV_VAR) == "1" || System.getProperty(ENV_VAR) == "1")

    fun requireEnabled(what: String) {
        check(enabled()) {
            "$what requires a debug build with $ENV_VAR=1 " +
                "(allowedByBuild=$allowedByBuild). Mock hardware is compiled out of release builds."
        }
    }

    /** Stamps [label] so a mock can never be mistaken for a real authenticator. */
    fun label(label: String, isMock: Boolean): String =
        if (isMock) LABEL_PREFIX + label else label
}
