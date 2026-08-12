/*
 * Checked-in defaults. `build.mjs emitGlueBuildFlags()` overwrites this file in
 * dist/ with the flags the build was actually invoked with; this copy is what
 * runs when the popup is served straight out of ext/. It must therefore stay
 * export-compatible with the generated one -- a missing export here is an import
 * error in vault.js, not a fallback.
 *
 * Every value below is the safe one. Nothing turns a flag on except build.mjs.
 */
const DEFAULTS = Object.freeze({
    profile: 'release',
    allowMockTap: false,
    forceMockTap: false,
    testHooks: false,
    vmMode: false,
    vmServerUrl: null,
});

export const BUILD_FLAGS = DEFAULTS;

export function buildProfile() {
    return BUILD_FLAGS.profile;
}

export function mockTapAllowed() {
    return BUILD_FLAGS.allowMockTap === true;
}

export function testHooksEnabled() {
    return BUILD_FLAGS.testHooks === true;
}

export function vmModeEnabled() {
    return BUILD_FLAGS.vmMode === true;
}

export function vmServerUrl() {
    return BUILD_FLAGS.vmServerUrl || null;
}

export function assertReleaseSafe() {
    if (BUILD_FLAGS.profile === 'release'
        && (BUILD_FLAGS.allowMockTap || BUILD_FLAGS.forceMockTap
            || BUILD_FLAGS.testHooks || BUILD_FLAGS.vmMode)) {
        throw new Error(
            'build-flags.js: release profile must not enable '
            + 'allowMockTap/forceMockTap/testHooks/vmMode',
        );
    }
    if (BUILD_FLAGS.vmMode && !BUILD_FLAGS.allowMockTap) {
        throw new Error('build-flags.js: vmMode without allowMockTap is incoherent');
    }
}
