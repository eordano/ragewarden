/**
 * Host access is requested for the user's own server only, at the moment they
 * sign in, instead of "<all_urls>" at install time. Must be called synchronously
 * from the click handler: both Chromium and Firefox refuse a permission request
 * that is not inside a user gesture. Resolves true without a prompt when the
 * origin is already granted.
 */
export function requestServerPermission(serverUrl, api = permissionsApi()) {
    let origin;
    try {
        origin = new URL(serverUrl).origin;
    } catch {
        return Promise.reject(new Error(`not a server URL: ${serverUrl}`));
    }
    if (!api) return Promise.resolve(true);
    return Promise.resolve(api.request({ origins: [`${origin}/*`] })).then((granted) => {
        if (!granted) {
            throw new Error(`Ragewarden needs permission to reach ${origin} to talk to your server.`);
        }
        return true;
    });
}

/** The origin the session talks to, when this profile has not granted it. */
export async function missingServerOrigin(sessionBlob, api = permissionsApi()) {
    if (!sessionBlob || !api || !api.contains) return null;
    let origin;
    try {
        const s = typeof sessionBlob === 'string' ? JSON.parse(sessionBlob) : sessionBlob;
        origin = new URL(s.api_url).origin;
    } catch {
        return null;
    }
    const granted = await Promise.resolve(api.contains({ origins: [`${origin}/*`] }));
    return granted ? null : origin;
}

function permissionsApi() {
    if (typeof chrome !== 'undefined' && chrome.permissions && chrome.permissions.request) return chrome.permissions;
    if (typeof browser !== 'undefined' && browser.permissions && browser.permissions.request) return browser.permissions;
    return null;
}
