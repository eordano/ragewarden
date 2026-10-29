const SHARED_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'ac.kr', 'go.kr',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'com.ar', 'com.mx', 'com.co', 'com.pe', 'com.uy', 'com.ve', 'com.ec',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'co.za', 'org.za', 'gov.za', 'ac.za',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.tw', 'org.tw', 'com.hk', 'org.hk', 'com.sg', 'edu.sg', 'gov.sg',
    'com.my', 'com.ph', 'com.vn', 'co.th', 'co.id', 'co.il', 'org.il', 'ac.il',
    'com.tr', 'gov.tr', 'com.pl', 'com.ua', 'com.ru', 'com.es', 'com.pt', 'co.at', 'or.at',
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app',
    'herokuapp.com', 'web.app', 'firebaseapp.com', 'appspot.com', 'blogspot.com',
    'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'fly.dev', 'onrender.com',
    'glitch.me', 'repl.co', 'ngrok.io', 'ngrok.app', 'duckdns.org', 'ts.net',
]);

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function parseUrl(value) {
    const s = String(value || '').trim();
    if (!s) return null;
    try {
        return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    } catch {
        return null;
    }
}

export function originHost(originOrUrl) {
    const u = parseUrl(originOrUrl);
    return u ? u.hostname.toLowerCase().replace(/\.$/, '') : '';
}

function isSharedSuffix(host) {
    if (!host.includes('.')) return true;
    return SHARED_SUFFIXES.has(host);
}

export function siteMatchesOrigin(site, origin) {
    const stored = parseUrl(site);
    const page = parseUrl(origin);
    if (!stored || !page) return false;
    const storedHost = stored.hostname.toLowerCase().replace(/\.$/, '');
    const pageHost = page.hostname.toLowerCase().replace(/\.$/, '');
    if (!storedHost || !pageHost) return false;
    if (page.protocol !== 'https:' && !LOCAL_HOSTS.has(pageHost)
        && !(stored.protocol === 'http:' && /^http:\/\//i.test(String(site).trim()))) {
        return false;
    }
    if (stored.protocol === 'https:' && /^https:\/\//i.test(String(site).trim())
        && page.protocol !== 'https:') {
        return false;
    }
    if (pageHost === storedHost) return true;
    if (isSharedSuffix(storedHost)) return false;
    return pageHost.endsWith(`.${storedHost}`);
}

export function isInternalCipher(c) {
    if (!c) return false;
    if (c.internal === true) return true;
    const name = String(c.name || '');
    return /^__.+__/.test(name) || name === 'Ragewarden Recipients (do not edit)';
}

export function cipherDecryptable(c) {
    if (!c) return false;
    if (!c.rage) return true;
    return c.decryptable === true;
}

export function ciphersForOrigin(ciphers, origin) {
    const out = [];
    for (const c of ciphers || []) {
        if (!c || (c.kind && c.kind !== 'login')) continue;
        if (isInternalCipher(c) || !cipherDecryptable(c)) continue;
        if (!siteMatchesOrigin(c.site, origin)) continue;
        out.push({
            id: c.id,
            name: c.name,
            username: c.username || null,
            site: c.site || null,
            rage: !!c.rage,
        });
    }
    return out;
}
