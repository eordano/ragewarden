const { useState: useStateV, useEffect: useEffectV, useRef: useRefV } = React;

async function performBridgeAction(item, action) {
  const bridge = (typeof window !== 'undefined') && window.RagewardenVault;
  if (!bridge || !item) return null;
  try {
    if (action === 'reveal' && typeof bridge.revealPassword === 'function') {
      return await bridge.revealPassword(item.id, 'password');
    }
    if (action === 'copy' && typeof bridge.copyPassword === 'function') {
      return await bridge.copyPassword(item.id);
    }
    if (action === 'autofill' && typeof bridge.autofillPassword === 'function') {
      return await bridge.autofillPassword(item.id, item.site || '');
    }
  } catch (err) {
    throw err;
  }
  return null;
}

const FolderChip = ({ name, active, onClick }) => (
  <button onClick={onClick} style={{
    padding: '6px 12px', borderRadius: 999, border: '1px solid var(--color-border)',
    background: active ? 'var(--color-fg-emphasis)' : 'var(--color-surface-elevated)',
    color: active ? 'var(--color-background)' : 'var(--color-fg-primary)',
    fontFamily: 'var(--font-sans)', fontSize: 12.5, fontWeight: 500,
    cursor: 'pointer', whiteSpace: 'nowrap',
    transition: 'all var(--dur-fast) var(--ease-out)',
  }}>{name}</button>
);

const VaultRow = ({ item, onClick, chipStyle = 'pill' }) => {
  const initials = item.name.replace(/[^a-zA-Z]/g, '').slice(0, 2).toUpperCase() || 'XX';
  const kindGlyph = {
    card: 'creditCard', note: 'paper', identity: 'user', ssh: 'terminal',
  }[item.kind];
  // Not decryptable here: dimmed, badged, still clickable -- the click routes to
  // the explanation screen (App.openItem), never to a decrypt.
  const offDevice = isNotOnThisDevice(item);
  return (
    <div onClick={onClick} data-off-device={offDevice || undefined} style={{
      display: 'flex', alignItems: 'stretch', gap: 12,
      padding: '12px 16px',
      borderBottom: '1px solid var(--color-divider)',
      cursor: 'pointer', position: 'relative',
      opacity: offDevice ? 0.55 : 1,
      transition: 'background var(--dur-fast) var(--ease-out)',
    }}
    onMouseEnter={e => e.currentTarget.style.background = 'var(--color-tile)'}
    onMouseLeave={e => e.currentTarget.style.background = ''}>
      {chipStyle === 'rule' && item.rage && !offDevice && <RageChip style="rule"/>}
      <div style={{
        width: 36, height: 36, borderRadius: 8,
        background: item.rage ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
        border: '1px solid var(--color-border)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 13,
        color: item.rage ? 'var(--color-accent)' : 'var(--color-fg-secondary)',
        flexShrink: 0, alignSelf: 'center', letterSpacing: '-0.01em',
      }}>{kindGlyph ? <Icon name={kindGlyph} size={16}/> : initials}</div>
      <div style={{ flex: 1, minWidth: 0, alignSelf: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15.5,
            color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{item.name}</div>
          {item.favorite && <Icon name="star" size={12} style={{ color: 'var(--color-warning)' }}/>}
        </div>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{item.username}{item.site ? ' · ' + item.site : ''}</div>
      </div>
      {offDevice && (
        <div style={{ alignSelf: 'center' }}>
          <NotOnDeviceChip/>
        </div>
      )}
      {!offDevice && item.rage && chipStyle !== 'rule' && (
        <div style={{ alignSelf: 'center' }}>
          {chipStyle === 'icon' ? <RageChip style="icon"/> : <RageChip recipients={item.recipients}/>}
        </div>
      )}
      {!item.rage && (
        <div style={{ alignSelf: 'center', color: 'var(--color-fg-secondary)' }}>
          <Icon name="chevronRight" size={16}/>
        </div>
      )}
    </div>
  );
};

const VaultScreen = ({ onOpen, onAdd, onSettings, onSearch, onBulkProtect, chipStyle, density }) => {
  const [folder, setFolder] = useStateV('All');
  const folders = ['All', 'Work', 'Personal', 'Infrastructure'];
  const allItems = [
    ...VAULT,
    ...(typeof ITEMS_BY_KIND !== 'undefined' ? ITEMS_BY_KIND.map(i => ({
      ...i,
      username: i.kind === 'card' ? i.cardholder
              : i.kind === 'identity' ? i.fullName
              : i.kind === 'ssh' ? i.keyType
              : 'Secure note',
      site: '',
    })) : []),
  ].filter(it => !isInternalItem(it));
  const filtered = allItems.filter(it => {
    if (folder !== 'All' && it.folder !== folder) return false;
    return true;
  });
  const rageCount = allItems.filter(i => i.rage).length;
  // Protect candidates are the items a re-wrap could actually open: plain ones.
  // An undecryptable rage item cannot be decrypted here, so it is never counted
  // into (or targeted by) the Protect banner.
  const unprotectedCount = allItems.filter(i => !i.rage && i.decryptable !== false).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar
        large
        title="Vault"
        subtitle={`${allItems.length} items · ${rageCount} protected`}
        right={<>
          <IconBtn name="plus" onClick={onAdd} title="Add"/>
          <IconBtn name="settings" onClick={onSettings} title="Settings"/>
        </>}
      />

      <div style={{ padding: '4px 16px 10px' }}>
        <button onClick={onSearch} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          background: 'var(--color-surface-sunken)',
          border: 'none', borderRadius: 10, padding: '8px 12px',
          cursor: 'pointer', textAlign: 'left',
          fontFamily: 'var(--font-sans)', fontSize: 14, color: 'var(--color-fg-secondary)',
        }}>
          <Icon name="search" size={16} style={{ color: 'var(--color-fg-secondary)' }}/>
          <span style={{ flex: 1 }}>Search vault, recipients, notes</span>
          <span style={{ fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', opacity: 0.7 }}>Filter</span>
        </button>
      </div>

      <div style={{ display: 'flex', gap: 6, padding: '0 16px 12px', overflowX: 'auto' }}>
        {folders.map(f => <FolderChip key={f} name={f} active={folder === f} onClick={() => setFolder(f)}/>)}
      </div>

      {unprotectedCount > 0 && (
        <div style={{
          margin: '0 16px 10px', padding: '10px 14px',
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 10, display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 7, background: 'var(--color-tile)',
            color: 'var(--color-warning)', display: 'flex', alignItems: 'center',
            justifyContent: 'center', flexShrink: 0,
          }}>
            <Icon name="info" size={15}/>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <span style={{
              fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-primary)',
            }}>
              {unprotectedCount} item{unprotectedCount === 1 ? ' is' : 's are'} unprotected
            </span>
          </div>
          <button onClick={onBulkProtect} style={{
            background: 'var(--color-accent)', color: 'var(--color-background)',
            border: 'none', borderRadius: 6, padding: '5px 12px',
            fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
            cursor: 'pointer', whiteSpace: 'nowrap',
          }}>Protect all</button>
        </div>
      )}

      <div style={{ flex: 1, overflowY: 'auto', borderTop: '1px solid var(--color-divider)' }}>
        {filtered.length === 0 ? (
          <div style={{
            padding: '40px 24px', textAlign: 'center',
            fontFamily: 'var(--font-serif)', fontSize: 15, fontStyle: 'italic',
            color: 'var(--color-fg-secondary)',
          }}>No items match.</div>
        ) : filtered.map(it => <VaultRow key={it.id} item={it} onClick={() => onOpen(it)} chipStyle={chipStyle}/>)}

        <div style={{
          padding: '24px 24px 32px', textAlign: 'center',
          fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
          fontStyle: 'italic', lineHeight: 1.5,
        }}>
          Vault syncs through Bitwarden.<br/>
          Protected items stay opaque to the server.
        </div>
      </div>
    </div>
  );
};

const InlineTapReveal = ({ item, action, onComplete, onCancel }) => {
  const [phase, setPhase] = useStateV(action ? 'waiting' : 'choose');
  const [chosenAction, setChosenAction] = useStateV(action || null);
  const recipients = (item.recipients || []).map(rid => RECIPIENTS.find(r => r.id === rid)).filter(Boolean);
  const primary = recipients[0];

  useEffectV(() => {
    if (phase !== 'waiting') return;
    let cancelled = false;
    let connectTimer = null;
    let fallbackTimer = null;

    const bridgeAttempt = performBridgeAction(item, chosenAction);
    if (bridgeAttempt && typeof bridgeAttempt.then === 'function') {
      bridgeAttempt.then(plaintext => {
        if (cancelled) return;
        if (plaintext === null) {
          fallbackTimer = setTimeout(() => {
            if (cancelled) return;
            setPhase('connected');
            connectTimer = setTimeout(() => {
              if (!cancelled) onComplete(chosenAction, null);
            }, 700);
          }, 1800);
          return;
        }
        setPhase('connected');
        connectTimer = setTimeout(() => {
          if (!cancelled) onComplete(chosenAction, plaintext);
        }, 400);
      }, _err => {
        if (cancelled) return;
        onCancel?.();
      });
      return () => {
        cancelled = true;
        if (connectTimer) clearTimeout(connectTimer);
        if (fallbackTimer) clearTimeout(fallbackTimer);
      };
    }

    fallbackTimer = setTimeout(() => {
      if (cancelled) return;
      setPhase('connected');
      connectTimer = setTimeout(() => {
        if (!cancelled) onComplete(chosenAction, null);
      }, 700);
    }, 1800);
    return () => {
      cancelled = true;
      if (connectTimer) clearTimeout(connectTimer);
      if (fallbackTimer) clearTimeout(fallbackTimer);
    };
  }, [phase, chosenAction]);

  const isWaiting = phase === 'waiting';
  const isConnected = phase === 'connected';

  if (phase === 'choose') {
    const actions = [
      { id: 'autofill', icon: 'arrowRight', label: 'Autofill', desc: `Deliver to ${item.site || 'the active app'}. Plaintext never on screen.` },
      { id: 'copy',     icon: 'copy',       label: 'Copy to clipboard', desc: 'Plaintext goes only to the clipboard.' },
      { id: 'reveal',   icon: 'eye',        label: 'Reveal on screen', desc: 'Auto-hides after 10 seconds. Last-resort path.' },
    ];
    return (
      <div style={{
        background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
        borderRadius: 10, padding: '12px 12px 10px',
      }}>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
          letterSpacing: '0.06em', textTransform: 'uppercase',
          color: 'var(--color-fg-secondary)', padding: '0 4px 8px',
        }}>Pick an action -- tap will authorize that specific use</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {actions.map(a => (
            <button key={a.id} onClick={() => { setChosenAction(a.id); setPhase('waiting'); }} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: 'transparent', border: 'none', padding: '10px 8px',
              borderRadius: 8, cursor: 'pointer', textAlign: 'left',
              transition: 'background var(--dur-fast) var(--ease-out)',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--color-tile)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <div style={{
                width: 32, height: 32, borderRadius: 8, background: 'var(--color-tile)',
                color: 'var(--color-accent)', display: 'flex', alignItems: 'center',
                justifyContent: 'center', flexShrink: 0,
              }}><Icon name={a.icon} size={16}/></div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>{a.label}</div>
                <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13, color: 'var(--color-fg-secondary)', lineHeight: 1.4, marginTop: 2 }}>{a.desc}</div>
              </div>
              <Icon name="chevronRight" size={16} style={{ color: 'var(--color-fg-secondary)', marginTop: 9 }}/>
            </button>
          ))}
        </div>
        <button onClick={onCancel} style={{
          width: '100%', background: 'transparent', border: 'none', cursor: 'pointer',
          padding: '8px 4px 2px', fontFamily: 'var(--font-sans)', fontSize: 12,
          color: 'var(--color-fg-secondary)',
        }}>Cancel</button>
      </div>
    );
  }

  const verb = { autofill: 'Autofill into', copy: 'Copy', reveal: 'Reveal' }[chosenAction];
  const target = chosenAction === 'autofill' ? (item.site || item.name) : `${item.name} password`;

  return (
    <div style={{
      background: 'var(--color-surface-elevated)',
      border: '1px solid ' + (isConnected ? 'var(--color-success)' : 'var(--color-accent)'),
      borderRadius: 10, padding: '14px 16px',
      transition: 'all var(--dur-base) var(--ease-out)',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 6 }}>
        <div style={{
          position: 'relative', width: 44, height: 44, flexShrink: 0,
        }}>
          {isWaiting && [0, 0.6].map(d => (
            <span key={d} aria-hidden style={{
              position: 'absolute', inset: 0, borderRadius: '50%',
              border: '1.5px solid var(--color-accent)', opacity: 0.35,
              animation: `ripple 1.6s var(--ease-out) infinite ${d}s`,
              pointerEvents: 'none',
            }}/>
          ))}
          <div style={{
            position: 'absolute', inset: 0, borderRadius: '50%',
            background: isConnected ? 'var(--color-success)' : 'var(--color-tile)',
            color: isConnected ? '#FAF6EE' : 'var(--color-accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'all var(--dur-base) var(--ease-out)',
            zIndex: 1,
          }}>
            <Icon name={isConnected ? 'check' : 'nfc'} size={22}/>
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15,
            color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em',
            wordBreak: 'break-word',
          }}>
            {verb} <span style={{ fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 13, wordBreak: 'break-all' }}>{target}</span>?
          </div>
          <div style={{
            fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
            marginTop: 2,
          }}>
            {isWaiting && <>Tap your YubiKey to authorize this {chosenAction === 'autofill' ? 'fill' : chosenAction}.</>}
            {isConnected && <>Tap accepted.</>}
          </div>
        </div>
      </div>

      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--color-divider)',
      }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
        }}>
          <Icon name="nfc" size={12}/> NFC · USB-C · {primary?.name || 'YubiKey'}
        </span>
        {isWaiting && (
          <button onClick={onCancel} style={{
            background: 'transparent', border: 'none', cursor: 'pointer',
            fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
            padding: '2px 6px',
          }}>Cancel</button>
        )}
      </div>
    </div>
  );
};

const TotpCard = ({ code, onCopy }) => {
  const [secs, setSecs] = useStateV(() => 30 - (Math.floor(Date.now() / 1000) % 30));
  useEffectV(() => {
    const t = setInterval(() => {
      setSecs(30 - (Math.floor(Date.now() / 1000) % 30));
    }, 250);
    return () => clearInterval(t);
  }, []);
  const pct = secs / 30;
  const lowTime = secs <= 5;

  const clean = String(code).replace(/\s+/g, '');
  const mid = Math.ceil(clean.length / 2);
  const left = clean.slice(0, mid);
  const right = clean.slice(mid);

  const handleCopy = () => {
    try { navigator.clipboard?.writeText(clean); } catch (e) {}
    onCopy?.();
  };

  const r = 16, c = 2 * Math.PI * r;

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 14,
      background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
      borderRadius: 10, padding: '14px 14px',
    }}>
      <div style={{
        position: 'relative', width: 40, height: 40, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <svg viewBox="0 0 40 40" style={{ position: 'absolute', inset: 0, transform: 'rotate(-90deg)' }}>
          <circle cx="20" cy="20" r={r} fill="none" stroke="var(--color-border)" strokeWidth="2.5"/>
          <circle cx="20" cy="20" r={r} fill="none"
            stroke={lowTime ? 'var(--color-danger)' : 'var(--color-accent)'}
            strokeWidth="2.5" strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - pct)}
            style={{ transition: 'stroke-dashoffset 250ms linear, stroke var(--dur-base) var(--ease-out)' }}/>
        </svg>
        <span style={{
          fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
          color: lowTime ? 'var(--color-danger)' : 'var(--color-fg-secondary)',
          fontVariantNumeric: 'tabular-nums',
        }}>{secs}</span>
      </div>

      <div style={{
        flex: 1, minWidth: 0,
        display: 'flex', alignItems: 'baseline', justifyContent: 'center', gap: 12,
      }}>
        <span style={{
          fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace',
          fontSize: 32, fontWeight: 500, letterSpacing: '0.08em',
          color: lowTime ? 'var(--color-danger)' : 'var(--color-fg-emphasis)',
          fontVariantNumeric: 'tabular-nums',
          transition: 'color var(--dur-base) var(--ease-out)',
          lineHeight: 1,
        }}>{left}</span>
        <span style={{
          fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace',
          fontSize: 32, fontWeight: 500, letterSpacing: '0.08em',
          color: lowTime ? 'var(--color-danger)' : 'var(--color-fg-emphasis)',
          fontVariantNumeric: 'tabular-nums',
          transition: 'color var(--dur-base) var(--ease-out)',
          lineHeight: 1,
        }}>{right}</span>
      </div>

      <button onClick={handleCopy} style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
        borderRadius: 8, padding: '8px 12px', cursor: 'pointer',
        fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 600,
        color: 'var(--color-fg-primary)', flexShrink: 0,
        transition: 'all var(--dur-fast) var(--ease-out)',
      }}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--color-tile)'}
      onMouseLeave={e => e.currentTarget.style.background = 'var(--color-surface-elevated)'}>
        <Icon name="copy" size={14}/>
        Copy
      </button>
    </div>
  );
};

const TotpEnrollScreen = ({ item, onSave, onBack, toast }) => {
  const [tab, setTab] = useStateV('manual');
  const [input, setInput] = useStateV('');
  const [status, setStatus] = useStateV(null);
  const [parsed, setParsed] = useStateV(null);
  const fileRef = useRefV(null);

  const BASE32_RE = /^[A-Z2-7=\s]+$/i;

  const parseOtpauth = (uri) => {
    try {
      const url = new URL(uri);
      if (url.protocol !== 'otpauth:' || url.host !== 'totp') return null;
      const label = decodeURIComponent(url.pathname.slice(1));
      const secret = url.searchParams.get('secret');
      const issuer = url.searchParams.get('issuer') || '';
      if (!secret || !BASE32_RE.test(secret)) return null;
      return { secret, label: label || 'Manual entry', issuer };
    } catch { return null; }
  };

  const validate = (val) => {
    const trimmed = val.trim();
    if (!trimmed) { setParsed(null); setStatus(null); return; }
    if (trimmed.startsWith('otpauth://totp/')) {
      const p = parseOtpauth(trimmed);
      if (p) { setParsed(p); setStatus({ tone: 'success', msg: 'Valid otpauth URI' }); }
      else { setParsed(null); setStatus({ tone: 'danger', msg: 'Invalid otpauth URI -- check the secret is base32' }); }
      return;
    }
    const clean = trimmed.replace(/\s+/g, '');
    if (BASE32_RE.test(clean) && clean.length >= 16) {
      setParsed({ secret: clean.toUpperCase(), label: item?.name || 'Manual entry', issuer: '' });
      setStatus({ tone: 'success', msg: 'Valid base32 secret' });
    } else {
      setParsed(null);
      setStatus({ tone: 'danger', msg: 'Enter a valid base32 string (A-Z, 2-7) or otpauth:// URI' });
    }
  };

  const handleInput = (val) => { setInput(val); validate(val); };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard?.readText();
      if (text) handleInput(text);
    } catch { toast?.('Clipboard access denied'); }
  };

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setStatus({ tone: 'info', msg: 'Processing...' });
    setTimeout(() => {
      setStatus({ tone: 'danger', msg: 'QR decoding not available in standalone prototype -- use manual entry' });
    }, 800);
  };

  const demoCode = parsed ? (() => {
    const s = parsed.secret;
    let n = 0;
    for (let i = 0; i < s.length; i++) n = (n * 31 + s.charCodeAt(i)) & 0xffffff;
    return String(n % 1000000).padStart(6, '0');
  })() : null;

  const tabBtn = (id, label) => (
    <button onClick={() => setTab(id)} style={{
      flex: 1, padding: '8px 0', border: 'none', cursor: 'pointer',
      background: tab === id ? 'var(--color-accent)' : 'var(--color-surface-elevated)',
      color: tab === id ? 'var(--color-background)' : 'var(--color-fg-primary)',
      fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 600,
      borderRadius: tab === id ? 8 : 0,
      transition: 'all var(--dur-fast) var(--ease-out)',
    }}>{label}</button>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar
        title="Add authenticator"
        left={<IconBtn name="arrowLeft" onClick={onBack}/>}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px 24px' }}>
        <div style={{
          display: 'flex', borderRadius: 8, overflow: 'hidden',
          border: '1px solid var(--color-border)', marginBottom: 16,
        }}>
          {tabBtn('scan', 'Scan QR')}
          {tabBtn('manual', 'Enter manually')}
        </div>

        {tab === 'scan' && (
          <div>
            <div style={{
              position: 'relative', width: '100%', aspectRatio: '1',
              background: 'var(--color-surface-sunken)',
              borderRadius: 12, overflow: 'hidden', marginBottom: 12,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <video style={{ width: '100%', height: '100%', objectFit: 'cover' }}/>
              <div style={{
                position: 'absolute', inset: '15%',
                border: '3px solid var(--color-accent)',
                borderRadius: 16, opacity: 0.7,
                boxShadow: '0 0 0 9999px rgba(20,16,12,0.45)',
              }}/>
              <div style={{
                position: 'absolute', bottom: 16,
                fontFamily: 'var(--font-sans)', fontSize: 12,
                color: 'rgba(250,246,238,0.8)',
              }}>Point your camera at the QR code</div>
            </div>

            <input
              ref={fileRef} type="file" accept="image/*"
              onChange={handleFile}
              style={{ display: 'none' }}
            />
            <Button
              variant="secondary" fullWidth
              icon="plus"
              onClick={() => fileRef.current?.click()}
            >Upload QR image</Button>

            {status && tab === 'scan' && (
              <div style={{ marginTop: 12 }}>
                <StatusMessage tone={status.tone}>{status.msg}</StatusMessage>
              </div>
            )}
          </div>
        )}

        {tab === 'manual' && (
          <div>
            <Field label="Secret or URI">
              <TextInput
                value={input}
                onChange={handleInput}
                placeholder="otpauth://totp/... or JBSWY3DPEHPK3PXP"
                mono
              />
            </Field>

            <Button
              variant="ghost" size="sm"
              icon="copy"
              onClick={handlePaste}
              style={{ marginTop: -8, marginBottom: 12 }}
            >Paste from clipboard</Button>

            {status && (
              <div style={{ marginBottom: 12 }}>
                <StatusMessage tone={status.tone}>{status.msg}</StatusMessage>
              </div>
            )}
          </div>
        )}

        {parsed && demoCode && (
          <div style={{ marginTop: 8 }}>
            <Field label="Preview">
              <div style={{
                background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
                borderRadius: 10, padding: '12px 14px', marginBottom: 8,
              }}>
                <div style={{
                  fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15,
                  color: 'var(--color-fg-emphasis)', marginBottom: 2,
                }}>{parsed.label}</div>
                {parsed.issuer && (
                  <div style={{
                    fontFamily: 'var(--font-sans)', fontSize: 12,
                    color: 'var(--color-fg-secondary)', marginBottom: 8,
                  }}>{parsed.issuer}</div>
                )}
              </div>
              <TotpCard code={demoCode} onCopy={() => toast?.('Code copied')}/>
            </Field>
          </div>
        )}
      </div>

      <div style={{ padding: '12px 16px 20px', borderTop: '1px solid var(--color-divider)' }}>
        <Button
          fullWidth
          disabled={!parsed}
          onClick={() => parsed && onSave?.(parsed.secret)}
        >Add to item</Button>
      </div>
    </div>
  );
};

window.TotpEnrollScreen = TotpEnrollScreen;

const ItemDetailScreen = ({ item, onBack, onEdit, onProtect, onHistory, onDelete, onTapFail, onTotpEnroll, monoSecrets, toast }) => {
  const [tapMode, setTapMode] = useStateV(null);
  const [revealed, setRevealed] = useStateV(false);
  const [revealedSecret, setRevealedSecret] = useStateV(null);
  const [secsLeft, setSecsLeft] = useStateV(10);
  const [showSheet, setShowSheet] = useStateV(false);
  const [showDelete, setShowDelete] = useStateV(false);
  const [showMove, setShowMove] = useStateV(false);
  const [showRecipients, setShowRecipients] = useStateV(false);
  const [showMultiId, setShowMultiId] = useStateV(false);

  useEffectV(() => {
    if (!revealed) return;
    setSecsLeft(10);
    const t = setInterval(() => {
      setSecsLeft(s => {
        if (s <= 1) {
          clearInterval(t);
          setRevealed(false);
          setRevealedSecret(null);
          setTapMode(null);
          toast?.('Password cleared from screen');
          return 30;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [revealed]);

  const completeAction = (action, bridgePlaintext) => {
    const secret = bridgePlaintext ?? item.password ?? '';
    if (action === 'autofill') {
      setTapMode(null);
      toast?.(`Autofilled into ${item.site || 'app'}`, { kind: 'success' });
    } else if (action === 'copy') {
      try { navigator.clipboard?.writeText(secret); } catch (e) {}
      setTapMode(null);
      toast?.('Copied', { kind: 'success' });
    } else if (action === 'reveal') {
      setRevealedSecret(bridgePlaintext ?? null);
      setRevealed(true);
    }
  };

  const recipients = (item.recipients || []).map(rid => RECIPIENTS.find(r => r.id === rid)).filter(Boolean);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar
        title={item.name}
        subtitle={item.site}
        left={<IconBtn name="arrowLeft" onClick={onBack}/>}
        right={<>
          <IconBtn name="edit" onClick={onEdit} title="Edit"/>
          <IconBtn name="moreVertical" onClick={() => setShowSheet(true)}/>
        </>}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px 24px' }}>
        <Field label="Username">
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
            borderRadius: 8, padding: '10px 12px',
          }}>
            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 14, color: 'var(--color-fg-primary)' }}>
              {item.username}
            </span>
            <CopyButton value={item.username} compact onCopy={() => toast?.('Username copied')}/>
          </div>
        </Field>

        <Field
          label="Password"
          hint={!item.rage ? 'This item is not protected by Ragewarden.' : undefined}
        >
          {!item.rage ? (
            <>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
                borderRadius: 8, padding: '10px 12px',
              }}>
                <Mono>{
                  revealed
                    ? (revealedSecret ?? item.password ?? '')
                    : (typeof item.password === 'string'
                        ? '•'.repeat(Math.min(item.password.length, 16))
                        : '•'.repeat(12))
                }</Mono>
                <div style={{ display: 'flex', gap: 6 }}>
                  <IconBtn name={revealed ? 'eyeOff' : 'eye'} onClick={() => setRevealed(r => !r)} size={16} style={{ width: 28, height: 28 }}/>
                  <CopyButton value={item.password ?? ''} compact sensitive onCopy={() => toast?.('Password copied')}/>
                </div>
              </div>
              {onProtect && (
                <button onClick={onProtect} style={{
                  marginTop: 10, width: '100%', padding: '10px 12px',
                  background: 'var(--color-tile)', border: '1px solid var(--color-accent)',
                  borderRadius: 8, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 10,
                  fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-emphasis)',
                  textAlign: 'left',
                }}>
                  <Icon name="chain" size={16} style={{ color: 'var(--color-accent)' }}/>
                  <span style={{ flex: 1 }}>
                    <span style={{ fontWeight: 600 }}>Protect this item</span> -- wrap in age, require a tap to unlock.
                  </span>
                  <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
                </button>
              )}
            </>
          ) : revealed ? (
            <div style={{
              background: 'var(--color-surface-elevated)', border: '1px solid var(--color-success)',
              borderRadius: 10, padding: '12px 14px',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8,
              }}>
                <Mono size={14} style={{
                  flex: 1, minWidth: 0,
                  wordBreak: 'break-all',
                  color: 'var(--color-fg-emphasis)',
                  fontWeight: 500,
                }}>{revealedSecret ?? item.password ?? ''}</Mono>
                <CopyButton value={revealedSecret ?? item.password ?? ''} compact sensitive
                  onCopy={() => toast?.('Password copied')}/>
              </div>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                paddingTop: 8, borderTop: '1px solid var(--color-divider)', gap: 8,
              }}>
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
                }}>
                  <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--color-success)' }}/>
                  Auto-clear in {secsLeft}s
                </span>
                <button onClick={() => { setRevealed(false); setTapMode(null); }} style={{
                  background: 'transparent', border: '1px solid var(--color-border)',
                  borderRadius: 6, padding: '4px 8px', cursor: 'pointer',
                  fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-primary)',
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                }}><Icon name="eyeOff" size={13}/>Hide</button>
              </div>
            </div>
          ) : tapMode ? (
            <InlineTapReveal
              item={item}
              action={tapMode === 'choose' ? null : tapMode}
              onComplete={completeAction}
              onCancel={() => setTapMode(null)}
            />
          ) : (
            <div style={{
              background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
              borderRadius: 8, padding: '10px 12px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
                <Mono style={{ color: 'var(--color-fg-secondary)', letterSpacing: 4 }}>••••••••••••</Mono>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
                {[
                  { id: 'autofill', icon: 'arrowRight', label: 'Autofill' },
                  { id: 'copy',     icon: 'copy',       label: 'Copy' },
                  { id: 'reveal',   icon: 'eye',        label: 'Reveal' },
                ].map(a => (
                  <button key={a.id} onClick={() => setTapMode(a.id)} style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
                    background: a.id === 'autofill' ? 'var(--color-accent)' : 'var(--color-surface-elevated)',
                    color: a.id === 'autofill' ? 'var(--color-background)' : 'var(--color-fg-primary)',
                    border: '1px solid ' + (a.id === 'autofill' ? 'var(--color-accent)' : 'var(--color-border)'),
                    borderRadius: 8, padding: '8px 6px',
                    fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all var(--dur-fast) var(--ease-out)',
                  }}>
                    <Icon name={a.icon} size={16}/>
                    <span>{a.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </Field>

        {item.totp ? (
          <Field label="One-time code">
            <TotpCard code={item.totp} onCopy={() => toast?.('Code copied')}/>
            <button onClick={() => onTotpEnroll?.()} style={{
              marginTop: 8, background: 'transparent', border: 'none',
              cursor: 'pointer', padding: '4px 0',
              fontFamily: 'var(--font-sans)', fontSize: 12,
              color: 'var(--color-accent)', fontWeight: 500,
              display: 'inline-flex', alignItems: 'center', gap: 6,
            }}>
              <Icon name="edit" size={12}/>
              Change authenticator
            </button>
          </Field>
        ) : (
          <Field label="One-time code">
            <button onClick={() => onTotpEnroll?.()} style={{
              width: '100%', padding: '10px 12px',
              background: 'var(--color-tile)', border: '1px solid var(--color-border)',
              borderRadius: 8, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 10,
              fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-emphasis)',
              textAlign: 'left',
            }}>
              <Icon name="plus" size={16} style={{ color: 'var(--color-accent)' }}/>
              <span style={{ flex: 1, fontWeight: 600 }}>Add authenticator</span>
              <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
            </button>
          </Field>
        )}

        {item.site && (
          <Field label="Context">
            <div style={{
              background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
              borderRadius: 10, overflow: 'hidden',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 12px', borderBottom: '1px solid var(--color-divider)',
              }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 6, flexShrink: 0,
                  background: 'var(--color-tile)', color: 'var(--color-accent)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <Icon name="globe" size={15}/>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: 'var(--font-sans)', fontSize: 10.5, fontWeight: 600,
                    letterSpacing: '0.06em', textTransform: 'uppercase',
                    color: 'var(--color-fg-secondary)',
                  }}>URL · exact host match</div>
                  <Mono size={13} style={{
                    color: 'var(--color-fg-emphasis)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    display: 'block',
                  }}>https://{item.site}</Mono>
                </div>
                <CopyButton value={`https://${item.site}`} compact onCopy={() => toast?.('URL copied')}/>
              </div>

              <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--color-divider)' }}>
                <div style={{
                  fontFamily: 'var(--font-sans)', fontSize: 10.5, fontWeight: 600,
                  letterSpacing: '0.06em', textTransform: 'uppercase',
                  color: 'var(--color-fg-secondary)', marginBottom: 6,
                }}>Autofill rules</div>
                {[
                  { icon: 'shield', label: 'Origin binding', value: 'Strict -- host must equal ' + item.site, kind: 'success' },
                  { icon: 'tap', label: 'Per-fill consent', value: 'Tap required, no biometric fallback', kind: 'success' },
                  { icon: 'bolt', label: 'Quick tile', value: item.favorite ? 'Pinned -- surfaces in app picker' : 'Disabled', kind: item.favorite ? 'success' : 'muted' },
                ].map((r, i, arr) => (
                  <div key={r.label} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    padding: '6px 0',
                    borderBottom: i < arr.length - 1 ? '1px dashed var(--color-divider)' : 'none',
                  }}>
                    <Icon name={r.icon} size={14} style={{ color: 'var(--color-fg-secondary)', marginTop: 2, flexShrink: 0 }}/>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-primary)' }}>{r.label}</div>
                      <div style={{
                        fontFamily: 'var(--font-sans)', fontSize: 11.5, marginTop: 1,
                        color: r.kind === 'success' ? 'var(--color-success)' : 'var(--color-fg-secondary)',
                      }}>{r.value}</div>
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
                <Icon name="clock" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
                <span style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)' }}>
                  Last autofill <span style={{ color: 'var(--color-fg-primary)', fontWeight: 500 }}>{item.lastUsed}</span> from <Mono size={11} style={{ color: 'var(--color-fg-primary)' }}>{item.site}</Mono>
                </span>
              </div>
            </div>
          </Field>
        )}

        {item.notes && (
          <Field label="Notes">
            <div style={{
              fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.5,
              color: 'var(--color-fg-primary)',
              padding: '10px 12px',
              background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
              borderRadius: 8,
            }}>{item.notes}</div>
          </Field>
        )}

        {item.rage && (
          <Field label="Unlock recipients" hint="Any one of these can decrypt this secret.">
            <div style={{
              background: 'var(--color-surface)', border: '1px solid var(--color-border)',
              borderRadius: 8, overflow: 'hidden',
            }}>
              {recipients.map((r, i) => (
                <div key={r.id} style={{
                  padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 10,
                  borderBottom: i < recipients.length - 1 ? '1px solid var(--color-divider)' : 'none',
                }}>
                  <RecipientPip kind={r.kind}/>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 500,
                      color: 'var(--color-fg-primary)',
                    }}>{r.name}</div>
                    <Mono size={11} style={{ color: 'var(--color-fg-secondary)' }}>{recipientKindLabel(r.kind)}</Mono>
                  </div>
                </div>
              ))}
            </div>
          </Field>
        )}

        <div style={{
          marginTop: 4, padding: '12px 14px',
          background: 'var(--color-surface-sunken)', borderRadius: 8,
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
          fontFamily: 'var(--font-sans)', fontSize: 11.5,
        }}>
          <div>
            <div style={{ color: 'var(--color-fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, fontSize: 10, marginBottom: 2 }}>Last used</div>
            <div style={{ color: 'var(--color-fg-primary)' }}>{item.lastUsed}</div>
          </div>
          <div>
            <div style={{ color: 'var(--color-fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, fontSize: 10, marginBottom: 2 }}>History</div>
            <div style={{ color: 'var(--color-fg-primary)' }}>{item.history} versions</div>
          </div>
        </div>
      </div>

      <Sheet open={showSheet} onClose={() => setShowSheet(false)} title="More actions">
        {[
          { label: 'Launch website', icon: 'arrowRight', go: () => toast?.('Opens browser to ' + (item.site || '--')) },
          { label: 'Edit recipients', icon: 'chain', go: () => setShowRecipients(true) },
          { label: 'Try a different recipient', icon: 'tap', go: () => setShowMultiId(true), only: item.rage && (item.recipients || []).length > 1 },
          { label: 'View history', icon: 'clock', go: () => onHistory?.() },
          { label: 'Move to folder', icon: 'folder', go: () => setShowMove(true) },
          { label: 'Simulate tap timeout', icon: 'alert', go: () => onTapFail?.('timeout'), only: item.rage },
          { label: 'Delete item', icon: 'trash', danger: true, go: () => setShowDelete(true) },
        ].filter(a => a.only !== false).map((a, i, arr) => (
          <button key={a.label} onClick={() => { setShowSheet(false); a.go?.(); }} style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: 12,
            background: 'transparent', border: 'none', padding: '12px 4px',
            borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
            fontFamily: 'var(--font-sans)', fontSize: 14,
            color: a.danger ? 'var(--color-danger-strong)' : 'var(--color-fg-primary)',
            cursor: 'pointer', textAlign: 'left',
          }}>
            <Icon name={a.icon} size={18}/>{a.label}
          </button>
        ))}
      </Sheet>

      <DeleteConfirmSheet
        open={showDelete} onClose={() => setShowDelete(false)} item={item}
        onConfirm={() => { toast?.('Deleted ' + item.name); onDelete?.(); }} toast={toast}
      />
      <MoveToFolderSheet
        open={showMove} onClose={() => setShowMove(false)} current={item.folder || null}
        onPick={(f) => toast?.(f.id ? 'Moved to ' + f.name : 'Moved to Unfiled')} toast={toast}
      />
      <RecipientPickerSheet
        open={showRecipients} onClose={() => setShowRecipients(false)}
        value={item.recipients || []}
        onChange={(rs) => toast?.('Recipients updated · re-encrypting (' + rs.length + ')')}
        toast={toast}
      />
      <MultiIdentityPickerSheet
        open={showMultiId} onClose={() => setShowMultiId(false)} item={item}
        onPick={(r) => toast?.('Asking ' + r.name + '...')}
      />
    </div>
  );
};

/*
 * NotOnDeviceScreen -- where a click on a dimmed item lands.
 *
 * The item's age header names recipients, none of which is an identity this
 * device holds, so there is nothing here that could open it: the screen offers
 * no Reveal/Copy/Autofill and no path that could start a decrypt. The only
 * remedy is a re-wrap performed on a device that holds one of the keys.
 */
const NotOnDeviceScreen = ({ item, onBack }) => {
  const count = item
    ? (typeof item.recipientCount === 'number' ? item.recipientCount : (item.recipients || []).length)
    : 0;
  const name = item?.name || 'This item';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar
        title={name}
        subtitle="Not on this device"
        left={<IconBtn name="arrowLeft" onClick={onBack}/>}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 18px 18px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ textAlign: 'center', padding: '26px 0 18px' }}>
          <div style={{
            width: 64, height: 64, borderRadius: 32, margin: '0 auto 16px',
            background: 'var(--color-surface-sunken)', border: '1px dashed var(--color-border)',
            color: 'var(--color-fg-secondary)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon name="cloudOff" size={30}/>
          </div>
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2,
            color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 10,
          }}>
            This item can’t be opened here.
          </div>
          <div style={{
            fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55,
            color: 'var(--color-fg-primary)', maxWidth: 320, margin: '0 auto',
          }}>
            It is wrapped to {count > 0
              ? `${count} recipient${count === 1 ? '' : 's'}`
              : 'recipients'}, none on this device -- re-wrap it from a device
            that holds a key.
          </div>
        </div>

        <StatusMessage tone="info" title="Nothing was decrypted" style={{ marginBottom: 10 }}>
          No key here matches any recipient in this item’s encryption header, so
          no unlock was attempted and no tap will be asked for.
        </StatusMessage>
        <StatusMessage tone="warning" title="To use it on this device">
          Open the item on a device that holds one of its keys and re-encrypt it
          with this device’s recipients added. It will appear here after the next sync.
        </StatusMessage>

        <div style={{ flex: 1 }}/>
        <Button fullWidth variant="secondary" onClick={onBack}>Back to vault</Button>
      </div>
    </div>
  );
};

window.VaultScreen = VaultScreen;
window.ItemDetailScreen = ItemDetailScreen;
window.NotOnDeviceScreen = NotOnDeviceScreen;
