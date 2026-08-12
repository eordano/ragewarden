const { useState, useEffect, useRef, useCallback } = React;

const RageChip = ({ recipients = [], style = 'pill', size = 'sm' }) => {
  if (style === 'icon') {
    return (
      <span title="Protected with RageDroid" style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        width: 22, height: 22, color: 'var(--color-accent)',
      }}>
        <Icon name="chain" size={14}/>
      </span>
    );
  }
  if (style === 'rule') {
    return <span style={{ display: 'inline-block', width: 3, alignSelf: 'stretch', background: 'var(--color-accent)', borderRadius: 2 }}/>;
  }
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 7px 2px 6px', borderRadius: 999,
      background: 'var(--color-tile)',
      color: 'var(--color-accent)',
      fontFamily: 'var(--font-sans)', fontSize: size === 'sm' ? 10.5 : 11.5,
      fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase',
      whiteSpace: 'nowrap',
    }}>
      <Icon name="chain" size={11}/> Rage
      {recipients.length > 0 && <span style={{ opacity: 0.6, fontWeight: 500 }}>· {recipients.length}</span>}
    </span>
  );
};

/*
 * Snapshot-truth helpers, shared by every list that draws from VAULT /
 * ITEMS_BY_KIND. Internal bookkeeping ciphers (__ragedroid_recipients_v1__,
 * __ragewarden_history_v1__:<id>, the legacy recipients note) are storage, not
 * items, and never render; an item whose rage header matched none of this
 * device's identities renders dimmed and routes to an explanation instead of a
 * decrypt. `decryptable` is absent on sample items that predate the field, so
 * only an explicit false dims.
 */
const isInternalItem = (it) => !!it && (
  it.internal === true
  || /^__.+__/.test(it.name || '')
  || it.name === 'Ragewarden Recipients (do not edit)'
);
const isNotOnThisDevice = (it) => !!it && it.rage === true && it.decryptable === false;

const NotOnDeviceChip = () => (
  <span title="Wrapped only to recipients that are not on this device" style={{
    display: 'inline-flex', alignItems: 'center', gap: 4,
    padding: '2px 7px 2px 6px', borderRadius: 999,
    background: 'var(--color-surface-sunken)',
    border: '1px dashed var(--color-border)',
    color: 'var(--color-fg-secondary)',
    fontFamily: 'var(--font-sans)', fontSize: 10.5,
    fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  }}>
    <Icon name="cloudOff" size={11}/> Not on this device
  </span>
);

const Mono = ({ children, size = 12, style = {} }) => (
  <span style={{
    fontFamily: 'ui-monospace, "SF Mono", "Menlo", "Roboto Mono", monospace',
    fontSize: size, color: 'var(--color-fg-primary)', letterSpacing: '-0.01em',
    ...style,
  }}>{children}</span>
);

const AppBar = ({ title, subtitle, left, right, large = false }) => (
  <div style={{
    padding: large ? '14px 18px 8px' : '10px 12px',
    display: 'flex', alignItems: large ? 'flex-end' : 'center',
    justifyContent: 'space-between',
    background: 'var(--color-background)',
    minHeight: large ? 64 : 48,
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flex: 1, minWidth: 0 }}>
      {left}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700,
          fontSize: large ? 26 : 17, letterSpacing: '-0.01em',
          color: 'var(--color-fg-emphasis)', lineHeight: 1.1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{title}</div>
        {subtitle && (
          <div style={{
            fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
            marginTop: 2,
          }}>{subtitle}</div>
        )}
      </div>
    </div>
    <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>{right}</div>
  </div>
);

const IconBtn = ({ name, onClick, size = 20, danger, title, style = {} }) => (
  <button onClick={onClick} aria-label={title} title={title}
    className="iconbtn"
    style={{
      width: 36, height: 36, borderRadius: 18, border: 'none',
      background: 'transparent', cursor: 'pointer',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: danger ? 'var(--color-danger-strong)' : 'var(--color-fg-primary)',
      ...style,
    }}>
    <Icon name={name} size={size}/>
  </button>
);

const Button = ({ children, onClick, variant = 'primary', size = 'md', icon, fullWidth, disabled, style = {} }) => {
  const styles = {
    primary: { background: 'var(--color-accent)', color: 'var(--color-background)', border: '1px solid var(--color-accent)' },
    secondary: { background: 'var(--color-surface-elevated)', color: 'var(--color-fg-primary)', border: '1px solid var(--color-border)' },
    ghost: { background: 'transparent', color: 'var(--color-fg-primary)', border: '1px solid transparent' },
    danger: { background: 'var(--color-danger)', color: 'var(--color-background)', border: '1px solid var(--color-danger)' },
  }[variant];
  const sz = size === 'sm' ? { padding: '7px 12px', fontSize: 13 } : { padding: '11px 18px', fontSize: 14.5 };
  return (
    <button onClick={onClick} disabled={disabled} style={{
      ...styles, ...sz,
      borderRadius: 8, cursor: disabled ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      fontFamily: 'var(--font-sans)', fontWeight: 600,
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8,
      width: fullWidth ? '100%' : undefined,
      transition: 'background var(--dur-fast) var(--ease-out)',
      ...style,
    }}>
      {icon && <Icon name={icon} size={16}/>}
      {children}
    </button>
  );
};

// Renders the toasts every screen in this prototype passes to `toast(...)`.
// It used to be `() => null`, which made the prototype's only error channel a
// no-op: every failure path in every screen rendered nothing at all.
const ToastHost = ({ toasts = [], dismiss }) => {
  if (!toasts.length) return null;
  const tone = {
    success: 'var(--color-success)',
    error:   'var(--color-danger-strong)',
    danger:  'var(--color-danger-strong)',
    warning: 'var(--color-warning)',
  };
  return (
    <div style={{
      position: 'absolute', left: 10, right: 10, bottom: 10, zIndex: 90,
      display: 'flex', flexDirection: 'column', gap: 6, pointerEvents: 'none',
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          pointerEvents: 'auto',
          display: 'flex', alignItems: 'flex-start', gap: 8,
          background: 'var(--color-surface-elevated)',
          border: '1px solid var(--color-border)',
          borderLeft: '3px solid ' + (tone[t.kind] || 'var(--color-info)'),
          borderRadius: 8, padding: '8px 8px 8px 11px',
          fontFamily: 'var(--font-sans)', fontSize: 12.5, lineHeight: 1.35,
          color: 'var(--color-fg-primary)',
          boxShadow: '0 4px 12px rgba(20,16,12,0.18)',
          animation: 'toast-in 180ms var(--ease-out)',
        }}>
          <span style={{ flex: 1, minWidth: 0, wordBreak: 'break-word' }}>{t.label}</span>
          <button onClick={() => dismiss?.(t.id)} aria-label="Dismiss" style={{
            border: 'none', background: 'transparent', cursor: 'pointer',
            color: 'inherit', fontSize: 15, lineHeight: 1, padding: '0 2px',
          }}>x</button>
        </div>
      ))}
    </div>
  );
};

const StatusMessage = ({ tone = 'info', title, icon, children, action, compact = false, style = {} }) => {
  const palette = {
    info:    { fg: 'var(--color-info)',    icon: 'info' },
    success: { fg: 'var(--color-success)', icon: 'check' },
    warning: { fg: 'var(--color-warning)', icon: 'alert' },
    danger:  { fg: 'var(--color-danger)',  icon: 'alert' },
  }[tone] || { fg: 'var(--color-info)', icon: 'info' };
  const iconName = icon || palette.icon;
  return (
    <div style={{
      background: 'var(--color-surface-sunken)',
      border: '1px solid var(--color-border)',
      borderLeft: '3px solid ' + palette.fg,
      borderRadius: 8,
      padding: compact ? '8px 10px' : '10px 12px',
      display: 'flex', alignItems: 'flex-start', gap: 10,
      ...style,
    }}>
      <Icon name={iconName} size={compact ? 13 : 14}
        style={{ color: palette.fg, flexShrink: 0, marginTop: compact ? 0 : 1 }}/>
      <div style={{ flex: 1, minWidth: 0 }}>
        {title && (
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700,
            fontSize: compact ? 12.5 : 13.5,
            color: 'var(--color-fg-emphasis)',
          }}>{title}</div>
        )}
        {children && (
          <div style={{
            fontFamily: 'var(--font-sans)', fontSize: compact ? 11 : 11.5,
            color: 'var(--color-fg-secondary)',
            marginTop: title ? 2 : 0, lineHeight: 1.45,
          }}>{children}</div>
        )}
      </div>
      {action && (
        <button onClick={action.onClick} style={{
          background: 'transparent', border: '1px solid var(--color-border)',
          borderRadius: 6, padding: '5px 10px', cursor: 'pointer',
          fontFamily: 'var(--font-sans)', fontSize: 11.5, fontWeight: 600,
          color: 'var(--color-fg-emphasis)', flexShrink: 0,
        }}>{action.label}</button>
      )}
    </div>
  );
};

let toastSeq = 0;
const useToasts = () => {
  const [toasts, setToasts] = useState([]);
  const show = useCallback((label, opts = {}) => {
    const id = ++toastSeq;
    setToasts(t => [...t, { id, label, ...opts }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), opts.duration || 3500);
    return id;
  }, []);
  const dismiss = useCallback(id => setToasts(t => t.filter(x => x.id !== id)), []);
  return { toasts, show, dismiss };
};

const Sheet = ({ open, onClose, title, children, height = 'auto' }) => {
  if (!open) return null;
  return (
    <div style={{
      position: 'absolute', inset: 0, zIndex: 60,
      display: 'flex', flexDirection: 'column', justifyContent: 'flex-end',
      background: 'var(--color-backdrop, rgba(20,16,12,0.40))',
      animation: 'fade-in 220ms var(--ease-out)',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--color-surface-elevated)',
        borderTopLeftRadius: 16, borderTopRightRadius: 16,
        padding: '14px 18px 28px',
        maxHeight: '85%', overflowY: 'auto',
        animation: 'sheet-in 220ms cubic-bezier(0.2,0.8,0.2,1)',
        boxShadow: '0 -8px 24px rgba(20,16,12,0.12)',
      }}>
        <div style={{ width: 36, height: 4, background: 'var(--color-border)', borderRadius: 2, margin: '0 auto 14px' }}/>
        {title && (
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18,
            color: 'var(--color-fg-emphasis)', marginBottom: 12, letterSpacing: '-0.01em',
          }}>{title}</div>
        )}
        {children}
      </div>
    </div>
  );
};

const Field = ({ label, hint, children, style = {} }) => (
  <div style={{ marginBottom: 16, ...style }}>
    <div style={{
      fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
      letterSpacing: '0.06em', textTransform: 'uppercase',
      color: 'var(--color-fg-secondary)', marginBottom: 6,
    }}>{label}</div>
    {children}
    {hint && (
      <div style={{
        fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
        marginTop: 6, lineHeight: 1.4,
      }}>{hint}</div>
    )}
  </div>
);

const TextInput = ({ value, onChange, placeholder, mono, type = 'text', style = {} }) => (
  <input type={type} value={value} onChange={e => onChange?.(e.target.value)} placeholder={placeholder}
    style={{
      width: '100%', boxSizing: 'border-box',
      background: 'var(--color-surface-sunken)',
      border: '1px solid var(--color-border)', borderRadius: 8,
      padding: '10px 12px',
      fontFamily: mono ? 'ui-monospace, "SF Mono", Menlo, monospace' : 'var(--font-sans)',
      fontSize: mono ? 13 : 14,
      color: 'var(--color-fg-primary)', outline: 'none',
      ...style,
    }}/>
);

const CopyButton = ({ value, label = 'Copy', onCopy, compact, sensitive = false }) => {
  const [copied, setCopied] = useState(false);
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    if (!copied) return;
    if (sensitive) {
      setSecs(30);
      const t = setInterval(() => {
        setSecs(s => {
          if (s <= 1) { clearInterval(t); setCopied(false); return 0; }
          return s - 1;
        });
      }, 1000);
      return () => clearInterval(t);
    }
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied, sensitive]);
  const click = () => {
    if (navigator.clipboard) { try { navigator.clipboard.writeText(value); } catch (e) {} }
    setCopied(true);
    onCopy?.();
  };
  return (
    <button onClick={click} style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: compact ? '4px 8px' : '6px 10px', borderRadius: 6,
      background: copied ? 'var(--color-success)' : 'var(--color-tile)',
      color: copied ? '#FAF6EE' : 'var(--color-fg-primary)',
      border: 'none', cursor: 'pointer',
      fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
      transition: 'all var(--dur-fast) var(--ease-out)',
    }}>
      <Icon name={copied ? 'check' : 'copy'} size={13}/>
      {copied ? (sensitive ? `Cleared in ${secs}s` : 'Copied') : label}
    </button>
  );
};

// ── Recipient pip (small dot per recipient on a cipher) ──
const RecipientPip = ({ kind, size = 10 }) => {
  const c = {
    yubikey: 'var(--color-accent)',
    fido2: 'var(--color-info)',
    strongbox: 'var(--color-success)',
    recovery: 'var(--color-warning)',
  }[kind] || 'var(--color-fg-secondary)';
  return <span style={{ width: size, height: size, borderRadius: '50%', background: c, display: 'inline-block' }}/>;
};

const recipientKindLabel = (k) => ({
  yubikey: 'YubiKey · PIV',
  fido2: 'FIDO2 hmac-secret',
  strongbox: 'Android StrongBox',
  recovery: 'Paper recovery',
}[k]);

const recipientKindIcon = (k) => ({
  yubikey: 'key',
  fido2: 'fingerprint',
  strongbox: 'shield',
  recovery: 'paper',
}[k]);

// ── MasterPasswordConfirm -- gates destructive actions ──
// Re-prompts for the master password before irreversible operations
// (revoke a recipient, sign out, etc). Optional via the
// `requireMasterPassword` setting; default on.
// `expected` (optional) lets the prototype check against a known value;
// when omitted any non-empty input is accepted so you can demo the flow.
const MasterPasswordConfirm = ({
  open, onClose, onConfirm,
  title = 'Confirm with master password',
  body, expected, action = 'Confirm', danger = true,
}) => {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  useEffect(() => { if (open) { setPw(''); setErr(''); } }, [open]);
  const submit = () => {
    if (!pw) { setErr('Enter your master password.'); return; }
    if (expected && pw !== expected) { setErr('Wrong master password.'); return; }
    onConfirm?.();
    onClose?.();
  };
  return (
    <Sheet open={open} onClose={onClose} title={title}>
      <div style={{ padding: '0 16px 16px' }}>
        {body && (
          <div style={{
            fontFamily: 'var(--font-serif)', fontSize: 14, lineHeight: 1.5,
            color: 'var(--color-fg-primary)', marginBottom: 14,
          }}>{body}</div>
        )}
        <Field label="Master password">
          <input
            type="password" value={pw}
            onChange={e => { setPw(e.target.value); setErr(''); }}
            onKeyDown={e => { if (e.key === 'Enter') submit(); }}
            autoFocus
            placeholder="••••••••••••"
            style={{
              width: '100%', boxSizing: 'border-box',
              background: 'var(--color-surface-sunken)',
              border: '1px solid ' + (err ? 'var(--color-danger)' : 'var(--color-border)'),
              borderRadius: 8, padding: '10px 12px',
              fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace',
              fontSize: 13, color: 'var(--color-fg-primary)', outline: 'none',
            }}/>
        </Field>
        {err && (
          <div style={{
            fontFamily: 'var(--font-sans)', fontSize: 12,
            color: 'var(--color-danger-strong)', marginTop: -8, marginBottom: 14,
          }}>{err}</div>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button fullWidth variant={danger ? 'danger' : 'primary'} onClick={submit}>{action}</Button>
        </div>
      </div>
    </Sheet>
  );
};

window.RageChip = RageChip;
window.isInternalItem = isInternalItem;
window.isNotOnThisDevice = isNotOnThisDevice;
window.NotOnDeviceChip = NotOnDeviceChip;
window.Mono = Mono;
window.AppBar = AppBar;
window.IconBtn = IconBtn;
window.Button = Button;
/*
 * PhraseEntry -- 24 numbered cells for typing a paper recovery phrase, modeled on
 * MetaMask's SRP import. Paste the whole sheet anywhere (numbers and punctuation
 * from a printout are stripped), type with four-letter autocomplete (BIP39 words
 * are unique at four letters -- ghost text completes, space/enter accepts), and
 * every word is checked against the wordlist as you go. The Continue affordance
 * belongs to the parent: onReady(phrase) fires with the full phrase once all
 * words are valid AND validatePhrase (the checksum, via WASM in the shipped
 * popup) passes; onReady(null) fires the moment that stops being true.
 */
const PhraseEntry = ({ length = 24, validatePhrase, onReady, autoFocus = true }) => {
  const wordlist = (typeof window !== 'undefined' && window.BIP39_WORDS) || [];
  const [words, setWords] = useState(() => Array.from({ length }, () => ''));
  const [hidden, setHidden] = useState(false);
  const [focused, setFocused] = useState(autoFocus ? 0 : -1);
  const [checking, setChecking] = useState(false);
  const [checksumError, setChecksumError] = useState(null);
  const refs = useRef([]);
  const checkSeq = useRef(0);

  const wordset = React.useMemo(() => new Set(wordlist), [wordlist]);
  const isWord = (w) => wordset.has(w);
  const isPrefix = (w) => w !== '' && wordlist.some(x => x.startsWith(w));
  const suggest = (w) => {
    if (w.length < 2 || isWord(w)) return null;
    const m = wordlist.filter(x => x.startsWith(w));
    return m.length >= 1 ? m[0] : null;
  };

  const normalize = (s) => s.toLowerCase().replace(/[^a-z]/g, '');
  const parsePaste = (text) =>
    text.toLowerCase().replace(/[^a-z]+/g, ' ').trim().split(/\s+/).filter(Boolean);

  const allValid = words.every(isWord);
  const filled = words.filter(w => w !== '').length;

  useEffect(() => {
    const seq = ++checkSeq.current;
    if (filled < length || !allValid) {
      setChecking(false);
      setChecksumError(null);
      onReady?.(null);
      return;
    }
    const phrase = words.join(' ');
    if (!validatePhrase) { onReady?.(phrase); return; }
    setChecking(true);
    Promise.resolve(validatePhrase(phrase)).then(
      (r) => {
        if (seq !== checkSeq.current) return;
        setChecking(false);
        const ok = r && r.ok;
        setChecksumError(ok ? null : ((r && r.error) || 'checksum failed'));
        onReady?.(ok ? phrase : null);
      },
      (err) => {
        if (seq !== checkSeq.current) return;
        setChecking(false);
        setChecksumError((err && err.message) || String(err));
        onReady?.(null);
      },
    );
  }, [words.join(' ')]);

  const setWord = (i, v) => {
    setWords(ws => { const next = ws.slice(); next[i] = v; return next; });
  };

  const focusCell = (i) => {
    const el = refs.current[i];
    if (el) { el.focus(); el.select?.(); }
  };

  const nextEmptyFrom = (ws, i) => {
    for (let k = i; k < length; k++) if (!ws[k]) return k;
    return Math.min(i, length - 1);
  };

  const handlePaste = (i, e) => {
    const text = (e.clipboardData || window.clipboardData)?.getData('text') || '';
    const parsed = parsePaste(text);
    if (parsed.length <= 1) return; // single word: let the input take it normally
    e.preventDefault();
    setWords(ws => {
      const next = ws.slice();
      const start = parsed.length === length ? 0 : i;
      for (let k = 0; k < parsed.length && start + k < length; k++) next[start + k] = parsed[k];
      setTimeout(() => focusCell(nextEmptyFrom(next, 0)), 0);
      return next;
    });
  };

  const acceptAndAdvance = (i) => {
    const cur = words[i];
    const s = suggest(cur);
    if (s && !isWord(cur)) setWord(i, s);
    if (i + 1 < length) setTimeout(() => focusCell(i + 1), 0);
  };

  const handleKeyDown = (i, e) => {
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      if (words[i] !== '') acceptAndAdvance(i);
    } else if (e.key === 'Tab' && !e.shiftKey && suggest(words[i]) && words[i] !== '' && !isWord(words[i])) {
      e.preventDefault();
      acceptAndAdvance(i);
    } else if (e.key === 'Backspace' && words[i] === '' && i > 0) {
      e.preventDefault();
      focusCell(i - 1);
    } else if (e.key === 'ArrowRight' && i + 1 < length && (e.target.selectionStart ?? 0) >= words[i].length) {
      focusCell(i + 1);
    } else if (e.key === 'ArrowLeft' && i > 0 && (e.target.selectionEnd ?? 1) === 0) {
      focusCell(i - 1);
    }
  };

  const firstBadIdx = words.findIndex(w => w !== '' && !isPrefix(w) && !isWord(w));
  const blurredBadIdx = words.findIndex((w, i) => w !== '' && i !== focused && !isWord(w));
  const badIdx = firstBadIdx !== -1 ? firstBadIdx : blurredBadIdx;

  let statusLine = null;
  let statusTone = 'var(--color-fg-secondary)';
  if (badIdx !== -1) {
    statusLine = `Word ${badIdx + 1} -- "${words[badIdx]}" isn’t a recovery word.`;
    statusTone = 'var(--color-danger, #B5361A)';
  } else if (checking) {
    statusLine = 'Checking the phrase...';
  } else if (checksumError && filled === length) {
    statusLine = 'All 24 are real words, but together they don't check out -- one is probably swapped or mistyped.';
    statusTone = 'var(--color-danger, #B5361A)';
  } else if (filled < length) {
    statusLine = `${filled} of ${length} words`;
  } else {
    statusLine = 'Phrase looks good.';
  }

  const cellFont = { fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 13, lineHeight: '18px' };

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
        {words.map((w, i) => {
          const bad = w !== '' && (i === focused ? !isPrefix(w) && !isWord(w) : !isWord(w));
          const ghost = i === focused && !hidden ? suggest(w) : null;
          return (
            <div key={i} style={{
              position: 'relative', display: 'flex', alignItems: 'center',
              border: `1px solid ${bad ? 'var(--color-danger, #B5361A)' : 'var(--color-border)'}`,
              borderRadius: 8, background: 'var(--color-surface)',
              padding: '7px 8px 7px 6px',
            }}>
              <span style={{
                width: 20, textAlign: 'right', marginRight: 6, userSelect: 'none',
                fontFamily: 'var(--font-sans)', fontSize: 10,
                color: 'var(--color-fg-secondary)',
              }}>{i + 1}</span>
              <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
                {ghost && (
                  <span aria-hidden style={{
                    position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)',
                    pointerEvents: 'none',
                    whiteSpace: 'pre', ...cellFont, color: 'var(--color-fg-secondary)', opacity: 0.5,
                  }}>{ghost}</span>
                )}
                <input
                  ref={el => { refs.current[i] = el; }}
                  value={w}
                  type={hidden ? 'password' : 'text'}
                  autoFocus={autoFocus && i === 0}
                  autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false}
                  onChange={e => setWord(i, normalize(e.target.value))}
                  onKeyDown={e => handleKeyDown(i, e)}
                  onPaste={e => handlePaste(i, e)}
                  onFocus={() => setFocused(i)}
                  onBlur={() => setFocused(f => (f === i ? -1 : f))}
                  style={{
                    position: 'relative', display: 'block', width: '100%', height: 18,
                    border: 'none', outline: 'none',
                    background: 'transparent', padding: 0, ...cellFont,
                    color: bad ? 'var(--color-danger, #B5361A)' : 'var(--color-fg-emphasis)',
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, marginTop: 10,
        fontFamily: 'var(--font-sans)', fontSize: 12,
      }}>
        <span style={{ flex: 1, color: statusTone }}>{statusLine}</span>
        <button onClick={() => setHidden(h => !h)} style={{
          border: 'none', background: 'transparent', cursor: 'pointer',
          color: 'var(--color-accent)', fontFamily: 'var(--font-sans)', fontSize: 12, padding: 0,
        }}>{hidden ? 'Show words' : 'Hide words'}</button>
        <button onClick={() => { setWords(Array.from({ length }, () => '')); setChecksumError(null); focusCell(0); }} style={{
          border: 'none', background: 'transparent', cursor: 'pointer',
          color: 'var(--color-fg-secondary)', fontFamily: 'var(--font-sans)', fontSize: 12, padding: 0,
        }}>Clear</button>
      </div>
    </div>
  );
};

window.ToastHost = ToastHost;
window.useToasts = useToasts;
window.StatusMessage = StatusMessage;
window.Sheet = Sheet;
window.Field = Field;
window.TextInput = TextInput;
window.CopyButton = CopyButton;
window.RecipientPip = RecipientPip;
window.recipientKindLabel = recipientKindLabel;
window.recipientKindIcon = recipientKindIcon;
window.MasterPasswordConfirm = MasterPasswordConfirm;
window.PhraseEntry = PhraseEntry;
