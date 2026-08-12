const { useState: useStateF, useMemo: useMemoF, useRef: useRefF, useEffect: useEffectF } = React;

const SEARCH_RECENTS_KEY = 'ragedroid_search_recents';
const PINNED_IDS = ['gh-prod', 'aws-root', 'tail-key'];

const SearchScreenPlus = ({ onBack, onOpen, chipStyle = 'pill' }) => {
  const [query, setQuery] = useStateF('');
  const [protectedOnly, setProtectedOnly] = useStateF(false);
  const [recipientId, setRecipientId] = useStateF(null);
  const [folder, setFolder] = useStateF(null);
  const [recents, setRecents] = useStateF(() => {
    try { return JSON.parse(localStorage.getItem(SEARCH_RECENTS_KEY) || '[]'); }
    catch (e) { return []; }
  });
  const inputRef = useRefF(null);

  useEffectF(() => { inputRef.current?.focus(); }, []);

  const folders = ['Work', 'Personal', 'Infrastructure'];

  const allItems = useMemoF(() => {
    const base = [...VAULT];
    if (typeof ITEMS_BY_KIND !== 'undefined') {
      for (const i of ITEMS_BY_KIND) {
        base.push({
          ...i,
          username: i.kind === 'card' ? i.cardholder
                  : i.kind === 'identity' ? i.fullName
                  : i.kind === 'ssh' ? i.keyType
                  : 'Secure note',
          site: i.site || '',
        });
      }
    }
    // Registry/history bookkeeping is not searchable -- it is not an item.
    return base.filter(it => !isInternalItem(it));
  }, []);

  const computeMatch = (item, q) => {
    if (!q) return null;
    const ql = q.toLowerCase();
    if (item.name?.toLowerCase().includes(ql)) return 'name';
    if (item.username?.toLowerCase().includes(ql)) return 'username';
    if (item.site?.toLowerCase().includes(ql)) return 'site';
    if (item.notes?.toLowerCase().includes(ql)) return 'notes';
    if (item.folder?.toLowerCase().includes(ql)) return 'folder';
    return null;
  };

  const filtered = allItems
    .map(it => ({ it, match: computeMatch(it, query) }))
    .filter(({ it, match }) => {
      if (protectedOnly && !it.rage) return false;
      if (recipientId && !(it.recipients || []).includes(recipientId)) return false;
      if (folder && it.folder !== folder) return false;
      if (query && !match) return false;
      return true;
    });

  const activeFilters = [protectedOnly, recipientId, folder].filter(Boolean).length;
  const hasQuery = query.length > 0;

  const recordRecent = (itemId) => {
    const next = [itemId, ...recents.filter(i => i !== itemId)].slice(0, 5);
    setRecents(next);
    try { localStorage.setItem(SEARCH_RECENTS_KEY, JSON.stringify(next)); } catch (e) {}
  };

  const open = (item) => { recordRecent(item.id); onOpen(item); };

  const recentItems = recents
    .map(id => allItems.find(it => it.id === id))
    .filter(Boolean);
  const pinnedItems = PINNED_IDS
    .map(id => allItems.find(it => it.id === id))
    .filter(Boolean);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        padding: '10px 12px 8px', display: 'flex', alignItems: 'center', gap: 8,
        background: 'var(--color-background)',
      }}>
        <IconBtn name="arrowLeft" onClick={onBack}/>
        <div style={{
          flex: 1, display: 'flex', alignItems: 'center', gap: 8,
          background: 'var(--color-surface-sunken)', borderRadius: 10, padding: '8px 12px',
        }}>
          <Icon name="search" size={16} style={{ color: 'var(--color-fg-secondary)' }}/>
          <input ref={inputRef} value={query} onChange={e => setQuery(e.target.value)}
            placeholder="Search vault, recipients, notes"
            style={{
              flex: 1, border: 'none', outline: 'none', background: 'transparent',
              fontFamily: 'var(--font-sans)', fontSize: 14, color: 'var(--color-fg-primary)',
            }}/>
          {query && <button onClick={() => setQuery('')} style={{
            background: 'transparent', border: 'none', cursor: 'pointer',
            color: 'var(--color-fg-secondary)', padding: 0, display: 'flex',
          }}><Icon name="x" size={16}/></button>}
        </div>
      </div>

      <div style={{ padding: '4px 14px 10px', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <FilterChip label="Protected only" icon="chain" active={protectedOnly}
          onClick={() => setProtectedOnly(v => !v)}/>
        <FilterChip
          label={recipientId ? RECIPIENTS.find(r => r.id === recipientId)?.name || 'Recipient' : 'Recipient'}
          icon="key" active={!!recipientId}
          onClick={() => {
            const order = [null, 'yk-primary', 'yk-backup', 'strongbox', 'recovery'];
            setRecipientId(order[(order.indexOf(recipientId) + 1) % order.length]);
          }}/>
        <FilterChip label={folder || 'Folder'} icon="folder" active={!!folder}
          onClick={() => {
            const order = [null, ...folders];
            setFolder(order[(order.indexOf(folder) + 1) % order.length]);
          }}/>
        {activeFilters > 0 && (
          <button onClick={() => { setProtectedOnly(false); setRecipientId(null); setFolder(null); }}
            style={{
              background: 'transparent', border: 'none', cursor: 'pointer', padding: '5px 8px',
              fontFamily: 'var(--font-sans)', fontSize: 11.5, fontWeight: 600,
              color: 'var(--color-fg-secondary)',
            }}>Clear</button>
        )}
      </div>

      {!hasQuery && activeFilters === 0 ? (
        <div style={{ flex: 1, overflowY: 'auto', borderTop: '1px solid var(--color-divider)' }}>
          {recentItems.length > 0 && (
            <SearchSection label="Recent">
              {recentItems.map(it => <PlainResultRow key={'rc-' + it.id} item={it} onClick={() => open(it)} hint="Recent"/>)}
            </SearchSection>
          )}
          {pinnedItems.length > 0 && (
            <SearchSection label="Pinned">
              {pinnedItems.map(it => <PlainResultRow key={'pn-' + it.id} item={it} onClick={() => open(it)} hint="Pinned" hintIcon="star"/>)}
            </SearchSection>
          )}
          {recentItems.length === 0 && pinnedItems.length === 0 && (
            <div style={{ padding: '60px 24px 0', textAlign: 'center' }}>
              <div style={{
                width: 48, height: 48, borderRadius: 24, background: 'var(--color-tile)',
                color: 'var(--color-fg-secondary)', display: 'inline-flex', alignItems: 'center',
                justifyContent: 'center', marginBottom: 14,
              }}><Icon name="search" size={22}/></div>
              <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, fontStyle: 'italic',
                color: 'var(--color-fg-secondary)' }}>
                Type to search, or pick a filter.
              </div>
            </div>
          )}
        </div>
      ) : (
        <>
          <div style={{
            padding: '0 18px 8px',
            fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
            letterSpacing: '0.06em', textTransform: 'uppercase',
            color: 'var(--color-fg-secondary)',
          }}>
            {filtered.length} {filtered.length === 1 ? 'result' : 'results'}
          </div>
          <div style={{ flex: 1, overflowY: 'auto', borderTop: '1px solid var(--color-divider)' }}>
            {filtered.length === 0 ? (
              <div style={{ padding: '60px 24px 0', textAlign: 'center' }}>
                <div style={{
                  width: 48, height: 48, borderRadius: 24, background: 'var(--color-tile)',
                  color: 'var(--color-fg-secondary)', display: 'inline-flex', alignItems: 'center',
                  justifyContent: 'center', marginBottom: 14,
                }}><Icon name="search" size={22}/></div>
                <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, fontStyle: 'italic',
                  color: 'var(--color-fg-secondary)' }}>
                  Nothing matches that search.
                </div>
              </div>
            ) : filtered.map(({ it, match }) => (
              <SearchResultRowPlus key={it.id} item={it} query={query} match={match}
                onClick={() => open(it)} chipStyle={chipStyle}/>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

const SearchSection = ({ label, children }) => (
  <>
    <div style={{
      padding: '14px 18px 6px',
      fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
      letterSpacing: '0.08em', textTransform: 'uppercase',
      color: 'var(--color-fg-secondary)',
    }}>{label}</div>
    {children}
  </>
);

const FilterChip = ({ label, icon, active, onClick }) => (
  <button onClick={onClick} style={{
    display: 'inline-flex', alignItems: 'center', gap: 5,
    padding: '5px 10px', borderRadius: 999,
    background: active ? 'var(--color-fg-emphasis)' : 'var(--color-surface-sunken)',
    color: active ? 'var(--color-background)' : 'var(--color-fg-primary)',
    border: '1px solid ' + (active ? 'var(--color-fg-emphasis)' : 'var(--color-border)'),
    cursor: 'pointer', fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
    transition: 'all var(--dur-fast) var(--ease-out)',
  }}>
    <Icon name={icon} size={11}/> {label}
  </button>
);

const MATCH_LABEL = {
  name:     'name',
  username: 'username',
  site:     'site',
  notes:    'notes',
  folder:   'folder',
};

const SearchResultRowPlus = ({ item, query, match, onClick, chipStyle }) => {
  const initials = item.name.replace(/[^a-zA-Z]/g, '').slice(0, 2).toUpperCase() || '··';
  return (
    <div onClick={onClick} style={{
      padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'center',
      borderBottom: '1px solid var(--color-divider)', cursor: 'pointer',
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: 8,
        background: item.rage ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
        border: '1px solid var(--color-border)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 13,
        color: item.rage ? 'var(--color-accent)' : 'var(--color-fg-secondary)',
        flexShrink: 0,
      }}>
        {item.kind === 'card' ? <Icon name="creditCard" size={16}/>
          : item.kind === 'note' ? <Icon name="paper" size={16}/>
          : item.kind === 'identity' ? <Icon name="user" size={16}/>
          : item.kind === 'ssh' ? <Icon name="terminal" size={16}/>
          : initials}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15,
            color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            flex: 1, minWidth: 0,
          }}>{highlightMatchPlus(item.name, query)}</div>
          {match && match !== 'name' && (
            <span style={{
              flexShrink: 0,
              fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
              letterSpacing: '0.04em', textTransform: 'uppercase',
              color: 'var(--color-accent)',
              background: 'var(--color-tile)',
              borderRadius: 999, padding: '1px 7px',
            }}>matched {MATCH_LABEL[match]}</span>
          )}
        </div>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1,
        }}>
          {match === 'notes' && item.notes ? <em>{snippet(item.notes, query)}</em>
            : match === 'folder' ? <>in {highlightMatchPlus(item.folder, query)}</>
            : highlightMatchPlus((item.username || '') + (item.site ? ' · ' + item.site : ''), query)}
        </div>
      </div>
      {item.rage && <RageChip recipients={item.recipients}/>}
    </div>
  );
};

const PlainResultRow = ({ item, onClick, hint, hintIcon }) => {
  const initials = item.name.replace(/[^a-zA-Z]/g, '').slice(0, 2).toUpperCase() || '··';
  return (
    <div onClick={onClick} style={{
      padding: '11px 16px', display: 'flex', gap: 12, alignItems: 'center',
      borderBottom: '1px solid var(--color-divider)', cursor: 'pointer',
    }}>
      <div style={{
        width: 32, height: 32, borderRadius: 8,
        background: item.rage ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
        border: '1px solid var(--color-border)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 12,
        color: item.rage ? 'var(--color-accent)' : 'var(--color-fg-secondary)',
        flexShrink: 0,
      }}>{initials}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5,
          color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{item.name}</div>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{item.username || ''}{item.site ? ' · ' + item.site : ''}</div>
      </div>
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        fontFamily: 'var(--font-sans)', fontSize: 10.5, fontWeight: 600,
        letterSpacing: '0.04em', textTransform: 'uppercase',
        color: 'var(--color-fg-secondary)',
      }}>
        {hintIcon && <Icon name={hintIcon} size={10}/>}
        {hint}
      </span>
    </div>
  );
};

const highlightMatchPlus = (text, q) => {
  if (!q || !text) return text;
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return text;
  return (
    <>
      {text.slice(0, i)}
      <mark style={{
        background: 'var(--color-tile)', color: 'var(--color-accent)',
        padding: '0 1px', borderRadius: 2, fontWeight: 700,
      }}>{text.slice(i, i + q.length)}</mark>
      {text.slice(i + q.length)}
    </>
  );
};

const snippet = (notes, q) => {
  if (!q) return notes.slice(0, 60);
  const i = notes.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return notes.slice(0, 60);
  const start = Math.max(0, i - 12);
  const end = Math.min(notes.length, i + q.length + 30);
  const s = (start > 0 ? '...' : '') + notes.slice(start, end) + (end < notes.length ? '...' : '');
  return s;
};

const URL_RE = /(https?:\/\/[^\s)]+|[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s)]*)?)/gi;

const linkifyNotes = (text) => {
  if (!text) return text;
  const parts = [];
  let last = 0;
  text.replace(URL_RE, (m, _g1, idx) => {
    if (idx > last) parts.push(text.slice(last, idx));
    parts.push(
      <span key={idx} style={{
        color: 'var(--color-accent)',
        textDecoration: 'underline',
        textDecorationColor: 'var(--color-accent-soft, var(--color-accent))',
        textUnderlineOffset: 2,
        cursor: 'pointer',
      }}>{m}</span>
    );
    last = idx + m.length;
  });
  if (last < text.length) parts.push(text.slice(last));
  return parts;
};

const ConnectivityBanner = ({ state, onRetry }) => {
  if (state === 'offline') {
    return (
      <StatusMessage
        tone="warning" icon="cloudOff"
        title="Offline -- vault is read from cache"
        style={{ margin: '0 14px 10px' }}
      >
        Reveal & autofill still work -- your YubiKey holds the key. Edits queue until you reconnect.
      </StatusMessage>
    );
  }
  if (state === 'save-failed') {
    return (
      <StatusMessage
        tone="danger"
        title="2 changes haven't synced"
        action={{ label: 'Retry', onClick: onRetry }}
        style={{ margin: '0 14px 10px' }}
      >
        <em>GitHub (prod)</em> · <em>AWS root</em> -- server returned 503. Local copy is intact.
      </StatusMessage>
    );
  }
  return null;
};

const VaultWithBanners = ({ connectivity, onRetry, ...vaultProps }) => (
  <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
    <VaultScreen {...vaultProps}/>
    {connectivity !== 'online' && (
      <div style={{
        position: 'absolute', left: 0, right: 0, bottom: 0,
        padding: '10px 0 14px',
        background: 'linear-gradient(to top, var(--color-background) 60%, transparent)',
        pointerEvents: 'none',
      }}>
        <div style={{ pointerEvents: 'auto' }}>
          <ConnectivityBanner state={connectivity} onRetry={onRetry}/>
        </div>
      </div>
    )}
  </div>
);

const PrewarmStrip = ({ visible }) => {
  if (!visible) return null;
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '7px 12px', marginBottom: 8,
      background: 'var(--color-surface-sunken)',
      border: '1px solid var(--color-border)',
      borderRadius: 8,
      fontFamily: 'var(--font-sans)', fontSize: 11.5,
      color: 'var(--color-fg-secondary)',
    }}>
      <span style={{
        display: 'inline-block', width: 6, height: 6, borderRadius: 3,
        background: 'var(--color-accent)',
        animation: 'prewarm-pulse 1.2s var(--ease-out) infinite',
      }}/>
      Warming up NFC reader...
    </div>
  );
};

window.SearchScreenPlus = SearchScreenPlus;
window.linkifyNotes = linkifyNotes;
window.ConnectivityBanner = ConnectivityBanner;
window.VaultWithBanners = VaultWithBanners;
window.PrewarmStrip = PrewarmStrip;
