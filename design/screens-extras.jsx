const { useState: useStateE, useEffect: useEffectE, useMemo: useMemoE, useRef: useRefE } = React;

const LockScreen = ({ onUnlock, toast }) => {
  const [phase, setPhase] = useStateE('idle');
  const [pw, setPw] = useStateE('');

  const tryBiometric = () => {
    setPhase('scanning');
    setTimeout(() => setPhase('success'), 1100);
    setTimeout(() => onUnlock?.(), 1700);
  };

  const submitPassword = () => {
    if (!pw) return;
    setPhase('success');
    setTimeout(() => onUnlock?.(), 600);
  };

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column',
      background: 'var(--color-background)', position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ padding: '40px 24px 0', textAlign: 'center' }}>
        <div style={{
          width: 56, height: 56, borderRadius: 14, background: 'var(--color-fg-emphasis)',
          color: 'var(--color-background)', display: 'inline-flex', alignItems: 'center',
          justifyContent: 'center', marginBottom: 18,
        }}>
          <Icon name="chain" size={28}/>
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 28, lineHeight: 1.1, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em' }}>
          RageDroid
        </div>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-secondary)', marginTop: 6 }}>
          maya@feldspar.fm · vault.feldspar.fm
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '0 24px' }}>
        {phase !== 'password' && (
          <>
            <button onClick={tryBiometric} disabled={phase !== 'idle'} style={{
              position: 'relative', width: 132, height: 132, borderRadius: 66,
              background: phase === 'success' ? 'var(--color-success)' : 'var(--color-tile)',
              border: 'none', cursor: phase === 'idle' ? 'pointer' : 'default',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'background var(--dur-base) var(--ease-out)',
              color: phase === 'success' ? '#FAF6EE' : 'var(--color-accent)',
            }}>
              {phase === 'scanning' && [0, 0.5].map(d => (
                <span key={d} style={{
                  position: 'absolute', inset: -10, borderRadius: '50%',
                  border: '2px solid var(--color-accent)', opacity: 0.3,
                  animation: `ripple 1.6s var(--ease-out) infinite ${d}s`,
                }}/>
              ))}
              <Icon name={phase === 'success' ? 'check' : 'fingerprint'} size={56}/>
            </button>

            <div style={{
              fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18,
              color: 'var(--color-fg-emphasis)', marginTop: 28, textAlign: 'center',
            }}>
              {phase === 'idle'     && 'Touch the sensor to unlock'}
              {phase === 'scanning' && 'Authenticating...'}
              {phase === 'success'  && 'Welcome back'}
            </div>
            <div style={{
              fontFamily: 'var(--font-sans)', fontSize: 12.5,
              color: 'var(--color-fg-secondary)', marginTop: 8, textAlign: 'center',
              maxWidth: 280, lineHeight: 1.5,
            }}>
              Unlocks the vault. Each protected item still needs its own tap.
            </div>
          </>
        )}

        {phase === 'password' && (
          <div style={{ width: '100%', maxWidth: 320 }}>
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <div style={{
                width: 48, height: 48, borderRadius: 24, background: 'var(--color-tile)',
                color: 'var(--color-accent)', display: 'inline-flex', alignItems: 'center',
                justifyContent: 'center', marginBottom: 12,
              }}>
                <Icon name="lock" size={22}/>
              </div>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 20, color: 'var(--color-fg-emphasis)' }}>
                Master password
              </div>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)', marginTop: 6 }}>
                Argon2id KDF, run on this device.
              </div>
            </div>
            <TextInput
              value={pw} onChange={setPw} type="password"
              placeholder="••••••••••••"
            />
            <div style={{ marginTop: 14 }}>
              <Button fullWidth onClick={submitPassword} disabled={!pw} icon="arrowRight">Unlock</Button>
            </div>
          </div>
        )}
      </div>

      <div style={{ padding: '0 24px 32px', textAlign: 'center' }}>
        {phase !== 'password' ? (
          <button onClick={() => setPhase('password')} style={{
            background: 'transparent', border: 'none', cursor: 'pointer', padding: '8px 12px',
            fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 600,
            color: 'var(--color-fg-secondary)',
          }}>Use master password instead</button>
        ) : (
          <button onClick={() => { setPhase('idle'); setPw(''); }} style={{
            background: 'transparent', border: 'none', cursor: 'pointer', padding: '8px 12px',
            fontFamily: 'var(--font-sans)', fontSize: 13, fontWeight: 600,
            color: 'var(--color-fg-secondary)',
          }}>Use fingerprint instead</button>
        )}
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 10.5, color: 'var(--color-fg-secondary)',
          marginTop: 12, opacity: 0.7,
        }}>
          Last sync: 11 minutes ago · 36 items
        </div>
      </div>
    </div>
  );
};

const RecipientDetail = ({ recipient, onBack, toast }) => {
  const [revokeOpen, setRevokeOpen] = useStateE(false);
  const [pwOpen, setPwOpen] = useStateE(false);
  const r = recipient;

  const items = VAULT.filter(i => i.rage && i.recipients?.includes(r.id));
  const totalProtected = VAULT.filter(i => i.rage).length;

  const activity = ACTIVITY.filter(a => a.recipient === r.id).slice(0, 4);

  const subtitleByKind = {
    yubikey:  'YubiKey · PIV X25519',
    fido2:    'FIDO2 hmac-secret',
    strongbox:'Android StrongBox',
    recovery: 'Paper age identity',
  }[r.kind];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Recipient" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto' }}>

        <div style={{ padding: '4px 18px 18px' }}>
          <div style={{
            display: 'flex', gap: 14, alignItems: 'center',
          }}>
            <div style={{
              width: 56, height: 56, borderRadius: 12, background: 'var(--color-tile)',
              color: 'var(--color-accent)', display: 'flex', alignItems: 'center',
              justifyContent: 'center', flexShrink: 0,
            }}>
              <Icon name={recipientKindIcon(r.kind)} size={26}/>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.01em', lineHeight: 1.1 }}>
                {r.name}
              </div>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginTop: 6 }}>
                {subtitleByKind}
              </div>
            </div>
          </div>
        </div>

        <div style={{ padding: '0 18px 18px' }}>
          <div style={{
            background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
            borderRadius: 12, padding: '14px 16px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)' }}>Coverage</span>
              <span style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-secondary)' }}>
                <span style={{ fontWeight: 700, color: 'var(--color-fg-emphasis)', fontSize: 16 }}>{r.coverage}</span> of {totalProtected} protected items
              </span>
            </div>
            <div style={{ height: 4, background: 'var(--color-surface-sunken)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ width: `${(r.coverage / Math.max(1, totalProtected)) * 100}%`, height: '100%', background: 'var(--color-accent)' }}/>
            </div>
            {r.coverage === totalProtected && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-success)', marginTop: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Icon name="check" size={12}/> This recipient can decrypt every protected item.
              </div>
            )}
            {r.coverage === 0 && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-warning)', marginTop: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Icon name="info" size={12}/> Enrolled but never written to a cipher. Re-encrypt to add.
              </div>
            )}
          </div>
        </div>

        <div style={{ padding: '0 18px 8px' }}>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginBottom: 8 }}>Identity</div>
        </div>
        <div style={{ background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}>
          {[
            { label: 'Serial',      value: r.serial },
            r.slot     && { label: 'PIV slot',    value: r.slot },
            r.firmware && { label: 'Firmware',    value: r.firmware },
            { label: 'Public key',  value: r.fingerprint, mono: true },
            { label: 'Enrolled',    value: r.enrolled },
            { label: 'Last used',   value: r.lastUsed },
          ].filter(Boolean).map((row, i, arr) => (
            <div key={row.label} style={{
              padding: '11px 18px', display: 'flex',
              flexDirection: row.mono ? 'column' : 'row',
              gap: row.mono ? 4 : 12, alignItems: row.mono ? 'flex-start' : 'center',
              justifyContent: 'space-between',
              borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
            }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 12.5, fontWeight: 600, color: 'var(--color-fg-secondary)', letterSpacing: '0.04em', textTransform: 'uppercase', flexShrink: 0 }}>{row.label}</span>
              {row.mono ? (
                <Mono size={11} style={{ color: 'var(--color-fg-primary)', wordBreak: 'break-all' }}>{row.value}</Mono>
              ) : (
                <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13.5, color: 'var(--color-fg-primary)', textAlign: 'right' }}>{row.value}</span>
              )}
            </div>
          ))}
        </div>

        <div style={{ padding: '20px 18px 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
            <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)' }}>Can unlock</div>
            {items.length > 6 && (
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)' }}>{items.length} items</span>
            )}
          </div>
        </div>
        <div style={{ background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}>
          {items.length === 0 && (
            <div style={{ padding: '18px 18px', fontFamily: 'var(--font-serif)', fontStyle: 'italic', fontSize: 13.5, color: 'var(--color-fg-secondary)' }}>
              No ciphers list this recipient yet. Add it during the next re-encrypt.
            </div>
          )}
          {items.slice(0, 6).map((it, i) => (
            <div key={it.id} style={{
              padding: '10px 18px', display: 'flex', alignItems: 'center', gap: 12,
              borderBottom: i < Math.min(items.length, 6) - 1 ? '1px solid var(--color-divider)' : 'none',
            }}>
              <RageChip style="rule"/>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.name}</div>
                <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)' }}>
                  {it.folder} · {it.recipients.length} recipients
                </div>
              </div>
              {it.recipients[0] === r.id && (
                <span title="This recipient is the only path on this cipher" style={{
                  fontFamily: 'var(--font-sans)', fontSize: 9.5, fontWeight: 600,
                  letterSpacing: '0.06em', textTransform: 'uppercase',
                  color: 'var(--color-warning)', border: '1px solid var(--color-warning)',
                  padding: '1px 5px', borderRadius: 3,
                }}>Sole</span>
              )}
            </div>
          ))}
          {items.length > 6 && (
            <div style={{ padding: '10px 18px', fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)', textAlign: 'center' }}>
              + {items.length - 6} more
            </div>
          )}
        </div>

        {activity.length > 0 && (
          <>
            <div style={{ padding: '20px 18px 0' }}>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginBottom: 8 }}>Recent activity</div>
            </div>
            <div style={{ background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}>
              {activity.map((a, i) => (
                <div key={a.id} style={{
                  padding: '10px 18px', display: 'flex', alignItems: 'center', gap: 12,
                  borderBottom: i < activity.length - 1 ? '1px solid var(--color-divider)' : 'none',
                }}>
                  <ActivityIcon action={a.action}/>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span style={{ fontWeight: 600 }}>{ACTION_LABEL[a.action] || a.action}</span> · {a.item}
                    </div>
                    <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)' }}>{a.ts}</div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        <div style={{ padding: '24px 18px 32px' }}>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-danger-strong)', marginBottom: 10 }}>Danger zone</div>
          <Button variant="secondary" fullWidth onClick={() => setRevokeOpen(true)} style={{ color: 'var(--color-danger-strong)', borderColor: 'var(--color-border)' }}>
            Revoke this recipient
          </Button>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 10, lineHeight: 1.5 }}>
            Removes this stanza from every cipher. Requires a tap from a different recipient on each one. Cannot be undone for this device -- only re-enrolled.
          </div>
        </div>
      </div>

      <Sheet open={revokeOpen} onClose={() => setRevokeOpen(false)} title={`Revoke ${r.name}?`}>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55, color: 'var(--color-fg-primary)', marginBottom: 12 }}>
          RageDroid will re-encrypt {r.coverage} item{r.coverage === 1 ? '' : 's'} with this stanza removed. Each re-encrypt requires one tap from a remaining recipient.
        </div>
        {r.coverage > 0 && VAULT.filter(i => i.rage && i.recipients?.[0] === r.id && i.recipients.length === 1).length > 0 && (
          <StatusMessage tone="warning" style={{ marginBottom: 12 }}>
            Some ciphers list this recipient as the only path. Revoking will lock you out of those.
          </StatusMessage>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="ghost" fullWidth onClick={() => setRevokeOpen(false)}>Keep</Button>
          <Button variant="danger" fullWidth onClick={() => { setRevokeOpen(false); setPwOpen(true); }}>Revoke</Button>
        </div>
      </Sheet>

      <MasterPasswordConfirm
        open={pwOpen}
        onClose={() => setPwOpen(false)}
        title={`Revoke ${r.name}?`}
        body={`RageDroid will re-encrypt ${r.coverage} item${r.coverage === 1 ? '' : 's'} without ${r.name}. Confirm with your master password to continue.`}
        action="Revoke recipient"
        onConfirm={() => { setPwOpen(false); toast?.('Revoke flow not implemented in prototype'); }}
      />
    </div>
  );
};

const SearchScreen = ({ onBack, onOpen, chipStyle = 'pill' }) => {
  const [query, setQuery] = useStateE('');
  const [protectedOnly, setProtectedOnly] = useStateE(false);
  const [recipientId, setRecipientId] = useStateE(null);
  const [folder, setFolder] = useStateE(null);
  const inputRef = useRefE(null);

  useEffectE(() => {
    inputRef.current?.focus();
  }, []);

  const folders = ['Work', 'Personal', 'Infrastructure'];

  const allItems = useMemoE(() => [
    ...VAULT,
    ...(typeof ITEMS_BY_KIND !== 'undefined' ? ITEMS_BY_KIND.map(i => ({
      ...i,
      username: i.kind === 'card' ? i.cardholder
              : i.kind === 'identity' ? i.fullName
              : i.kind === 'ssh' ? i.keyType
              : 'Secure note',
      site: '',
    })) : []),
  ].filter(it => !isInternalItem(it)), []);

  const filtered = allItems.filter(it => {
    if (protectedOnly && !it.rage) return false;
    if (recipientId && !(it.recipients || []).includes(recipientId)) return false;
    if (folder && it.folder !== folder) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = [it.name, it.username, it.site, it.notes, it.folder].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const activeFilters = [protectedOnly, recipientId, folder].filter(Boolean).length;

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
          <input ref={inputRef} value={query} onChange={e => setQuery(e.target.value)} placeholder="Search vault, recipients, notes"
            style={{
              flex: 1, border: 'none', outline: 'none', background: 'transparent',
              fontFamily: 'var(--font-sans)', fontSize: 14, color: 'var(--color-fg-primary)',
            }}/>
          {query && <button onClick={() => setQuery('')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--color-fg-secondary)', padding: 0, display: 'flex' }}><Icon name="x" size={16}/></button>}
        </div>
      </div>

      <div style={{ padding: '4px 14px 10px', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <FilterChip
          label="Protected only"
          icon="chain"
          active={protectedOnly}
          onClick={() => setProtectedOnly(v => !v)}
        />
        <FilterChip
          label={recipientId ? RECIPIENTS.find(r => r.id === recipientId)?.name || 'Recipient' : 'Recipient'}
          icon="key"
          active={!!recipientId}
          onClick={() => {
            const order = [null, 'yk-primary', 'yk-backup', 'strongbox', 'recovery'];
            setRecipientId(order[(order.indexOf(recipientId) + 1) % order.length]);
          }}
        />
        <FilterChip
          label={folder || 'Folder'}
          icon="folder"
          active={!!folder}
          onClick={() => {
            const order = [null, ...folders];
            setFolder(order[(order.indexOf(folder) + 1) % order.length]);
          }}
        />
        {activeFilters > 0 && (
          <button onClick={() => { setProtectedOnly(false); setRecipientId(null); setFolder(null); }} style={{
            background: 'transparent', border: 'none', cursor: 'pointer', padding: '5px 8px',
            fontFamily: 'var(--font-sans)', fontSize: 11.5, fontWeight: 600,
            color: 'var(--color-fg-secondary)',
          }}>Clear</button>
        )}
      </div>

      {(query || activeFilters > 0) && (
        <div style={{
          padding: '0 18px 8px',
          fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
          letterSpacing: '0.06em', textTransform: 'uppercase',
          color: 'var(--color-fg-secondary)',
        }}>
          {filtered.length} {filtered.length === 1 ? 'result' : 'results'}
        </div>
      )}

      <div style={{ flex: 1, overflowY: 'auto', borderTop: '1px solid var(--color-divider)' }}>
        {filtered.length === 0 ? (
          <div style={{
            padding: '60px 24px 0', textAlign: 'center',
          }}>
            <div style={{
              width: 48, height: 48, borderRadius: 24, background: 'var(--color-tile)',
              color: 'var(--color-fg-secondary)', display: 'inline-flex', alignItems: 'center',
              justifyContent: 'center', marginBottom: 14,
            }}><Icon name="search" size={22}/></div>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, fontStyle: 'italic', color: 'var(--color-fg-secondary)' }}>
              {query ? 'Nothing matches that search.' : 'Type to search, or pick a filter.'}
            </div>
          </div>
        ) : filtered.map(it => (
          <SearchResultRow key={it.id} item={it} query={query} onClick={() => onOpen(it)} chipStyle={chipStyle}/>
        ))}
      </div>
    </div>
  );
};

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

const SearchResultRow = ({ item, query, onClick, chipStyle }) => {
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
        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15,
          color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{highlightMatch(item.name, query)}</div>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1,
        }}>{highlightMatch((item.username || '') + (item.site ? ' · ' + item.site : ''), query)}</div>
      </div>
      {item.rage && <RageChip recipients={item.recipients}/>}
    </div>
  );
};

const highlightMatch = (text, q) => {
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

const ACTION_LABEL = {
  autofill: 'Autofilled',
  copy:     'Copied',
  reveal:   'Revealed',
  totp:     'TOTP read',
  enroll:   'Enrolled',
  rotate:   'Re-encrypted',
  failed:   'Failed',
};

const ACTION_COLOR = {
  autofill: 'var(--color-accent)',
  copy:     'var(--color-accent)',
  reveal:   'var(--color-warning)',
  totp:     'var(--color-info)',
  enroll:   'var(--color-success)',
  rotate:   'var(--color-success)',
  failed:   'var(--color-danger)',
};

const ACTION_ICON = {
  autofill: 'arrowRight',
  copy:     'copy',
  reveal:   'eye',
  totp:     'clock',
  enroll:   'plus',
  rotate:   'refresh',
  failed:   'x',
};

const ActivityIcon = ({ action }) => (
  <div style={{
    width: 28, height: 28, borderRadius: 14, background: 'var(--color-tile)',
    color: ACTION_COLOR[action] || 'var(--color-fg-secondary)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
  }}>
    <Icon name={ACTION_ICON[action] || 'info'} size={14}/>
  </div>
);

const AuditLogScreen = ({ onBack }) => {
  const [filter, setFilter] = useStateE('all');
  const filtered = ACTIVITY.filter(a => {
    if (filter === 'all') return true;
    if (filter === 'unlocks') return ['autofill', 'copy', 'reveal', 'totp'].includes(a.action);
    if (filter === 'failures') return a.action === 'failed';
    if (filter === 'admin') return ['enroll', 'rotate'].includes(a.action);
  });

  const groups = [];
  let currentBucket = null;
  filtered.forEach(a => {
    const bucket = bucketFor(a.ts);
    if (bucket !== currentBucket) {
      groups.push({ label: bucket, entries: [] });
      currentBucket = bucket;
    }
    groups[groups.length - 1].entries.push(a);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Activity" subtitle="Local · this device" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>

      <div style={{ padding: '0 14px 8px', display: 'flex', gap: 6, overflowX: 'auto' }}>
        {[
          { id: 'all',     label: 'All' },
          { id: 'unlocks', label: 'Unlocks' },
          { id: 'failures',label: 'Failures' },
          { id: 'admin',   label: 'Enrol & rotate' },
        ].map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            padding: '5px 12px', borderRadius: 999,
            background: filter === f.id ? 'var(--color-fg-emphasis)' : 'var(--color-surface-sunken)',
            color: filter === f.id ? 'var(--color-background)' : 'var(--color-fg-primary)',
            border: '1px solid ' + (filter === f.id ? 'var(--color-fg-emphasis)' : 'var(--color-border)'),
            cursor: 'pointer', fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
            whiteSpace: 'nowrap',
          }}>{f.label}</button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', borderTop: '1px solid var(--color-divider)' }}>
        {groups.length === 0 && (
          <div style={{
            padding: '60px 24px', textAlign: 'center',
            fontFamily: 'var(--font-serif)', fontStyle: 'italic', fontSize: 14,
            color: 'var(--color-fg-secondary)',
          }}>No matching activity.</div>
        )}
        {groups.map(g => (
          <div key={g.label}>
            <div style={{
              padding: '12px 18px 6px',
              fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
              letterSpacing: '0.08em', textTransform: 'uppercase',
              color: 'var(--color-fg-secondary)',
              background: 'var(--color-background)',
              position: 'sticky', top: 0,
            }}>{g.label}</div>
            {g.entries.map(a => (
              <ActivityRow key={a.id} a={a}/>
            ))}
          </div>
        ))}

        <div style={{
          padding: '20px 24px 32px', textAlign: 'center',
          fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
          fontStyle: 'italic', lineHeight: 1.5,
        }}>
          Activity is stored on this device only. Nothing leaves the phone.
        </div>
      </div>
    </div>
  );
};

const ActivityRow = ({ a }) => {
  const recipient = RECIPIENTS.find(r => r.id === a.recipient);
  return (
    <div style={{
      padding: '12px 18px', display: 'flex', gap: 12, alignItems: 'flex-start',
      borderBottom: '1px solid var(--color-divider)',
    }}>
      <ActivityIcon action={a.action}/>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{ACTION_LABEL[a.action] || a.action}</span>
          {a.cleared && <span style={{ fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)' }}>· cleared</span>}
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-primary)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.item}</div>
        {a.reason && (
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: a.action === 'failed' ? 'var(--color-danger)' : 'var(--color-fg-secondary)', marginTop: 2 }}>{a.reason}</div>
        )}
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)',
          marginTop: 4, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
        }}>
          <span>{a.when}</span>
          {recipient && <>· <RecipientPip kind={recipient.kind} size={7}/> {recipient.name}</>}
          {a.site && <>· {a.site}</>}
        </div>
      </div>
    </div>
  );
};

const bucketFor = (ts) => {
  const t = ts.toLowerCase();
  if (t.includes('just now') || t.includes('minute') || t.includes('hour')) return 'Today';
  if (t.includes('yesterday')) return 'Yesterday';
  return 'Earlier';
};

const BackfillWizard = ({ item, onBack, onDone, toast }) => {
  const [step, setStep] = useStateE(0);
  const [picked, setPicked] = useStateE(['yk-primary', 'yk-backup', 'recovery']);
  const [encryptPhase, setEncryptPhase] = useStateE('idle');

  const togglePick = (id) => setPicked(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);

  const Step = ({ children }) => (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '6px 18px 18px' }}>{children}</div>
  );

  if (step === 0) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Protect this item" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <Step>
        <div style={{
          display: 'flex', gap: 12, padding: '12px 14px', marginBottom: 18,
          background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
          borderRadius: 10, alignItems: 'center',
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, background: 'var(--color-surface-elevated)',
            color: 'var(--color-fg-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Icon name="lock" size={18}/>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item?.name || 'Item'}</div>
            <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)' }}>Currently unprotected · Bitwarden only</div>
          </div>
        </div>

        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2,
          color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 12,
        }}>Wrap this secret in a rage envelope.</div>
        <div style={{
          fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.5,
          color: 'var(--color-fg-primary)', marginBottom: 14,
        }}>
          We'll generate a fresh file key, encrypt the existing password to it, then write age stanzas for each recipient you pick. The Bitwarden cipher's password field is replaced with a placeholder; the ciphertext lives in the <em>rage:v1</em> custom field.
        </div>
        <StatusMessage tone="info">
          The original plaintext is zeroized after re-encrypt. Old Bitwarden history rows for this cipher remain accessible to anyone with your master password -- wipe them from the web vault if that matters.
        </StatusMessage>

        <div style={{ flex: 1 }}/>
        <Button fullWidth icon="arrowRight" onClick={() => setStep(1)}>Pick recipients</Button>
      </Step>
    </div>
  );

  if (step === 1) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Recipients" subtitle="Step 2 of 3" left={<IconBtn name="arrowLeft" onClick={() => setStep(0)}/>}/>
      <Step>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.5, color: 'var(--color-fg-secondary)', marginBottom: 14 }}>
          Any one of these can decrypt this item. Pick at least two so a lost device isn't a lockout.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {RECIPIENTS.map(r => {
            const on = picked.includes(r.id);
            return (
              <div key={r.id} onClick={() => togglePick(r.id)} style={{
                padding: '12px 14px', borderRadius: 10, cursor: 'pointer',
                background: on ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
                border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                display: 'flex', gap: 12, alignItems: 'center',
                transition: 'all var(--dur-fast) var(--ease-out)',
              }}>
                <div style={{
                  width: 22, height: 22, borderRadius: 11,
                  background: on ? 'var(--color-accent)' : 'var(--color-surface-sunken)',
                  border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                  color: '#FAF6EE', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  {on && <Icon name="check" size={13}/>}
                </div>
                <div style={{
                  width: 32, height: 32, borderRadius: 7, background: 'var(--color-surface-sunken)',
                  color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}><Icon name={recipientKindIcon(r.kind)} size={16}/></div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                  <Mono size={10.5} style={{ color: 'var(--color-fg-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{r.fingerprint}</Mono>
                </div>
              </div>
            );
          })}
        </div>

        {picked.length < 2 && (
          <StatusMessage tone="warning" style={{ marginTop: 14 }}>
            Single recipient = single point of failure. We strongly recommend at least two.
          </StatusMessage>
        )}

        <div style={{ flex: 1 }}/>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="ghost" onClick={() => setStep(0)}>Back</Button>
          <Button fullWidth icon="tap" onClick={() => { setStep(2); setEncryptPhase('idle'); }} disabled={picked.length === 0}>
            Tap to authorize ({picked.length})
          </Button>
        </div>
      </Step>
    </div>
  );

  const fire = () => {
    setEncryptPhase('tap');
    setTimeout(() => setEncryptPhase('done'), 1800);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Authorize" subtitle="Step 3 of 3" left={<IconBtn name="arrowLeft" onClick={() => setStep(1)}/>}/>
      <Step>
        <div style={{
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 12, padding: 24, textAlign: 'center', marginBottom: 14,
        }}>
          <div style={{ height: 110, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
            {encryptPhase === 'tap' && [0, 0.5].map(d => (
              <span key={d} style={{
                position: 'absolute', width: 100, height: 100, borderRadius: '50%',
                border: '2px solid var(--color-accent)', opacity: 0.25,
                animation: `ripple 1.6s var(--ease-out) infinite ${d}s`,
              }}/>
            ))}
            <div style={{
              width: 70, height: 70, borderRadius: 35,
              background: encryptPhase === 'done' ? 'var(--color-success)' : 'var(--color-tile)',
              color: encryptPhase === 'done' ? '#FAF6EE' : 'var(--color-accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1,
              transition: 'all var(--dur-base) var(--ease-out)',
            }}>
              <Icon name={encryptPhase === 'done' ? 'check' : 'tap'} size={32}/>
            </div>
          </div>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18, color: 'var(--color-fg-emphasis)', marginTop: 4 }}>
            {encryptPhase === 'idle' && 'Tap any one recipient'}
            {encryptPhase === 'tap'  && 'Re-encrypting...'}
            {encryptPhase === 'done' && 'Item is now protected'}
          </div>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-secondary)', marginTop: 8, lineHeight: 1.5 }}>
            {encryptPhase === 'idle' && 'One tap from any recipient is enough to write the new ciphertext.'}
            {encryptPhase === 'tap'  && `Wrapping file key for ${picked.length} recipient${picked.length === 1 ? '' : 's'}...`}
            {encryptPhase === 'done' && `${picked.length} stanza${picked.length === 1 ? '' : 's'} written to the rage:v1 custom field.`}
          </div>
        </div>

        <div style={{ flex: 1 }}/>
        {encryptPhase === 'idle' && <Button fullWidth icon="tap" onClick={fire}>Begin</Button>}
        {encryptPhase === 'tap'  && <Button fullWidth disabled>Encrypting...</Button>}
        {encryptPhase === 'done' && <Button fullWidth icon="check" onClick={() => { toast?.('Item protected', { kind: 'success' }); onDone?.(); }}>Done</Button>}
      </Step>
    </div>
  );
};

const PaperRecoveryWizard = ({ onBack, onDone, toast }) => {
  const [step, setStep] = useStateE(0);
  const phrase = RECOVERY_PHRASE;

  const [challenge] = useStateE(() => {
    const idxs = [];
    while (idxs.length < 3) {
      const r = Math.floor(Math.random() * phrase.length);
      if (!idxs.includes(r)) idxs.push(r);
    }
    return idxs.sort((a, b) => a - b);
  });
  const [answers, setAnswers] = useStateE({});

  const allCorrect = challenge.every(i => (answers[i] || '').toLowerCase().trim() === phrase[i]);

  if (step === 0) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Paper recovery" subtitle="Step 1 of 2" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 18px 18px' }}>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 10 }}>
          Write these 24 words down.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55, color: 'var(--color-fg-primary)', marginBottom: 16 }}>
          This phrase is your last-resort recovery identity. Anyone with all 24 words can decrypt every protected item. <em>Never type it into a screen.</em>
        </div>

        <div style={{
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 12, padding: '16px 14px', marginBottom: 14,
        }}>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', columnGap: 14, rowGap: 8,
          }}>
            {phrase.map((w, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'baseline', gap: 8,
              }}>
                <span style={{
                  fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 11,
                  color: 'var(--color-fg-secondary)', minWidth: 22, textAlign: 'right',
                  fontVariantNumeric: 'tabular-nums',
                }}>{(i + 1).toString().padStart(2, '0')}</span>
                <span style={{
                  fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 14,
                  color: 'var(--color-fg-emphasis)', fontWeight: 500,
                }}>{w}</span>
              </div>
            ))}
          </div>
        </div>

        <StatusMessage tone="danger" title="Mockup -- these are not recovery words" style={{ marginBottom: 14 }}>
          This prototype renders placeholder text. The shipped popup renders the phrase
          <code> RagewardenVault.enrollRecovery()</code> actually generated.
        </StatusMessage>

        <StatusMessage tone="warning" style={{ marginBottom: 14 }}>
          Don't screenshot. Don't type into a password manager. Print, write by hand, or split across two safes.
        </StatusMessage>

        <Button variant="secondary" fullWidth icon="paper" onClick={() => toast?.('Print sheet -- not implemented in prototype')} style={{ marginBottom: 8 }}>
          Print recovery sheet
        </Button>
        <Button fullWidth icon="arrowRight" onClick={() => setStep(1)}>I've written them down</Button>
      </div>
    </div>
  );

  if (step === 1) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Confirm" subtitle="Step 2 of 2" left={<IconBtn name="arrowLeft" onClick={() => setStep(0)}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 18px 18px' }}>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 10 }}>
          Type 3 words to confirm.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55, color: 'var(--color-fg-secondary)', marginBottom: 16 }}>
          We'll only verify these three positions. We never see or store the rest.
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 14 }}>
          {challenge.map(i => {
            const ans = answers[i] || '';
            const correct = ans && ans.toLowerCase().trim() === phrase[i];
            const wrong = ans && !correct;
            return (
              <Field key={i} label={`Word #${i + 1}`}>
                <div style={{ position: 'relative' }}>
                  <TextInput
                    value={ans}
                    onChange={v => setAnswers(a => ({ ...a, [i]: v }))}
                    placeholder={`Word ${i + 1}`}
                    mono
                    style={{
                      borderColor: correct ? 'var(--color-success)' : wrong ? 'var(--color-danger)' : 'var(--color-border)',
                      paddingRight: 36,
                    }}
                  />
                  {correct && (
                    <Icon name="check" size={16} style={{
                      position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                      color: 'var(--color-success)',
                    }}/>
                  )}
                </div>
              </Field>
            );
          })}
        </div>

        <Button fullWidth icon="check" disabled={!allCorrect} onClick={() => setStep(2)}>
          {allCorrect ? 'Confirm recipient' : 'All three must match'}
        </Button>
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Recipient enrolled"/>
      <div style={{ flex: 1, padding: '24px 24px 18px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
          <div style={{
            width: 64, height: 64, borderRadius: 32, background: 'var(--color-success)', color: '#FAF6EE',
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 18,
          }}>
            <Icon name="check" size={32}/>
          </div>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 26, lineHeight: 1.15, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 12 }}>
            Recovery identity ready.
          </div>
          <div style={{ fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.5, color: 'var(--color-fg-secondary)', maxWidth: 320 }}>
            Stored offline as a paper backup. We'll add it as a stanza next time you re-encrypt -- no tap required, since the public key alone is enough to encrypt.
          </div>
        </div>
        <Button fullWidth icon="arrowRight" onClick={onDone}>Done</Button>
      </div>
    </div>
  );
};

/*
 * RecoveryPhraseScreen -- the only place a freshly generated recovery phrase is
 * ever shown. `result` comes straight from RagewardenVault.enrollRecovery();
 * the words render here and nowhere else -- never the console, never a toast.
 * (The App used to console.warn the phrase after enrolment; anything that
 * scrapes the console -- extensions, remote logging, a screen recording of
 * devtools -- would have carried the whole vault's last-resort key.)
 */
const RecoveryPhraseScreen = ({ result, onDone }) => {
  const words = String(result?.phrase || '').trim().split(/\s+/).filter(Boolean);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Your recovery phrase"/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 18px 18px' }}>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 10 }}>
          Write these {words.length} words down now.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55, color: 'var(--color-fg-primary)', marginBottom: 16 }}>
          This is the real phrase for the recovery identity that was just
          published. Leaving this screen destroys the only copy.
        </div>

        <div style={{
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 12, padding: '16px 14px', marginBottom: 14,
        }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', columnGap: 14, rowGap: 8 }}>
            {words.map((w, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                <span style={{
                  fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 11,
                  color: 'var(--color-fg-secondary)', minWidth: 22, textAlign: 'right',
                  fontVariantNumeric: 'tabular-nums',
                }}>{(i + 1).toString().padStart(2, '0')}</span>
                <span style={{
                  fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 14,
                  color: 'var(--color-fg-emphasis)', fontWeight: 500,
                }}>{w}</span>
              </div>
            ))}
          </div>
        </div>

        <StatusMessage tone="warning" style={{ marginBottom: 14 }}>
          Don't screenshot. Don't type into a password manager. Print, write by
          hand, or split across two safes.
        </StatusMessage>

        {result?.registryEntryId && (
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)', marginBottom: 14 }}>
            Registry entry: {result.registryEntryId}
          </div>
        )}

        <Button fullWidth icon="check" onClick={onDone}>I've written them down</Button>
      </div>
    </div>
  );
};

const KindDetailScreen = ({ item, onBack, toast }) => {
  const [revealedField, setRevealedField] = useStateE(null);

  const reveal = (field) => {
    setRevealedField(field);
    setTimeout(() => setRevealedField(null), 10000);
  };

  const Hero = () => (
    <div style={{ padding: '4px 18px 18px' }}>
      <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
        <div style={{
          width: 56, height: 56, borderRadius: 12, background: 'var(--color-tile)',
          color: 'var(--color-accent)', display: 'flex', alignItems: 'center',
          justifyContent: 'center', flexShrink: 0,
        }}>
          <Icon name={KIND_ICON[item.kind] || 'paper'} size={26}/>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.01em', lineHeight: 1.1 }}>{item.name}</span>
            {item.rage && <RageChip recipients={item.recipients}/>}
          </div>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)' }}>
            {KIND_LABEL[item.kind]} · {item.folder}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title={KIND_LABEL[item.kind]} left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <Hero/>

        <div style={{ padding: '0 18px 24px' }}>
          {item.kind === 'card'     && <CardBody     item={item} reveal={reveal} revealedField={revealedField} toast={toast}/>}
          {item.kind === 'note'     && <NoteBody     item={item} reveal={reveal} revealedField={revealedField} toast={toast}/>}
          {item.kind === 'identity' && <IdentityBody item={item} toast={toast}/>}
          {item.kind === 'ssh'      && <SshBody      item={item} reveal={reveal} revealedField={revealedField} toast={toast}/>}
        </div>
      </div>
    </div>
  );
};

const KIND_ICON  = { card: 'creditCard', note: 'paper', identity: 'user', ssh: 'terminal' };
const KIND_LABEL = { card: 'Card', note: 'Secure note', identity: 'Identity', ssh: 'SSH key' };

const CardBody = ({ item, reveal, revealedField, toast }) => {
  const last4 = item.number.replace(/\s/g, '').slice(-4);
  const masked = '•••• •••• •••• ' + last4;
  return (
    <>
      <div style={{
        background: 'var(--color-fg-emphasis)', color: 'var(--color-background)',
        borderRadius: 12, padding: '20px 18px', marginBottom: 16, position: 'relative', overflow: 'hidden',
      }}>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', opacity: 0.7, marginBottom: 24 }}>{item.brand}</div>
        <div style={{ fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 18, letterSpacing: '0.08em', marginBottom: 14, fontVariantNumeric: 'tabular-nums' }}>
          {revealedField === 'number' ? item.number : masked}
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 12 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-sans)', fontSize: 9.5, opacity: 0.6, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 2 }}>Cardholder</div>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14, fontWeight: 600 }}>{item.cardholder}</div>
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-sans)', fontSize: 9.5, opacity: 0.6, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 2 }}>Expiry</div>
            <div style={{ fontFamily: 'ui-monospace, "SF Mono", Menlo, monospace', fontSize: 14, fontVariantNumeric: 'tabular-nums' }}>{item.expiry}</div>
          </div>
        </div>
      </div>

      <Field label="Card number">
        <SecretRow
          value={revealedField === 'number' ? item.number : masked}
          isRevealed={revealedField === 'number'}
          onReveal={() => reveal('number')}
          onCopy={() => toast?.('Card number copied')}
        />
      </Field>
      <Field label="CVV" hint="3 or 4-digit verification code on the card.">
        <SecretRow
          value={revealedField === 'cvv' ? item.cvv : '•••'}
          isRevealed={revealedField === 'cvv'}
          onReveal={() => reveal('cvv')}
          onCopy={() => toast?.('CVV copied')}
        />
      </Field>
      {item.notes && <NotesField text={item.notes}/>}
    </>
  );
};

const NoteBody = ({ item, reveal, revealedField, toast }) => {
  const showing = revealedField === 'body';
  return (
    <>
      <Field label="Body">
        {showing ? (
          <div style={{
            background: 'var(--color-surface-elevated)', border: '1px solid var(--color-success)',
            borderRadius: 10, padding: '14px 14px',
            fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.55,
            color: 'var(--color-fg-emphasis)', whiteSpace: 'pre-wrap',
          }}>
            {item.body}
            <div style={{
              borderTop: '1px solid var(--color-divider)', marginTop: 12, paddingTop: 8,
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-success)', fontWeight: 600 }}>
                <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--color-success)', marginRight: 6, verticalAlign: 'middle' }}/>
                Auto-hides in 10s
              </span>
              <CopyButton value={item.body} compact onCopy={() => toast?.('Note copied')}/>
            </div>
          </div>
        ) : (
          <button onClick={() => reveal('body')} style={{
            width: '100%', background: 'var(--color-surface-sunken)', border: '1px dashed var(--color-border)',
            borderRadius: 10, padding: '20px 14px', cursor: 'pointer', textAlign: 'center',
            fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-secondary)',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
          }}>
            <Icon name="eye" size={20} style={{ color: 'var(--color-accent)' }}/>
            <span>Tap your authenticator to reveal</span>
          </button>
        )}
      </Field>
      {item.notes && <NotesField text={item.notes}/>}
    </>
  );
};

const IdentityBody = ({ item, toast }) => (
  <>
    {[
      ['Full name',    item.fullName],
      ['Date of birth',item.dob],
      ['Address',      item.address, true],
      ['Phone',        item.phone],
      ['Email',        item.email],
      ['National ID',  item.nationalId],
    ].filter(([_, v]) => v).map(([label, value, multiline]) => (
      <Field key={label} label={label}>
        <div style={{
          display: 'flex', alignItems: multiline ? 'flex-start' : 'center', gap: 8,
          background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
          borderRadius: 8, padding: '10px 12px',
        }}>
          <div style={{
            flex: 1, fontFamily: 'var(--font-serif)', fontSize: 14, color: 'var(--color-fg-primary)',
            whiteSpace: multiline ? 'pre-wrap' : 'normal',
          }}>{value}</div>
          <CopyButton value={value} compact onCopy={() => toast?.(`${label} copied`)}/>
        </div>
      </Field>
    ))}
    {item.notes && <NotesField text={item.notes}/>}
  </>
);

const SshBody = ({ item, reveal, revealedField, toast }) => (
  <>
    <Field label="Key type">
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
        borderRadius: 8, padding: '10px 12px',
      }}>
        <Mono size={13}>{item.keyType}</Mono>
      </div>
    </Field>
    <Field label="Fingerprint">
      <div style={{
        background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
        borderRadius: 8, padding: '10px 12px',
      }}>
        <Mono size={11.5} style={{ wordBreak: 'break-all' }}>{item.fingerprint}</Mono>
      </div>
    </Field>
    <Field label="Public key" hint="Always safe to share.">
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: 8,
        background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
        borderRadius: 8, padding: '10px 12px',
      }}>
        <Mono size={11} style={{ flex: 1, wordBreak: 'break-all', lineHeight: 1.45 }}>{item.publicKey}</Mono>
        <CopyButton value={item.publicKey} compact onCopy={() => toast?.('Public key copied')}/>
      </div>
    </Field>
    <Field label="Private key" hint="Tap a recipient to copy directly into your SSH agent. Never displayed in full.">
      {revealedField === 'private' ? (
        <div style={{
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-success)',
          borderRadius: 10, padding: '12px 14px',
        }}>
          <Mono size={11} style={{ wordBreak: 'break-all', display: 'block', whiteSpace: 'pre-wrap', color: 'var(--color-fg-emphasis)' }}>{item.privateKey}</Mono>
          <div style={{
            borderTop: '1px solid var(--color-divider)', marginTop: 10, paddingTop: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-success)', fontWeight: 600 }}>
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--color-success)', marginRight: 6, verticalAlign: 'middle' }}/>
              Auto-hides in 10s
            </span>
            <CopyButton value={item.privateKey} compact onCopy={() => toast?.('Private key copied')}/>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 8 }}>
          <Button fullWidth variant="secondary" icon="terminal" onClick={() => toast?.('SSH agent push -- not implemented in prototype')}>
            Push to ssh-agent
          </Button>
          <Button variant="ghost" icon="eye" onClick={() => reveal('private')}>Reveal</Button>
        </div>
      )}
    </Field>
    {item.notes && <NotesField text={item.notes}/>}
  </>
);

const SecretRow = ({ value, isRevealed, onReveal, onCopy }) => (
  <div style={{
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
    background: 'var(--color-surface-sunken)', border: '1px solid ' + (isRevealed ? 'var(--color-success)' : 'var(--color-border)'),
    borderRadius: 8, padding: '10px 12px',
  }}>
    <Mono size={13.5} style={{ flex: 1, color: isRevealed ? 'var(--color-fg-emphasis)' : 'var(--color-fg-primary)', fontWeight: isRevealed ? 500 : 400 }}>{value}</Mono>
    <div style={{ display: 'flex', gap: 6 }}>
      <IconBtn name={isRevealed ? 'eyeOff' : 'eye'} onClick={onReveal} size={16} style={{ width: 28, height: 28 }}/>
      <CopyButton value={value} compact onCopy={onCopy}/>
    </div>
  </div>
);

const NotesField = ({ text }) => (
  <Field label="Notes">
    <div style={{
      background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
      borderRadius: 8, padding: '10px 12px',
      fontFamily: 'var(--font-serif)', fontSize: 13.5, lineHeight: 1.5,
      color: 'var(--color-fg-primary)', whiteSpace: 'pre-wrap',
    }}>{text}</div>
  </Field>
);

const BulkProtectWizard = ({ onBack, onDone, toast }) => {
  const [step, setStep] = useStateE(0);
  const [picked, setPicked] = useStateE(['yk-primary', 'yk-backup', 'recovery']);
  const [showAll, setShowAll] = useStateE(false);
  const [progressItems, setProgressItems] = useStateE([]);
  const [progressIdx, setProgressIdx] = useStateE(-1);
  const timerRef = useRefE(null);

  const allItems = useMemoE(() => {
    const items = [
      ...VAULT,
      ...(typeof ITEMS_BY_KIND !== 'undefined' ? ITEMS_BY_KIND.map(i => ({
        ...i,
        username: i.kind === 'card' ? i.cardholder
                : i.kind === 'identity' ? i.fullName
                : i.kind === 'ssh' ? i.keyType
                : 'Secure note',
        site: '',
      })) : []),
    ];
    // Candidates are the items a re-wrap can actually open on this device:
    // plain, non-internal, and not `decryptable: false` (re-wrapping starts
    // with a decrypt, so an undecryptable item could only ever fail).
    return items.filter(i => !isInternalItem(i) && i.rage !== true && i.decryptable !== false);
  }, []);

  const [selected, setSelected] = useStateE(() => allItems.map(i => i.id));

  const toggleSelect = (id) => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  const togglePick = (id) => setPicked(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);

  const selectedItems = allItems.filter(i => selected.includes(i.id));
  const previewCount = 5;
  const visibleItems = showAll ? allItems : allItems.slice(0, previewCount);
  const hiddenCount = allItems.length - previewCount;

  const doneCount = progressItems.filter(p => p.status === 'done').length;
  const failedCount = progressItems.filter(p => p.status === 'failed').length;
  const allDone = progressItems.length > 0 && (doneCount + failedCount) === progressItems.length;

  const startProgress = () => {
    const items = selectedItems.map(i => ({ id: i.id, name: i.name, username: i.username, status: 'pending' }));
    setProgressItems(items);
    setProgressIdx(0);
  };

  useEffectE(() => {
    if (progressIdx < 0 || progressIdx >= progressItems.length) return;
    const updated = [...progressItems];
    updated[progressIdx] = { ...updated[progressIdx], status: 'encrypting' };
    setProgressItems(updated);

    timerRef.current = setTimeout(() => {
      const finished = [...updated];
      finished[progressIdx] = { ...finished[progressIdx], status: 'done' };
      setProgressItems(finished);
      if (progressIdx + 1 < finished.length) {
        setProgressIdx(progressIdx + 1);
      }
    }, 800);

    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [progressIdx]);

  const Step = ({ children }) => (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '6px 18px 18px' }}>{children}</div>
  );

  if (step === 0) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Protect unprotected items" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <Step>
        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, lineHeight: 1.2,
          color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 8,
        }}>{allItems.length} item{allItems.length === 1 ? '' : 's'} in your vault {allItems.length === 1 ? 'is' : 'are'} not rage-protected</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14 }}>
          {visibleItems.map(it => {
            const on = selected.includes(it.id);
            return (
              <div key={it.id} onClick={() => toggleSelect(it.id)} style={{
                padding: '10px 12px', borderRadius: 10, cursor: 'pointer',
                background: on ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
                border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                display: 'flex', gap: 10, alignItems: 'center',
                transition: 'all var(--dur-fast) var(--ease-out)',
              }}>
                <div style={{
                  width: 20, height: 20, borderRadius: 4,
                  background: on ? 'var(--color-accent)' : 'var(--color-surface-sunken)',
                  border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                  color: '#FAF6EE', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  {on && <Icon name="check" size={12}/>}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.name}</div>
                  <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)' }}>
                    {it.username || it.kind || 'Login'}
                  </div>
                </div>
              </div>
            );
          })}
          {hiddenCount > 0 && (
            <button onClick={() => setShowAll(v => !v)} style={{
              background: 'transparent', border: 'none', cursor: 'pointer',
              padding: '8px 0', fontFamily: 'var(--font-sans)', fontSize: 12,
              fontWeight: 600, color: 'var(--color-accent)', textAlign: 'center',
            }}>
              {showAll ? 'Show fewer' : `and ${hiddenCount} more`}
            </button>
          )}
        </div>

        <StatusMessage tone="info" style={{ marginBottom: 14 }}>
          Each item will be re-encrypted with your chosen recipients. This replaces the plaintext in Bitwarden with an age-wrapped blob.
        </StatusMessage>

        <div style={{ flex: 1 }}/>
        <Button fullWidth icon="arrowRight" onClick={() => setStep(1)} disabled={selectedItems.length === 0}>
          Pick recipients ({selectedItems.length} item{selectedItems.length === 1 ? '' : 's'})
        </Button>
      </Step>
    </div>
  );

  if (step === 1) return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Recipients" subtitle="Step 2 of 3" left={<IconBtn name="arrowLeft" onClick={() => setStep(0)}/>}/>
      <Step>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.5, color: 'var(--color-fg-secondary)', marginBottom: 14 }}>
          Any one of these can decrypt this item. Pick at least two so a lost device isn't a lockout.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {RECIPIENTS.map(r => {
            const on = picked.includes(r.id);
            return (
              <div key={r.id} onClick={() => togglePick(r.id)} style={{
                padding: '12px 14px', borderRadius: 10, cursor: 'pointer',
                background: on ? 'var(--color-tile)' : 'var(--color-surface-elevated)',
                border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                display: 'flex', gap: 12, alignItems: 'center',
                transition: 'all var(--dur-fast) var(--ease-out)',
              }}>
                <div style={{
                  width: 22, height: 22, borderRadius: 11,
                  background: on ? 'var(--color-accent)' : 'var(--color-surface-sunken)',
                  border: '1px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                  color: '#FAF6EE', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  {on && <Icon name="check" size={13}/>}
                </div>
                <div style={{
                  width: 32, height: 32, borderRadius: 7, background: 'var(--color-surface-sunken)',
                  color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}><Icon name={recipientKindIcon(r.kind)} size={16}/></div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                  <Mono size={10.5} style={{ color: 'var(--color-fg-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{r.fingerprint}</Mono>
                </div>
              </div>
            );
          })}
        </div>

        {picked.length < 2 && (
          <StatusMessage tone="warning" style={{ marginTop: 14 }}>
            Single recipient = single point of failure. We strongly recommend at least two.
          </StatusMessage>
        )}

        <div style={{ flex: 1 }}/>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="ghost" onClick={() => setStep(0)}>Back</Button>
          <Button fullWidth icon="tap" onClick={() => { setStep(2); startProgress(); }} disabled={picked.length === 0}>
            Begin ({selectedItems.length} item{selectedItems.length === 1 ? '' : 's'} &times; {picked.length} recipient{picked.length === 1 ? '' : 's'})
          </Button>
        </div>
      </Step>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Protecting" subtitle="Step 3 of 3" left={allDone ? undefined : <IconBtn name="arrowLeft" onClick={() => setStep(1)}/>}/>
      <Step>
        <div style={{
          fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18,
          color: 'var(--color-fg-emphasis)', marginBottom: 8,
        }}>
          {allDone ? `${doneCount} item${doneCount === 1 ? '' : 's'} protected` : `${doneCount} of ${progressItems.length} protected`}
        </div>

        <div style={{
          height: 6, background: 'var(--color-surface-sunken)', borderRadius: 3,
          overflow: 'hidden', marginBottom: 16,
        }}>
          <div style={{
            width: `${(doneCount / Math.max(1, progressItems.length)) * 100}%`,
            height: '100%', background: allDone ? 'var(--color-success)' : 'var(--color-accent)',
            transition: 'width 300ms var(--ease-out), background 300ms var(--ease-out)',
          }}/>
        </div>

        <div style={{ flex: 1, overflowY: 'auto' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {progressItems.map(p => (
              <div key={p.id} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 10px', borderRadius: 8,
                background: p.status === 'done' ? 'var(--color-surface-elevated)' : 'transparent',
              }}>
                {p.status === 'pending' && (
                  <div style={{
                    width: 20, height: 20, borderRadius: 10,
                    background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
                    flexShrink: 0,
                  }}/>
                )}
                {p.status === 'encrypting' && (
                  <div style={{
                    width: 20, height: 20, borderRadius: 10,
                    background: 'var(--color-accent)',
                    flexShrink: 0,
                    animation: 'prewarm-pulse 1.2s ease-in-out infinite',
                  }}/>
                )}
                {p.status === 'done' && (
                  <div style={{
                    width: 20, height: 20, borderRadius: 10,
                    background: 'var(--color-success)', color: '#FAF6EE',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <Icon name="check" size={12}/>
                  </div>
                )}
                {p.status === 'failed' && (
                  <div style={{
                    width: 20, height: 20, borderRadius: 10,
                    background: 'var(--color-danger)', color: '#FAF6EE',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <Icon name="x" size={12}/>
                  </div>
                )}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: 'var(--font-serif)', fontWeight: 600, fontSize: 13.5,
                    color: p.status === 'done' ? 'var(--color-fg-emphasis)' : 'var(--color-fg-primary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{p.name}</div>
                  {p.status === 'failed' && p.error && (
                    <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-danger)', marginTop: 2 }}>
                      {p.error}
                    </div>
                  )}
                </div>
                {p.status === 'failed' && (
                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    <button style={{
                      background: 'transparent', border: '1px solid var(--color-border)',
                      borderRadius: 6, padding: '3px 8px', cursor: 'pointer',
                      fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
                      color: 'var(--color-fg-secondary)',
                    }}>Skip</button>
                    <button style={{
                      background: 'transparent', border: '1px solid var(--color-accent)',
                      borderRadius: 6, padding: '3px 8px', cursor: 'pointer',
                      fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
                      color: 'var(--color-accent)',
                    }}>Retry</button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {allDone && (
          <Button fullWidth icon="check" onClick={() => {
            toast?.(`${doneCount} item${doneCount === 1 ? '' : 's'} protected`, { kind: 'success' });
            onDone?.();
          }}>Done</Button>
        )}
      </Step>
    </div>
  );
};

/*
 * PaperRevealScreen -- decrypt one item by typing its 24-word paper phrase.
 * The phrase never leaves the screen: onReveal(phrase) is the only consumer,
 * and the parent wires it to bridge.recoverFromPhrase(item.id, phrase).
 * validatePhrase (checksum) arms the button before any server round-trip.
 */
const PaperRevealScreen = ({ item, onBack, onReveal, validatePhrase, toast }) => {
  const [phrase, setPhrase] = useState(null);
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState(null);
  const [error, setError] = useState(null);
  const name = item?.name || 'this item';

  // Branch on the structured `code` the bridge attaches to decrypt failures;
  // the message-sniff is kept only for a bundle older than the codes.
  const friendly = (e) => {
    const m = String((e && e.message) || e);
    if ((e && e.code === 'no_matching_identity') || m.includes('matched any stanza')) {
      return `The phrase checks out, but ${name} was never encrypted to this paper identity. It can only decrypt items that list the paper recovery as a recipient.`;
    }
    return m;
  };

  const submit = async () => {
    if (!phrase || busy) return;
    setBusy(true); setError(null);
    try {
      const s = await onReveal(phrase);
      setSecret(String(s));
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Paper recovery" subtitle={name} left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 18px', display: 'flex', flexDirection: 'column' }}>
        {secret == null ? (
          <>
            <div style={{
              fontFamily: 'var(--font-serif)', fontSize: 14, lineHeight: 1.55,
              color: 'var(--color-fg-secondary)', marginBottom: 14,
            }}>
              Type the 24 words from your paper sheet, in order. You can paste the
              whole phrase into any box -- numbers and punctuation are ignored.
            </div>
            <PhraseEntry validatePhrase={validatePhrase} onReady={setPhrase}/>
            {error && (
              <StatusMessage tone="danger" title="Could not decrypt" style={{ marginTop: 14 }}>
                {error}
              </StatusMessage>
            )}
            <div style={{ flex: 1, minHeight: 14 }}/>
            <Button fullWidth disabled={!phrase || busy} onClick={submit}>
              {busy ? 'Decrypting...' : `Decrypt ${name}`}
            </Button>
          </>
        ) : (
          <>
            <StatusMessage tone="info" title="Decrypted with the paper identity" style={{ marginBottom: 14 }}>
              This reveal used only the words you typed; the paper identity was not
              stored on this device.
            </StatusMessage>
            <div style={{
              background: 'var(--color-surface)', border: '1px solid var(--color-border)',
              borderRadius: 10, padding: '14px 14px', marginBottom: 14,
            }}>
              <Mono size={14}>{secret}</Mono>
            </div>
            <CopyButton value={secret} sensitive label="Copy secret" onCopy={() => toast?.('Copied -- clipboard clears in 30 s')}/>
            <div style={{ flex: 1 }}/>
            <Button fullWidth variant="secondary" onClick={onBack}>Done</Button>
          </>
        )}
      </div>
    </div>
  );
};

window.LockScreen = LockScreen;
window.RecipientDetail = RecipientDetail;
window.SearchScreen = SearchScreen;
window.AuditLogScreen = AuditLogScreen;
window.BackfillWizard = BackfillWizard;
window.BulkProtectWizard = BulkProtectWizard;
window.PaperRecoveryWizard = PaperRecoveryWizard;
window.RecoveryPhraseScreen = RecoveryPhraseScreen;
window.PaperRevealScreen = PaperRevealScreen;
window.KindDetailScreen = KindDetailScreen;
window.ActivityIcon = ActivityIcon;
window.ACTION_LABEL = ACTION_LABEL;
