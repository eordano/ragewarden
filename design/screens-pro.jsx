const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP } = React;

const SectionLabel = ({ children, action }) => (
  <div style={{
    padding: '20px 18px 8px', display: 'flex', alignItems: 'baseline', justifyContent: 'space-between',
  }}>
    <div style={{
      fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em',
      textTransform: 'uppercase', color: 'var(--color-fg-secondary)',
    }}>{children}</div>
    {action}
  </div>
);

const Card = ({ children, style = {}, onClick }) => (
  <div onClick={onClick} style={{
    background: 'var(--color-surface)', border: '1px solid var(--color-border)',
    borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)',
    overflow: 'hidden',
    cursor: onClick ? 'pointer' : 'default',
    ...style,
  }}>{children}</div>
);

const Row = ({ icon, title, subtitle, value, onClick, danger, last }) => (
  <button onClick={onClick} style={{
    width: '100%', display: 'flex', alignItems: 'center', gap: 12,
    padding: '12px 16px', background: 'transparent', border: 'none',
    borderBottom: last ? 'none' : '1px solid var(--color-divider)',
    cursor: onClick ? 'pointer' : 'default', textAlign: 'left',
    color: 'var(--color-fg-primary)', fontFamily: 'var(--font-sans)',
  }}>
    {icon && (
      <div style={{
        width: 32, height: 32, borderRadius: 8,
        background: 'var(--color-tile)',
        color: danger ? 'var(--color-danger, #B5361A)' : 'var(--color-accent)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
      }}><Icon name={icon} size={16}/></div>
    )}
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{
        fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5,
        color: danger ? 'var(--color-danger, #B5361A)' : 'var(--color-fg-emphasis)',
      }}>{title}</div>
      {subtitle && (
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
          {subtitle}
        </div>
      )}
    </div>
    {value !== undefined && (
      <span style={{ fontFamily: 'var(--font-sans)', fontSize: 12.5, color: 'var(--color-fg-secondary)' }}>{value}</span>
    )}
    {onClick && <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>}
  </button>
);

const Switch = ({ on, onChange }) => (
  <label style={{ position: 'relative', display: 'inline-block', width: 40, height: 24, flexShrink: 0 }}>
    <input type="checkbox" checked={on} onChange={e => onChange(e.target.checked)} style={{ display: 'none' }}/>
    <span style={{
      position: 'absolute', inset: 0, borderRadius: 12,
      background: on ? 'var(--color-accent)' : 'var(--color-border)',
      transition: 'background var(--dur-fast)',
      cursor: 'pointer',
    }}/>
    <span style={{
      position: 'absolute', top: 2, left: on ? 18 : 2,
      width: 20, height: 20, borderRadius: 10, background: '#FAF6EE',
      transition: 'left var(--dur-fast) var(--ease-out)', pointerEvents: 'none',
    }}/>
  </label>
);

const SwitchRow = ({ icon, title, subtitle, on, onChange, last }) => (
  <div
    onClick={() => onChange(!on)}
    role="switch"
    aria-checked={on}
    tabIndex={0}
    onKeyDown={(e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); onChange(!on); } }}
    style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '12px 16px',
      borderBottom: last ? 'none' : '1px solid var(--color-divider)',
      cursor: 'pointer',
      userSelect: 'none',
    }}>
    {icon && (
      <div style={{
        width: 32, height: 32, borderRadius: 8, background: 'var(--color-tile)',
        color: 'var(--color-accent)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
      }}><Icon name={icon} size={16}/></div>
    )}
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>{title}</div>
      {subtitle && (
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2, lineHeight: 1.4 }}>
          {subtitle}
        </div>
      )}
    </div>
    <div onClick={(e) => e.stopPropagation()}>
      <Switch on={on} onChange={onChange}/>
    </div>
  </div>
);

const SettingsScreenFull = ({
  onBack,
  onAccount,
  onAddRecipient, onOpenRecipient,
  onRecovery,
  onAutofill, onIME,
  autofillOn = true, onToggleAutofill = () => {},
  imeOn = false, onToggleIME = () => {},
  defaultRecipientIds = [], onChangeDefaultRecipients = () => {},
  onFolders,
  onOpenAuditLog,
  onSignOut,
  onAbout,
  requireMasterPassword = true,
  onToggleRequireMP = () => {},
  toast,
}) => {
  const items = VAULT.length;
  const protectedItems = VAULT.filter(v => v.rage).length;
  const [defaultsPickerOpen, setDefaultsPickerOpen] = useStateP(false);

  const defaultRecipients = defaultRecipientIds
    .map(id => RECIPIENTS.find(r => r.id === id))
    .filter(Boolean);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Settings" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', paddingBottom: 32 }}>

        <div style={{ padding: '8px 16px 0' }}>
          <button onClick={onAccount} style={{
            width: '100%', display: 'flex', gap: 12, alignItems: 'center',
            padding: '14px 14px',
            background: 'var(--color-surface-elevated)',
            border: '1px solid var(--color-border)',
            borderRadius: 12,
            cursor: 'pointer', textAlign: 'left',
          }}>
            <div style={{
              width: 44, height: 44, borderRadius: 22, background: 'var(--color-accent)',
              color: 'var(--color-background)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18,
            }}>M</div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 16, color: 'var(--color-fg-emphasis)' }}>
                maya@feldspar.fm
              </div>
              <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 2, display: 'block' }}>
                vault.feldspar.fm · {items} items · {protectedItems} protected
              </Mono>
            </div>
            <Icon name="chevronRight" size={16} style={{ color: 'var(--color-fg-secondary)' }}/>
          </button>
        </div>

        <SectionLabel
          action={
            <button onClick={onAddRecipient} style={{
              background: 'transparent', border: 'none', padding: 0,
              display: 'inline-flex', alignItems: 'center', gap: 4,
              color: 'var(--color-accent)', fontFamily: 'var(--font-sans)',
              fontSize: 12.5, fontWeight: 600, cursor: 'pointer',
            }}><Icon name="plus" size={13}/> Add</button>
          }
        >Identities</SectionLabel>
        <Card>
          {RECIPIENTS.map((r, i) => (
            <button key={r.id} onClick={() => onOpenRecipient(r)} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 16px', background: 'transparent', border: 'none',
              borderBottom: i < RECIPIENTS.length - 1 ? '1px solid var(--color-divider)' : 'none',
              cursor: 'pointer', textAlign: 'left',
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: 8, background: 'var(--color-tile)',
                color: 'var(--color-accent)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}><Icon name={recipientKindIcon(r.kind)} size={16}/></div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
                  {recipientKindLabel(r.kind)} · {r.lastUsed}
                </div>
              </div>
              <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
            </button>
          ))}
        </Card>

        <Card style={{ marginTop: 8 }}>
          <button
            onClick={() => setDefaultsPickerOpen(true)}
            style={{
              width: '100%', display: 'flex', alignItems: 'flex-start', gap: 12,
              padding: '12px 16px', background: 'transparent', border: 'none',
              cursor: 'pointer', textAlign: 'left',
            }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8, background: 'var(--color-tile)',
              color: 'var(--color-accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
            }}><Icon name="shield" size={16}/></div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>
                Default recipients
              </div>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2, lineHeight: 1.45 }}>
                Every new item is encrypted to these recipients by default.
              </div>
              {defaultRecipients.length > 0 ? (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                  {defaultRecipients.map(r => (
                    <span key={r.id} style={{
                      display: 'inline-flex', alignItems: 'center', gap: 5,
                      padding: '3px 8px', borderRadius: 12,
                      background: 'var(--color-tile)',
                      border: '1px solid var(--color-border)',
                      fontFamily: 'var(--font-sans)', fontSize: 11.5,
                      color: 'var(--color-fg-emphasis)',
                    }}>
                      <Icon name={recipientKindIcon(r.kind)} size={11} style={{ color: 'var(--color-accent)' }}/>
                      {r.name}
                    </span>
                  ))}
                </div>
              ) : (
                <div style={{
                  fontFamily: 'var(--font-sans)', fontSize: 12,
                  color: 'var(--color-danger-strong)', marginTop: 8, fontWeight: 600,
                }}>
                  None -- new items will be unprotected. Tap to choose at least one.
                </div>
              )}
            </div>
            <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)', marginTop: 10 }}/>
          </button>
        </Card>

        <SectionLabel>Vault</SectionLabel>
        <Card>
          <Row icon="folder" title="Folders" subtitle="6 folders · 1 nested" onClick={onFolders}/>
          <Row icon="paper" title="Recovery phrase" subtitle="View, re-print, or download recovery file" onClick={onRecovery}/>
          <Row icon="clock" title="Recent unlocks" subtitle={`${ACTIVITY.length} entries · stored on this device`} onClick={onOpenAuditLog} last/>
        </Card>

        <SectionLabel>System integration</SectionLabel>
        <Card>
          <SwitchRow icon="bolt" title="Autofill"
            subtitle={autofillOn ? 'RageDroid is the active autofill provider.' : 'Tap to make RageDroid the active autofill provider.'}
            on={autofillOn} onChange={(v) => { onToggleAutofill(v); toast?.(v ? 'Autofill enabled.' : 'Autofill disabled.'); }}/>
          <SwitchRow icon="terminal" title="Quick-fill keyboard"
            subtitle={imeOn ? 'A RageDroid keyboard suggests credentials inside login forms.' : 'Suggests credentials inline above the keys, even in apps that don\'t support Autofill.'}
            on={imeOn} onChange={(v) => { onToggleIME(v); toast?.(v ? 'Quick-fill keyboard enabled.' : 'Quick-fill keyboard disabled.'); }} last/>
        </Card>

        <SectionLabel>Security</SectionLabel>
        <Card>
          <SwitchRow icon="lock" title="Confirm destructive actions"
            subtitle="Re-prompt for the master password before revoking a recipient or signing out."
            on={requireMasterPassword} onChange={onToggleRequireMP} last/>
        </Card>

        <SectionLabel>About</SectionLabel>
        <Card>
          <Row icon="info" title="Version" value="0.4.1 · build 81a3"/>
          <Row icon="globe" title="Source code" subtitle="github.com/eordano/ragewarden" onClick={() => toast?.('Opens browser')}/>
          <Row icon="x" title="Sign out & forget device" subtitle="Wipes the encrypted vault cache from this device." onClick={onSignOut} danger last/>
        </Card>

        <div style={{
          padding: '24px 18px 12px', textAlign: 'center',
          fontFamily: 'var(--font-serif)', fontStyle: 'italic',
          fontSize: 13, lineHeight: 1.5, color: 'var(--color-fg-secondary)',
        }}>
          RageDroid 0.4.1 · A LocalForge product<br/>
          age 1.2.0 · yubikit-android 2.5
        </div>
      </div>

      <RecipientPickerSheet
        open={defaultsPickerOpen}
        onClose={() => setDefaultsPickerOpen(false)}
        value={defaultRecipientIds}
        onChange={(next) => { onChangeDefaultRecipients(next); toast?.(`Default recipients updated · ${next.length} selected`); }}
        allowEmpty={false}
        toast={toast}
      />
    </div>
  );
};

const SYNC_INTERVALS = [
  { id: '1m',     label: 'Every 1 min' },
  { id: '5m',     label: 'Every 5 min' },
  { id: '15m',    label: 'Every 15 min' },
  { id: '1h',     label: 'Every hour' },
  { id: 'manual', label: 'Only on changes & startup' },
];

const AccountScreen = ({ onBack, onSignOut, toast }) => {
  const [syncState, setSyncState] = useStateP('idle');
  const [lastSync, setLastSync] = useStateP('14:21');
  const [intervalId, setIntervalId] = useStateP('5m');
  const [pullToRefresh, setPullToRefresh] = useStateP(true);
  const [pickerOpen, setPickerOpen] = useStateP(false);
  const doSync = () => {
    if (syncState !== 'idle') return;
    setSyncState('syncing');
    setTimeout(() => {
      const now = new Date();
      setLastSync(`${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`);
      setSyncState('done');
      setTimeout(() => setSyncState('idle'), 1800);
    }, 1100);
  };

  const syncRowSubtitle = syncState === 'syncing'
    ? 'Pulling latest blob from vault.feldspar.fm...'
    : syncState === 'done'
      ? 'Up to date · 0 changes'
      : `Last sync ${lastSync}`;
  const syncIcon = syncState === 'done' ? 'check' : 'refresh';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
    <AppBar title="Account" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
    <div style={{ flex: 1, overflowY: 'auto', paddingBottom: 32 }}>

      <SectionLabel>Identity</SectionLabel>
      <Card>
        <div style={{ padding: '14px 16px' }}>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18, color: 'var(--color-fg-emphasis)' }}>maya@feldspar.fm</div>
          <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 4, display: 'block' }}>
            account: 6f7e8a91-30c2-4d10-b0a1-2c3d4e5f6071
          </Mono>
        </div>
      </Card>

      <SectionLabel>Server</SectionLabel>
      <Card>
        <Row title="URL" value="vault.feldspar.fm" onClick={() => toast?.('Server URL is set at sign-in')}/>
        <Row
          title="Sync interval"
          subtitle={intervalId === 'manual' ? 'Background polling disabled.' : 'Pulls in the background.'}
          value={SYNC_INTERVALS.find(o => o.id === intervalId)?.label || ''}
          onClick={() => setPickerOpen(true)}
        />
        <Row title="KDF" subtitle="PBKDF2-HMAC-SHA256" value="600 000" last/>
      </Card>

      <SectionLabel>This device</SectionLabel>
      <Card>
        <Row title="Device name" value="Pixel 8 · Maya" onClick={() => toast?.('Tap to rename')}/>
        <Row
          icon={syncIcon}
          title="Sync now"
          subtitle={syncRowSubtitle}
          onClick={doSync}
        />
        <SwitchRow
          icon="chevronDown"
          title="Pull to refresh"
          subtitle="Drag the vault list down to trigger a manual sync."
          on={pullToRefresh}
          onChange={setPullToRefresh}
        />
        <Row title="Vault cache" subtitle="Encrypted blob · 184 KB" value="Clear" onClick={() => toast?.('Re-syncs on next unlock')} last/>
      </Card>

      <div style={{ padding: '20px 16px' }}>
        <Button fullWidth variant="danger" icon="trash" onClick={onSignOut}>Sign out & forget device</Button>
        <div style={{
          fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)',
          textAlign: 'center', marginTop: 10, lineHeight: 1.5,
        }}>
          Removes the encrypted cache, keys derived on this device, and the autofill registration. Your server vault is untouched.
        </div>
      </div>
    </div>

    <Sheet open={pickerOpen} onClose={() => setPickerOpen(false)} title="Sync interval">
      <div style={{ padding: '0 16px 16px' }}>
        <div style={{
          background: 'var(--color-surface)', border: '1px solid var(--color-border)',
          borderRadius: 10, overflow: 'hidden',
        }}>
          {SYNC_INTERVALS.map((opt, i) => {
            const active = opt.id === intervalId;
            return (
              <button key={opt.id}
                onClick={() => { setIntervalId(opt.id); setPickerOpen(false); }}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                  padding: '14px 16px', background: 'transparent',
                  border: 'none',
                  borderBottom: i === SYNC_INTERVALS.length - 1 ? 'none' : '1px solid var(--color-divider)',
                  textAlign: 'left', cursor: 'pointer',
                }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5,
                    color: 'var(--color-fg-emphasis)',
                  }}>{opt.label}</div>
                  {opt.id === 'manual' && (
                    <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
                      Pulls only when items change locally or the app launches. No background polling.
                    </div>
                  )}
                </div>
                {active && <Icon name="check" size={16} style={{ color: 'var(--color-accent)' }}/>}
              </button>
            );
          })}
        </div>
      </div>
    </Sheet>
  </div>
  );
};

const KIND_GROUP = {
  yubikey: 'hardware', fido2: 'hardware',
  strongbox: 'device',
  recovery: 'recovery',
};
const GROUP_LABEL = {
  hardware: { name: 'Hardware · tap to decrypt', sub: 'Phishing-resistant. Most secure.' },
  device:   { name: 'This device',                sub: 'Always available while signed in.' },
  recovery: { name: 'Recovery',                   sub: 'Fallback if every other recipient is lost.' },
};

const RecipientPickerSheet = ({ open, onClose, value = [], onChange, allowEmpty = false, toast }) => {
  const [picked, setPicked] = useStateP(value);
  useEffectP(() => { if (open) setPicked(value); }, [open]);

  const groups = useMemoP(() => {
    const g = { hardware: [], device: [], recovery: [] };
    RECIPIENTS.forEach(r => g[KIND_GROUP[r.kind] || 'device'].push(r));
    return g;
  }, []);

  const toggle = (id) => setPicked(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);

  const protectedItems = VAULT.filter(v => v.rage).length;

  return (
    <Sheet open={open} onClose={onClose} title="Recipients">
      <div style={{ padding: '0 16px 12px' }}>
        <div style={{
          fontFamily: 'var(--font-serif)', fontSize: 14, lineHeight: 1.5,
          color: 'var(--color-fg-secondary)', marginBottom: 16,
        }}>
          Any of the selected recipients can decrypt this item. Choose at least one -- without recovery you can be locked out.
        </div>

        {Object.keys(groups).map(g => (
          groups[g].length > 0 && (
            <div key={g} style={{ marginBottom: 14 }}>
              <div style={{
                fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
                letterSpacing: '0.06em', textTransform: 'uppercase',
                color: 'var(--color-fg-secondary)', marginBottom: 6, padding: '0 2px',
              }}>{GROUP_LABEL[g].name}</div>
              <div style={{ fontFamily: 'var(--font-serif)', fontStyle: 'italic', fontSize: 12.5, color: 'var(--color-fg-secondary)', marginBottom: 8, padding: '0 2px' }}>
                {GROUP_LABEL[g].sub}
              </div>
              <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden' }}>
                {groups[g].map((r, i) => {
                  const on = picked.includes(r.id);
                  return (
                    <label key={r.id} style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '12px 14px',
                      borderBottom: i < groups[g].length - 1 ? '1px solid var(--color-divider)' : 'none',
                      cursor: 'pointer',
                      background: on ? 'var(--color-tile)' : 'transparent',
                      transition: 'background var(--dur-fast)',
                    }}>
                      <RecipientPip kind={r.kind}/>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                        <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 2, display: 'block' }}>
                          {r.fingerprint}
                        </Mono>
                      </div>
                      <span style={{
                        width: 22, height: 22, borderRadius: 4,
                        border: '1.5px solid ' + (on ? 'var(--color-accent)' : 'var(--color-border)'),
                        background: on ? 'var(--color-accent)' : 'transparent',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        color: '#FAF6EE', flexShrink: 0,
                      }}>
                        {on && <Icon name="check" size={14}/>}
                      </span>
                      <input type="checkbox" checked={on} onChange={() => toggle(r.id)} style={{ display: 'none' }}/>
                    </label>
                  );
                })}
              </div>
            </div>
          )
        ))}

        {!picked.includes('recovery') && (
          <div style={{
            padding: '10px 12px', background: 'var(--color-tile)',
            border: '1px solid var(--color-warning, #C99A3F)',
            borderRadius: 8, marginTop: 8, marginBottom: 12,
            display: 'flex', gap: 8, alignItems: 'flex-start',
          }}>
            <Icon name="alert" size={16} style={{ color: 'var(--color-warning, #C99A3F)', marginTop: 2, flexShrink: 0 }}/>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13, color: 'var(--color-fg-primary)', lineHeight: 1.4 }}>
              No recovery identity included. If you lose every other recipient, this item is gone forever.
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button fullWidth disabled={!allowEmpty && picked.length === 0} onClick={() => { onChange(picked); onClose(); }}>
            Save · {picked.length} {picked.length === 1 ? 'recipient' : 'recipients'}
          </Button>
        </div>
      </div>
    </Sheet>
  );
};

const TYPE_OPTIONS = [
  { id: 'login',    icon: 'chain',      name: 'Login',         desc: 'Username + password, optionally with TOTP.' },
  { id: 'card',     icon: 'creditCard', name: 'Card',          desc: 'Credit / debit card. Number and CVV are gated.' },
  { id: 'note',     icon: 'paper',      name: 'Secure note',   desc: 'Free-form encrypted text. No structure.' },
  { id: 'identity', icon: 'user',       name: 'Identity',      desc: 'Name, address, ID numbers -- for autofill.' },
  { id: 'ssh',      icon: 'terminal',   name: 'SSH key',       desc: 'Private key gated; public key always shown.' },
];

const AddItemTypePickerScreen = ({ onBack, onPick }) => (
  <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
    <AppBar title="New item" subtitle="Pick a type" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
    <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px 24px' }}>
      {TYPE_OPTIONS.map(t => (
        <button key={t.id} onClick={() => onPick(t.id)} style={{
          width: '100%', display: 'flex', gap: 12, alignItems: 'flex-start',
          padding: 14, marginBottom: 8, textAlign: 'left',
          background: 'var(--color-surface-elevated)',
          border: '1px solid var(--color-border)', borderRadius: 12,
          cursor: 'pointer', fontFamily: 'var(--font-sans)',
        }}>
          <div style={{
            width: 40, height: 40, borderRadius: 10, background: 'var(--color-tile)',
            color: 'var(--color-accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}><Icon name={t.icon} size={20}/></div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 16, color: 'var(--color-fg-emphasis)' }}>{t.name}</div>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.4, marginTop: 2 }}>{t.desc}</div>
          </div>
          <Icon name="chevronRight" size={18} style={{ color: 'var(--color-fg-secondary)', marginTop: 12 }}/>
        </button>
      ))}
    </div>
  </div>
);

const WORDS = ['mountain','pebble','curtain','forest','ocean','lantern','velvet','hollow','pioneer','meadow','cipher','shelter','copper','ember','garnet','harbor','indigo','jasper','kestrel','lichen','mantle','nutmeg','onyx','pewter','quartz','redwood','sable','tamarind','umber','verdigris','willow','xenon','yarrow','zephyr'];

const PasswordGeneratorSheet = ({ open, onClose, onUse, toast }) => {
  const [mode, setMode] = useStateP('chars');
  const [length, setLength] = useStateP(20);
  const [wordCount, setWordCount] = useStateP(4);
  const [upper, setUpper] = useStateP(true);
  const [lower, setLower] = useStateP(true);
  const [digits, setDigits] = useStateP(true);
  const [symbols, setSymbols] = useStateP(true);
  const [pw, setPw] = useStateP('');

  const gen = () => {
    if (mode === 'words') {
      const out = Array.from({ length: wordCount }, () => WORDS[Math.floor(Math.random() * WORDS.length)]);
      setPw(out.join('-') + '-' + Math.floor(Math.random() * 99));
      return;
    }
    let pool = '';
    if (lower) pool += 'abcdefghjkmnpqrstuvwxyz';
    if (upper) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (digits) pool += '23456789';
    if (symbols) pool += '!@#$%^&*-_=+';
    if (!pool) pool = 'abcdefghijklmnopqrstuvwxyz';
    let out = '';
    for (let i = 0; i < length; i++) out += pool[Math.floor(Math.random() * pool.length)];
    setPw(out);
  };

  useEffectP(() => { if (open) gen(); }, [open, mode, length, wordCount, upper, lower, digits, symbols]);

  return (
    <Sheet open={open} onClose={onClose} title="Generate password">
      <div style={{ padding: '0 16px 16px' }}>

        <div style={{
          padding: '14px 14px',
          background: 'var(--color-tile)',
          border: '1px solid var(--color-border)',
          borderRadius: 10,
          fontFamily: 'ui-monospace, "SF Mono", "Menlo", "Roboto Mono", monospace',
          fontSize: 16, lineHeight: 1.4,
          wordBreak: 'break-all',
          color: 'var(--color-fg-emphasis)',
          minHeight: 72,
        }}>{pw || '...'}</div>

        <div style={{ display: 'flex', gap: 8, marginTop: 10, marginBottom: 18 }}>
          <Button variant="secondary" icon="refresh" onClick={gen}>Regenerate</Button>
          <Button variant="secondary" icon="copy" onClick={() => { toast?.('Copied'); }}>Copy</Button>
          <Button fullWidth onClick={() => { onUse?.(pw); onClose(); }}>Use</Button>
        </div>

        <div style={{ display: 'flex', background: 'var(--color-tile)', borderRadius: 8, padding: 3, marginBottom: 16 }}>
          {[{id:'chars',label:'Random characters'},{id:'words',label:'Memorable words'}].map(m => (
            <button key={m.id} onClick={() => setMode(m.id)} style={{
              flex: 1, padding: '8px 10px',
              background: mode === m.id ? 'var(--color-surface)' : 'transparent',
              border: 'none', borderRadius: 6,
              fontFamily: 'var(--font-sans)', fontSize: 12.5, fontWeight: 600,
              color: mode === m.id ? 'var(--color-fg-emphasis)' : 'var(--color-fg-secondary)',
              cursor: 'pointer',
              boxShadow: mode === m.id ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
            }}>{m.label}</button>
          ))}
        </div>

        {mode === 'chars' ? (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-primary)',
              marginBottom: 6,
            }}>
              <span>Length</span>
              <Mono size={13} style={{ fontWeight: 600 }}>{length}</Mono>
            </div>
            <input type="range" min={8} max={48} value={length} onChange={e => setLength(+e.target.value)}
              style={{ width: '100%', accentColor: 'var(--color-accent)' }}/>
            <div style={{ marginTop: 16 }}>
              {[
                { id: 'upper', label: 'A-Z',    on: upper,   set: setUpper },
                { id: 'lower', label: 'a-z',    on: lower,   set: setLower },
                { id: 'digits',label: '0-9',    on: digits,  set: setDigits },
                { id: 'syms',  label: '!@#%...',  on: symbols, set: setSymbols },
              ].map((c, i, arr) => (
                <div key={c.id} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '10px 0', borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
                }}>
                  <Mono size={14}>{c.label}</Mono>
                  <Switch on={c.on} onChange={c.set}/>
                </div>
              ))}
            </div>
          </>
        ) : (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-primary)',
              marginBottom: 6,
            }}>
              <span>Words</span>
              <Mono size={13} style={{ fontWeight: 600 }}>{wordCount}</Mono>
            </div>
            <input type="range" min={3} max={8} value={wordCount} onChange={e => setWordCount(+e.target.value)}
              style={{ width: '100%', accentColor: 'var(--color-accent)' }}/>
            <div style={{
              fontFamily: 'var(--font-serif)', fontStyle: 'italic',
              fontSize: 13, color: 'var(--color-fg-secondary)', marginTop: 12, lineHeight: 1.5,
            }}>
              Hyphenated wordlists are easier to dictate and type. RageDroid uses the BIP39 wordlist.
            </div>
          </>
        )}
      </div>
    </Sheet>
  );
};

const HISTORY_FIXTURE = [
  { id: 'v4', when: 'Today · 14:18',     by: 'maya@feldspar.fm',  changes: [{ field: 'Password', diff: 'rotated' }], current: true },
  { id: 'v3', when: 'Mon · 09:02',       by: 'maya@feldspar.fm',  changes: [{ field: 'TOTP', diff: 'added'  }] },
  { id: 'v2', when: '14 days ago',       by: 'maya@feldspar.fm',  changes: [{ field: 'Username', diff: 'changed' }] },
  { id: 'v1', when: '7 March · created', by: 'maya@feldspar.fm',  changes: [{ field: 'Item created' }] },
];

const ItemHistoryScreen = ({ item, onBack, toast }) => {
  const [selected, setSelected] = useStateP(null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="History" subtitle={item?.name || 'GitHub'} left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0 24px' }}>

        <div style={{
          padding: '0 18px 12px',
          fontFamily: 'var(--font-serif)', fontStyle: 'italic',
          fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.5,
        }}>
          Past values are stored encrypted under the same recipients. Restoring re-encrypts; nothing leaves the device unsealed.
        </div>

        <div style={{ position: 'relative', paddingLeft: 32 }}>
          <div style={{
            position: 'absolute', left: 23, top: 16, bottom: 16,
            width: 1.5, background: 'var(--color-divider)',
          }}/>

          {HISTORY_FIXTURE.map((h, i) => (
            <div key={h.id} style={{ position: 'relative', padding: '8px 18px 16px 0' }}>
              <div style={{
                position: 'absolute', left: -17, top: 14,
                width: 12, height: 12, borderRadius: 6,
                background: h.current ? 'var(--color-accent)' : 'var(--color-surface)',
                border: '2px solid ' + (h.current ? 'var(--color-accent)' : 'var(--color-border)'),
                boxShadow: '0 0 0 4px var(--color-background)',
              }}/>
              <button onClick={() => setSelected(h)} style={{
                width: '100%', textAlign: 'left',
                padding: '12px 14px', borderRadius: 10,
                background: selected?.id === h.id ? 'var(--color-tile)' : 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                cursor: 'pointer', fontFamily: 'var(--font-sans)',
              }}>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
                  <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>
                    {h.when}
                  </div>
                  {h.current && (
                    <span style={{
                      fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 700,
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                      color: 'var(--color-accent)',
                    }}>Current</span>
                  )}
                </div>
                <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 2, display: 'block' }}>{h.by}</Mono>
                <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {h.changes.map((c, j) => (
                    <span key={j} style={{
                      fontFamily: 'var(--font-sans)', fontSize: 11.5,
                      padding: '2px 8px', borderRadius: 10,
                      background: 'var(--color-tile)',
                      color: 'var(--color-fg-primary)',
                    }}>{c.field}{c.diff ? ' · ' + c.diff : ''}</span>
                  ))}
                </div>
                {!h.current && selected?.id === h.id && (
                  <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                    <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); toast?.('Diff view not in prototype'); }}>View diff</Button>
                    <Button size="sm" onClick={(e) => { e.stopPropagation(); toast?.('Restored ' + h.when); onBack(); }}>Restore</Button>
                  </div>
                )}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const DeleteConfirmSheet = ({ open, onClose, item, onConfirm, toast }) => {
  const [typed, setTyped] = useStateP('');
  useEffectP(() => { if (open) setTyped(''); }, [open]);
  const protectedItem = item?.rage;
  const expected = item?.name || '';
  const ok = !protectedItem || typed.trim().toLowerCase() === expected.trim().toLowerCase();

  return (
    <Sheet open={open} onClose={onClose} title="Delete this item?">
      <div style={{ padding: '0 16px 16px' }}>
        <div style={{
          padding: '14px 14px', borderRadius: 10,
          background: 'var(--color-tile)', border: '1px solid var(--color-border)',
          marginBottom: 14,
        }}>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 16, color: 'var(--color-fg-emphasis)' }}>
            {item?.name}
          </div>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
            {item?.username || item?.site || '--'}
          </div>
        </div>

        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.5, color: 'var(--color-fg-primary)', marginBottom: 14 }}>
          {protectedItem ? (
            <>This item is <strong>RageDroid-protected</strong>. Deleting it removes every encrypted version from the server. There is no undo.</>
          ) : (
            <>The server keeps a 30-day soft-delete. You can restore it from the trash within that window.</>
          )}
        </div>

        {protectedItem && (
          <Field label={`Type "${expected}" to confirm`}>
            <TextInput value={typed} onChange={setTyped} placeholder={expected}/>
          </Field>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button fullWidth variant="danger" disabled={!ok} icon="trash" onClick={() => { onConfirm?.(item); onClose(); }}>
            Delete{protectedItem ? ' permanently' : ''}
          </Button>
        </div>
      </div>
    </Sheet>
  );
};

const FAIL_COPY = {
  'wrong-key': {
    title: 'Wrong key',
    body: 'The key you tapped isn’t a recipient for this item. Check that it’s the right hardware key, or pick a different recipient.',
    icon: 'x', tone: 'danger',
  },
  'timeout': {
    title: 'Timed out',
    body: 'No tap detected within 30 seconds. NFC keys time out faster than USB; hold steady against the back of the phone.',
    icon: 'clock', tone: 'warning',
  },
  'cancelled': {
    title: 'Cancelled',
    body: 'You dismissed the prompt before tapping. The cipher is unchanged.',
    icon: 'x', tone: 'muted',
  },
  'no-match': {
    title: 'No matching recipient',
    body: 'None of your enrolled identities can decrypt this cipher. It was probably created on another device with different recipients.',
    icon: 'alert', tone: 'danger',
  },
};

const TapFailureScreen = ({ kind = 'timeout', item, onRetry, onPick, onPaper, onBack }) => {
  const c = FAIL_COPY[kind] || FAIL_COPY.timeout;
  const tone = {
    danger:  { bg: 'var(--color-danger, #B5361A)', fg: '#FAF6EE' },
    warning: { bg: 'var(--color-warning, #C99A3F)', fg: '#1A140A' },
    muted:   { bg: 'var(--color-tile)', fg: 'var(--color-fg-emphasis)' },
  }[c.tone];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Reveal" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, padding: '24px 18px', display: 'flex', flexDirection: 'column' }}>

        <div style={{
          padding: '20px 16px',
          background: 'var(--color-surface-elevated)',
          border: '1px solid var(--color-border)',
          borderRadius: 12,
          textAlign: 'center',
        }}>
          <div style={{
            width: 72, height: 72, borderRadius: 36, margin: '0 auto 16px',
            background: tone.bg, color: tone.fg,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}><Icon name={c.icon} size={32}/></div>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 22, color: 'var(--color-fg-emphasis)' }}>{c.title}</div>
          <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14, lineHeight: 1.55, color: 'var(--color-fg-secondary)', marginTop: 8, padding: '0 4px' }}>{c.body}</div>
        </div>

        {item?.recipients && item.recipients.length > 1 && (
          <>
            <div style={{
              padding: '20px 4px 8px',
              fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
              letterSpacing: '0.08em', textTransform: 'uppercase',
              color: 'var(--color-fg-secondary)',
            }}>Or try a different recipient</div>
            <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10 }}>
              {item.recipients.map((rid, i, arr) => {
                const r = RECIPIENTS.find(x => x.id === rid);
                if (!r) return null;
                return (
                  <button key={rid} onClick={() => onPick?.(r)} style={{
                    width: '100%', display: 'flex', alignItems: 'center', gap: 12,
                    padding: '12px 14px', background: 'transparent', border: 'none',
                    borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
                    cursor: 'pointer', textAlign: 'left',
                  }}>
                    <RecipientPip kind={r.kind}/>
                    <div style={{ flex: 1, fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                    <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
                  </button>
                );
              })}
            </div>
          </>
        )}

        <div style={{ flex: 1 }}/>
        {onPaper && (
          <Button fullWidth variant="secondary" onClick={onPaper} style={{ marginBottom: 10 }}>
            Type the paper recovery phrase
          </Button>
        )}
        <Button fullWidth icon="tap" onClick={onRetry}>Try again</Button>
      </div>
    </div>
  );
};

const MultiIdentityPickerSheet = ({ open, onClose, item, onPick }) => {
  const ids = (item?.recipients || []).map(rid => RECIPIENTS.find(r => r.id === rid)).filter(Boolean);
  return (
    <Sheet open={open} onClose={onClose} title="Pick a recipient">
      <div style={{ padding: '0 16px 16px' }}>
        <div style={{
          fontFamily: 'var(--font-serif)', fontSize: 14, lineHeight: 1.5,
          color: 'var(--color-fg-secondary)', marginBottom: 12,
        }}>
          More than one identity can decrypt {item?.name || 'this item'}. Pick the one you have on hand.
        </div>
        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10 }}>
          {ids.map((r, i) => (
            <button key={r.id} onClick={() => { onPick?.(r); onClose(); }} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 14px', background: 'transparent', border: 'none',
              borderBottom: i < ids.length - 1 ? '1px solid var(--color-divider)' : 'none',
              cursor: 'pointer', textAlign: 'left',
            }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8, background: 'var(--color-tile)',
                color: 'var(--color-accent)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}><Icon name={recipientKindIcon(r.kind)} size={18}/></div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>{r.name}</div>
                <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
                  {recipientKindLabel(r.kind)} · last used {r.lastUsed}
                </div>
              </div>
              <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
            </button>
          ))}
        </div>
      </div>
    </Sheet>
  );
};

const FOLDER_FIXTURE = [
  { id: 'work',           name: 'Work',           color: '#C8552B', count: 12 },
  { id: 'personal',       name: 'Personal',       color: '#6B8E5A', count: 8 },
  { id: 'infrastructure', name: 'Infrastructure', color: '#3A6B8E', count: 7,  parent: null },
  { id: 'family',         name: 'Family',         color: '#B57A2A', count: 4 },
  { id: 'archive',        name: 'Archive',        color: '#8C7B6B', count: 23 },
  { id: 'shared',         name: 'Shared',         color: '#7C5A8E', count: 0 },
];

const FoldersScreen = ({ onBack, onEdit, onNew, toast }) => {
  const live = (typeof window !== 'undefined' && Array.isArray(window.FOLDERS)) ? window.FOLDERS : null;
  const folders = live && live.length > 0
    ? live.map((f, i) => ({
        ...f,
        color: f.color || FOLDER_COLORS[i % FOLDER_COLORS.length],
        count: typeof f.count === 'number' ? f.count : 0,
      }))
    : FOLDER_FIXTURE;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Folders" left={<IconBtn name="arrowLeft" onClick={onBack}/>}
        right={<IconBtn name="plus" title="New folder" onClick={() => onNew()}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0 24px' }}>
        <div style={{
          padding: '0 18px 12px',
          fontFamily: 'var(--font-serif)', fontStyle: 'italic',
          fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.5,
        }}>
          Folders are decrypted client-side. Only you can see their names -- the server stores them as opaque ciphertext.
        </div>

        <Card>
          {folders.map((f, i) => (
            <button key={f.id} onClick={() => onEdit(f)} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 16px', background: 'transparent', border: 'none',
              borderBottom: i < folders.length - 1 ? '1px solid var(--color-divider)' : 'none',
              cursor: 'pointer', textAlign: 'left',
            }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8,
                background: f.color, color: '#FAF6EE',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}><Icon name="folder" size={18}/></div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)' }}>{f.name}</div>
                <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
                  {f.count} {f.count === 1 ? 'item' : 'items'}
                </div>
              </div>
              <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
            </button>
          ))}
        </Card>
      </div>
    </div>
  );
};

const FOLDER_COLORS = ['#C8552B', '#6B8E5A', '#3A6B8E', '#B57A2A', '#8C7B6B', '#7C5A8E', '#C99A3F', '#5A8E8E'];

const FolderEditScreen = ({ folder, onBack, onSave, onDelete, toast }) => {
  const [name, setName] = useStateP(folder?.name || '');
  const [color, setColor] = useStateP(folder?.color || FOLDER_COLORS[0]);
  const isNew = !folder;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title={isNew ? 'New folder' : 'Edit folder'}
        left={<IconBtn name="arrowLeft" onClick={onBack}/>}
        right={<Button size="sm" onClick={() => { onSave({ name, color }); toast?.(isNew ? 'Folder created' : 'Saved'); }}>Save</Button>}
      />
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'center', padding: '20px 0 24px' }}>
          <div style={{
            width: 80, height: 80, borderRadius: 18,
            background: color, color: '#FAF6EE',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 8px 20px rgba(0,0,0,0.10)',
          }}><Icon name="folder" size={36}/></div>
        </div>

        <Field label="Name">
          <TextInput value={name} onChange={setName} placeholder="e.g. Infrastructure"/>
        </Field>

        <Field label="Colour">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            {FOLDER_COLORS.map(c => (
              <button key={c} onClick={() => setColor(c)} style={{
                width: 36, height: 36, borderRadius: 18, background: c,
                border: color === c ? '3px solid var(--color-fg-emphasis)' : '3px solid transparent',
                cursor: 'pointer', padding: 0,
              }}/>
            ))}
          </div>
        </Field>

        {!isNew && (
          <div style={{ marginTop: 24 }}>
            <Button fullWidth variant="danger" icon="trash" onClick={() => { onDelete?.(folder); toast?.('Folder deleted'); }}>
              Delete folder
            </Button>
            <div style={{
              fontFamily: 'var(--font-sans)', fontSize: 11.5,
              color: 'var(--color-fg-secondary)', textAlign: 'center', marginTop: 8, lineHeight: 1.5,
            }}>
              The {folder.count} item{folder.count === 1 ? '' : 's'} in this folder will move to <em>Unfiled</em>.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const MoveToFolderSheet = ({ open, onClose, current, onPick, toast }) => (
  <Sheet open={open} onClose={onClose} title="Move to folder">
    <div style={{ padding: '0 16px 16px' }}>
      <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden' }}>
        {[{ id: null, name: 'Unfiled', color: 'var(--color-tile)' }, ...FOLDER_FIXTURE].map((f, i, arr) => (
          <button key={f.id || 'none'} onClick={() => { onPick?.(f); onClose(); }} style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: 12,
            padding: '12px 14px', background: 'transparent', border: 'none',
            borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
            cursor: 'pointer', textAlign: 'left',
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: 6,
              background: f.color || 'var(--color-tile)',
              color: f.id ? '#FAF6EE' : 'var(--color-fg-secondary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}><Icon name="folder" size={16}/></div>
            <div style={{ flex: 1, fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>
              {f.name}
            </div>
            {current === f.id && <Icon name="check" size={16} style={{ color: 'var(--color-accent)' }}/>}
          </button>
        ))}
      </div>
    </div>
  </Sheet>
);

const SystemAutofillPickerScreen = ({ onBack, onAutofill, onCreate, toast }) => {
  const [domain, setDomain] = useStateP('login.feldspar.fm');
  const matches = VAULT.filter(v =>
    v.kind === undefined || v.kind === 'login'
  ).filter(v => v.site && v.site.includes(domain.split('.').slice(-2, -1)[0]));
  const result = matches.length === 0 ? 'none' : matches.length === 1 ? 'one' : 'many';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'rgba(0,0,0,0.4)' }}>
      <div style={{ flex: 1, padding: '40px 16px 0', opacity: 0.6, pointerEvents: 'none' }}>
        <div style={{
          background: 'var(--color-surface-elevated)', borderRadius: 12,
          padding: '14px 14px', marginBottom: 12,
          fontFamily: 'var(--font-sans)', fontSize: 14, color: 'var(--color-fg-secondary)',
        }}>
          <Mono size={11}>https://{domain}/sign_in</Mono>
          <div style={{ marginTop: 12, padding: 8, background: 'var(--color-tile)', borderRadius: 6, fontFamily: 'var(--font-sans)', fontSize: 13 }}>Email</div>
          <div style={{ marginTop: 8, padding: 8, background: 'var(--color-tile)', borderRadius: 6, fontFamily: 'var(--font-sans)', fontSize: 13 }}>Password</div>
        </div>
      </div>

      <div style={{
        background: 'var(--color-surface)',
        borderTopLeftRadius: 18, borderTopRightRadius: 18,
        boxShadow: '0 -8px 24px rgba(0,0,0,0.18)',
        padding: '6px 0 16px',
      }}>
        <div style={{
          width: 36, height: 4, background: 'var(--color-border)',
          borderRadius: 2, margin: '6px auto 12px',
        }}/>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 16px 12px' }}>
          <div style={{
            width: 28, height: 28, borderRadius: 6, background: 'var(--color-accent)',
            color: 'var(--color-background)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}><Icon name="bolt" size={14}/></div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>RageDroid</div>
            <Mono size={10.5} style={{ color: 'var(--color-fg-secondary)' }}>autofill · {domain}</Mono>
          </div>
          <button onClick={onBack} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4 }}>
            <Icon name="x" size={18} style={{ color: 'var(--color-fg-secondary)' }}/>
          </button>
        </div>

        <div style={{ display: 'flex', gap: 4, padding: '0 16px 12px' }}>
          {['login.feldspar.fm', 'github.com', 'unknown-bank.com'].map(d => (
            <button key={d} onClick={() => setDomain(d)} style={{
              flex: 1, padding: '6px 8px', borderRadius: 6,
              background: domain === d ? 'var(--color-tile)' : 'transparent',
              border: '1px solid ' + (domain === d ? 'var(--color-border)' : 'transparent'),
              fontFamily: 'ui-monospace, monospace', fontSize: 10.5,
              color: 'var(--color-fg-secondary)', cursor: 'pointer',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>{d}</button>
          ))}
        </div>

        {result === 'none' && (
          <div style={{ padding: '20px 16px', textAlign: 'center' }}>
            <div style={{
              width: 48, height: 48, borderRadius: 24, margin: '0 auto 12px',
              background: 'var(--color-tile)', color: 'var(--color-fg-secondary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}><Icon name="search" size={20}/></div>
            <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 16, color: 'var(--color-fg-emphasis)' }}>No match for {domain}</div>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13, color: 'var(--color-fg-secondary)', marginTop: 4, lineHeight: 1.5 }}>
              Save your credentials here and they'll appear next time.
            </div>
            <Button onClick={onCreate} icon="plus" style={{ marginTop: 14 }}>Save new login</Button>
          </div>
        )}

        {result !== 'none' && (
          <div>
            {matches.slice(0, 3).map((it, i) => (
              <button key={it.id} onClick={() => onAutofill(it)} style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 12,
                padding: '12px 16px', background: 'transparent', border: 'none',
                borderTop: '1px solid var(--color-divider)',
                cursor: 'pointer', textAlign: 'left',
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8, background: 'var(--color-tile)',
                  color: 'var(--color-accent)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14,
                }}>{(it.name || '··').slice(0, 2).toUpperCase()}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14.5, color: 'var(--color-fg-emphasis)' }}>{it.name}</div>
                  <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>{it.username}</div>
                </div>
                {it.rage ? (
                  <span style={{
                    fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 700,
                    letterSpacing: '0.06em', textTransform: 'uppercase',
                    color: 'var(--color-accent)',
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                  }}><Icon name="tap" size={12}/> tap to fill</span>
                ) : (
                  <span style={{
                    fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
                    color: 'var(--color-fg-secondary)',
                  }}>fill</span>
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const QWERTY = [
  ['q','w','e','r','t','y','u','i','o','p'],
  ['a','s','d','f','g','h','j','k','l'],
  ['z','x','c','v','b','n','m'],
];

const CustomIMEScreen = ({ onBack, onAutofill, toast }) => {
  const matches = VAULT.filter(v => (v.kind === undefined || v.kind === 'login') && v.site).slice(0, 3);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        flex: 1, padding: '40px 16px 8px', background: 'var(--color-background)',
        display: 'flex', flexDirection: 'column',
      }}>
        <AppBar title="Sign in to Feldspar" subtitle="login.feldspar.fm"
          left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
        <div style={{ marginTop: 16 }}>
          <Field label="Email"><TextInput value="" onChange={() => {}} placeholder="you@example.com"/></Field>
          <Field label="Password"><TextInput value="" onChange={() => {}} placeholder="••••••••" type="password" mono/></Field>
        </div>
      </div>

      <div style={{
        background: 'var(--color-surface-sunken, #E8DDC9)',
        padding: '6px 6px 8px',
        borderTop: '1px solid var(--color-border)',
      }}>
        <div style={{
          background: 'var(--color-surface)', borderRadius: 10,
          padding: '8px 10px', marginBottom: 6,
          display: 'flex', gap: 8, alignItems: 'center', overflowX: 'auto',
        }}>
          <div style={{
            width: 24, height: 24, borderRadius: 4, background: 'var(--color-accent)',
            color: 'var(--color-background)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}><Icon name="bolt" size={12}/></div>
          {matches.map(m => (
            <button key={m.id} onClick={() => onAutofill(m)} style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '5px 10px', borderRadius: 14,
              background: 'var(--color-tile)', border: '1px solid var(--color-border)',
              fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
              color: 'var(--color-fg-emphasis)', cursor: 'pointer', flexShrink: 0,
            }}>
              {m.rage && <Icon name="tap" size={10} style={{ color: 'var(--color-accent)' }}/>}
              {m.name}
            </button>
          ))}
        </div>

        {QWERTY.map((row, i) => (
          <div key={i} style={{
            display: 'flex', justifyContent: 'center', gap: 4, marginBottom: 4,
            paddingLeft: i === 1 ? 14 : 0, paddingRight: i === 1 ? 14 : 0,
          }}>
            {i === 2 && (
              <div style={{ ...keyStyle, width: 38, fontSize: 11 }}><Icon name="arrowRight" size={14} style={{ transform: 'rotate(180deg)' }}/></div>
            )}
            {row.map(k => (
              <div key={k} style={{ ...keyStyle, flex: 1 }}>{k}</div>
            ))}
            {i === 2 && (
              <div style={{ ...keyStyle, width: 38, fontSize: 11 }}>⌫</div>
            )}
          </div>
        ))}
        <div style={{ display: 'flex', gap: 4 }}>
          <div style={{ ...keyStyle, width: 50, fontSize: 11 }}>?123</div>
          <div style={{ ...keyStyle, width: 32 }}>,</div>
          <div style={{ ...keyStyle, flex: 1 }}>space</div>
          <div style={{ ...keyStyle, width: 32 }}>.</div>
          <div style={{ ...keyStyle, width: 50, fontSize: 11 }}>↵</div>
        </div>
      </div>
    </div>
  );
};

const keyStyle = {
  height: 38, padding: '0 6px',
  background: 'var(--color-surface)',
  borderRadius: 6,
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  fontFamily: 'var(--font-sans)', fontSize: 15, fontWeight: 500,
  color: 'var(--color-fg-emphasis)',
  boxShadow: '0 1px 0 var(--color-border)',
  userSelect: 'none',
};

const TokenExpiredScreen = ({ onSignIn, onLater, toast }) => (
  <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '0 18px' }}>
    <AppBar title="" left={<IconBtn name="x" title="Close" onClick={onLater}/>}/>
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', textAlign: 'center', padding: '24px 0' }}>
      <div style={{
        width: 72, height: 72, borderRadius: 36, margin: '0 auto 20px',
        background: 'var(--color-warning, #C99A3F)', color: '#1A140A',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}><Icon name="clock" size={32}/></div>
      <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 26, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 12 }}>
        Session expired.
      </div>
      <div style={{ fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.55, color: 'var(--color-fg-secondary)', marginBottom: 8 }}>
        Your sign-in token timed out. The vault is still encrypted on this device -- you can keep reading cached items, but new syncs need a fresh token.
      </div>
      <div style={{ fontFamily: 'var(--font-serif)', fontStyle: 'italic', fontSize: 13.5, color: 'var(--color-fg-secondary)', marginBottom: 20 }}>
        No data left the device. No master password is required again.
      </div>
    </div>
    <Button fullWidth onClick={onSignIn} icon="key">Re-authenticate</Button>
    <button onClick={onLater} style={{
      background: 'transparent', border: 'none', padding: '14px 0', cursor: 'pointer',
      fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-secondary)',
    }}>Keep working offline</button>
  </div>
);

const OfflineBanner = ({ minutesStale = 12, onRetry }) => (
  <div style={{
    background: 'var(--color-warning, #C99A3F)', color: '#1A140A',
    padding: '8px 14px',
    display: 'flex', alignItems: 'center', gap: 10,
    fontFamily: 'var(--font-sans)', fontSize: 12.5,
  }}>
    <Icon name="alert" size={14}/>
    <div style={{ flex: 1 }}>
      <strong style={{ fontWeight: 700 }}>Offline.</strong> Showing snapshot from {minutesStale} min ago.
    </div>
    <button onClick={onRetry} style={{
      background: '#1A140A', color: '#FAF6EE', border: 'none',
      padding: '4px 10px', borderRadius: 12, cursor: 'pointer',
      fontFamily: 'var(--font-sans)', fontSize: 11.5, fontWeight: 600,
    }}>Retry</button>
  </div>
);

const SaveFailedBanner = ({ count = 1, onRetry, onView }) => (
  <div style={{
    background: 'var(--color-danger, #B5361A)', color: '#FAF6EE',
    padding: '8px 14px',
    display: 'flex', alignItems: 'center', gap: 10,
    fontFamily: 'var(--font-sans)', fontSize: 12.5,
  }}>
    <Icon name="alert" size={14}/>
    <div style={{ flex: 1 }}>
      <strong style={{ fontWeight: 700 }}>{count} pending</strong> · couldn't reach the server.
    </div>
    <button onClick={onRetry} style={{
      background: '#FAF6EE', color: '#1A140A', border: 'none',
      padding: '4px 10px', borderRadius: 12, cursor: 'pointer',
      fontFamily: 'var(--font-sans)', fontSize: 11.5, fontWeight: 600,
    }}>Retry</button>
  </div>
);

const EmptyVaultHero = ({ onAdd, onAutofill }) => (
  <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
    <AppBar title="Vault" subtitle="0 items"/>
    <div style={{ flex: 1, padding: '40px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
      <svg viewBox="0 0 120 120" style={{ width: 140, height: 140, marginBottom: 24 }}>
        <circle cx="60" cy="60" r="54" fill="none" stroke="var(--color-border)" strokeWidth="2"/>
        <circle cx="60" cy="60" r="38" fill="none" stroke="var(--color-border)" strokeWidth="2"/>
        <circle cx="60" cy="60" r="6"  fill="var(--color-accent)"/>
        <path d="M60 6 L60 22 M60 98 L60 114 M6 60 L22 60 M98 60 L114 60"
          stroke="var(--color-accent)" strokeWidth="2" strokeLinecap="round"/>
        <path d="M88 32 L92 28 M28 32 L24 28 M88 88 L92 92 M28 88 L24 92"
          stroke="var(--color-fg-secondary)" strokeWidth="1.5" strokeLinecap="round" opacity="0.5"/>
      </svg>

      <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 26, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 12 }}>
        An empty vault.
      </div>
      <div style={{ fontFamily: 'var(--font-serif)', fontSize: 15, lineHeight: 1.55, color: 'var(--color-fg-secondary)', marginBottom: 20, maxWidth: 280 }}>
        Add your first secret, or let RageDroid catch credentials as you sign into apps.
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%', maxWidth: 280 }}>
        <Button fullWidth icon="plus" onClick={onAdd}>Add your first secret</Button>
        <Button fullWidth variant="secondary" icon="bolt" onClick={onAutofill}>Catch a credential via autofill</Button>
      </div>

      <div style={{
        fontFamily: 'var(--font-serif)', fontStyle: 'italic',
        fontSize: 12.5, color: 'var(--color-fg-secondary)', marginTop: 24, lineHeight: 1.5,
      }}>
        Your vault syncs from <Mono size={11.5}>vault.feldspar.fm</Mono>. Nothing here yet.
      </div>
    </div>
  </div>
);

window.SettingsScreenFull       = SettingsScreenFull;
window.AccountScreen            = AccountScreen;
window.RecipientPickerSheet     = RecipientPickerSheet;
window.AddItemTypePickerScreen  = AddItemTypePickerScreen;
window.PasswordGeneratorSheet   = PasswordGeneratorSheet;
window.ItemHistoryScreen        = ItemHistoryScreen;
window.DeleteConfirmSheet       = DeleteConfirmSheet;
window.TapFailureScreen         = TapFailureScreen;
window.MultiIdentityPickerSheet = MultiIdentityPickerSheet;
window.FoldersScreen            = FoldersScreen;
window.FolderEditScreen         = FolderEditScreen;
window.MoveToFolderSheet        = MoveToFolderSheet;
window.SystemAutofillPickerScreen = SystemAutofillPickerScreen;
window.CustomIMEScreen          = CustomIMEScreen;
window.TokenExpiredScreen       = TokenExpiredScreen;
window.OfflineBanner            = OfflineBanner;
window.SaveFailedBanner         = SaveFailedBanner;
window.EmptyVaultHero           = EmptyVaultHero;
window.FOLDER_FIXTURE           = FOLDER_FIXTURE;
