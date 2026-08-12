const { useState: useStateW, useEffect: useEffectW } = React;

const FirstRun = ({ onDone, toast }) => {
  const [step, setStep] = useStateW(0);
  const [serverUrl, setServerUrl] = useStateW('https://vault.bitwarden.com');
  const [email, setEmail] = useStateW('maya@feldspar.fm');
  const [pw, setPw] = useStateW('');
  const [enrollPhase, setEnrollPhase] = useStateW('idle');
  const [enrollKind, setEnrollKind] = useStateW(null);
  const [showAdvancedEnroll, setShowAdvancedEnroll] = useStateW(false);

  const Logo = () => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{
        width: 32, height: 32, borderRadius: 8, background: 'var(--color-fg-emphasis)',
        color: 'var(--color-background)', display: 'flex', alignItems: 'center',
        justifyContent: 'center',
      }}>
        <Icon name="chain" size={18}/>
      </div>
      <div>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.01em', lineHeight: 1 }}>RageDroid</div>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 10, color: 'var(--color-fg-secondary)', marginTop: 2 }}>A LocalForge product</div>
      </div>
    </div>
  );

  const Step = ({ children }) => (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 22px 18px' }}>
      {children}
    </div>
  );

  const StepTitle = ({ kicker, title, sub }) => (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-accent)', marginBottom: 8 }}>{kicker}</div>
      <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 28, lineHeight: 1.15, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 8 }}>{title}</div>
      {sub && <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, lineHeight: 1.5, color: 'var(--color-fg-secondary)' }}>{sub}</div>}
    </div>
  );

  if (step === 0) return (
    <Step>
      <div style={{ marginBottom: 36 }}><Logo/></div>
      <div style={{ flex: 1 }}>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 400, fontSize: 14, fontStyle: 'italic', color: 'var(--color-fg-secondary)', marginBottom: 14 }}>A phishing-resistant Bitwarden client.</div>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 32, lineHeight: 1.1, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.02em', marginBottom: 20 }}>The master password leaking does not leak any of the actual secrets.</div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, lineHeight: 1.55, color: 'var(--color-fg-primary)', marginBottom: 16 }}>
          RageDroid wraps every secret in an additional <em>age</em> envelope. Unlocking any individual credential requires a hardware tap -- your YubiKey, the FIDO2 authenticator in your laptop, or this phone's secure element.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, lineHeight: 1.55, color: 'var(--color-fg-primary)' }}>
          Both layers are needed to read a secret. Steal one, learn nothing.
        </div>
      </div>
      <Button fullWidth onClick={() => setStep(1)} icon="arrowRight">Begin setup</Button>
      <div style={{ textAlign: 'center', marginTop: 14, fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)' }}>
        Existing Bitwarden vault required · age/rage compatible · open source
      </div>
    </Step>
  );

  if (step === 1) return (
    <Step>
      <StepTitle kicker="Step 1 of 3" title="Sign in to your vault" sub={<>Connect your Bitwarden vault. <button type="button" onClick={() => setServerUrl('https://')} style={{ background: 'none', border: 0, padding: 0, color: 'var(--color-accent)', textDecoration: 'underline', font: 'inherit', cursor: 'pointer' }}>Use a self-hosted server</button>.</>}/>
      <div style={{ flex: 1 }}>
        <Field label="Server">
          <TextInput value={serverUrl} onChange={setServerUrl} mono/>
        </Field>
        <Field label="Email">
          <TextInput value={email} onChange={setEmail}/>
        </Field>
        <Field label="Master password">
          <TextInput value={pw} onChange={setPw} type="password" placeholder="••••••••••••"/>
        </Field>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <Button variant="ghost" onClick={() => setStep(0)}>Back</Button>
        <Button fullWidth onClick={() => { setPw('•'.repeat(14)); setStep(2); }} icon="arrowRight">Sign in & continue</Button>
      </div>
    </Step>
  );

  if (step === 2) {
    const trigger = () => {
      setEnrollPhase('listening');
      setTimeout(() => setEnrollPhase('found'), 1400);
      setTimeout(() => setEnrollPhase('generating'), 2400);
      setTimeout(() => setEnrollPhase('done'), 3800);
    };

    if (!enrollKind) {
      const passkeyOptions = [
        { id: 'platform', icon: 'fingerprint', name: 'This phone',
          desc: 'Use the secure element + biometrics already on this device.',
          tag: 'Fastest', recommended: true },
        { id: 'security-key', icon: 'key', name: 'A security key',
          desc: 'YubiKey, Solo, Titan, or any FIDO2 authenticator. Tap to confirm each unlock.' },
      ];
      const advancedOptions = [
        { id: 'yubikey-piv', icon: 'usb', name: 'YubiKey (PIV mode)',
          desc: 'Pin a key to PIV slot 95 with an X25519 keypair. Power-user path.' },
      ];

      const OptionRow = ({ o }) => (
        <div onClick={() => { setEnrollKind(o.id); setEnrollPhase('idle'); }} style={{
          padding: '14px 14px',
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 10, cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'flex-start',
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: 'var(--color-tile)', color: 'var(--color-accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Icon name={o.icon} size={18}/>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)', whiteSpace: 'nowrap' }}>{o.name}</span>
              {o.recommended && <span style={{
                fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em',
                color: 'var(--color-success)', padding: '2px 6px',
                border: '1px solid var(--color-success)', borderRadius: 4,
              }}>Recommended</span>}
              {o.tag && !o.recommended && <span style={{
                fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em',
                color: 'var(--color-fg-secondary)',
              }}>{o.tag}</span>}
            </div>
            <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.45 }}>{o.desc}</div>
          </div>
          <Icon name="chevronRight" size={18} style={{ color: 'var(--color-fg-secondary)', marginTop: 8 }}/>
        </div>
      );

      return (
        <Step>
          <StepTitle kicker="Step 2 of 3" title="Enroll your first passkey" sub="Pick how you want to authorize unlocks. Each unlock takes a tap. The private key is generated on the device and never leaves it."/>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {passkeyOptions.map(o => <OptionRow key={o.id} o={o}/>)}
          </div>

          <div style={{ marginTop: 14 }}>
            {!showAdvancedEnroll ? (
              <button onClick={() => setShowAdvancedEnroll(true)} style={{
                background: 'transparent', border: 'none', cursor: 'pointer', padding: 0,
                fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 600,
                color: 'var(--color-fg-secondary)', display: 'inline-flex', alignItems: 'center', gap: 4,
              }}>More options <Icon name="chevronDown" size={12}/></button>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {advancedOptions.map(o => <OptionRow key={o.id} o={o}/>)}
              </div>
            )}
          </div>

          <div style={{ flex: 1 }}/>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button variant="ghost" onClick={() => setStep(1)}>Back</Button>
          </div>
        </Step>
      );
    }

    const kindCopy = {
      'platform':     { title: 'Enroll this phone', sub: 'Generates a passkey backed by the device secure element. Biometric to unlock.', idleHint: 'Tap to start. You\'ll be asked to confirm with biometrics.', listeningHint: 'Authenticating with the secure element...', genTitle: 'Generating device passkey', genMeta: 'StrongBox · curve25519', doneTitle: 'This phone enrolled' },
      'security-key': { title: 'Enroll a security key', sub: 'Insert via USB-C, or hold to the back of the phone for NFC. The key generates its own keypair.', idleHint: 'Insert via USB-C, or hold the key to the back of the phone.', listeningHint: 'Listening for NFC and USB-C...', genTitle: 'Generating keypair on device', genMeta: 'FIDO2 · curve25519', doneTitle: 'Security key enrolled' },
      'yubikey-piv':  { title: 'Enroll a YubiKey (PIV)', sub: 'RageDroid generates an X25519 keypair on the YubiKey itself. The private key never leaves the device.', idleHint: 'Insert via USB-C, or hold the YubiKey to the back of the phone.', listeningHint: 'Listening for NFC and USB-C...', genTitle: 'Generating X25519 keypair', genMeta: 'PIV slot 95 · curve25519', doneTitle: 'Primary YubiKey enrolled' },
    }[enrollKind];

    return (
      <Step>
        <StepTitle kicker="Step 2 of 3" title={kindCopy.title} sub={kindCopy.sub}/>

        <div style={{
          background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
          borderRadius: 12, padding: 18, marginBottom: 14, position: 'relative', overflow: 'hidden',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 130, position: 'relative' }}>
            {(enrollPhase === 'listening' || enrollPhase === 'idle') && (
              <>
                {enrollPhase === 'listening' && [0, 0.5].map(d => (
                  <span key={d} style={{
                    position: 'absolute', width: 110, height: 110, borderRadius: '50%',
                    border: '2px solid var(--color-accent)', opacity: 0.25,
                    animation: `ripple 1.6s var(--ease-out) infinite ${d}s`,
                  }}/>
                ))}
                <div style={{
                  width: 80, height: 80, borderRadius: 40, background: 'var(--color-tile)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--color-accent)', position: 'relative', zIndex: 1,
                }}>
                  <Icon name={enrollKind === 'platform' ? 'fingerprint' : 'key'} size={36}/>
                </div>
              </>
            )}
            {enrollPhase === 'found' && (
              <div style={{
                width: 80, height: 80, borderRadius: 40, background: 'var(--color-success)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#FAF6EE',
              }}>
                <Icon name="check" size={36}/>
              </div>
            )}
            {enrollPhase === 'generating' && (
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18, color: 'var(--color-fg-emphasis)' }}>{kindCopy.genTitle}</div>
                <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 8, display: 'block' }}>{kindCopy.genMeta}</Mono>
                <div style={{ marginTop: 12, height: 2, background: 'var(--color-tile)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: 'var(--color-accent)', animation: 'progress-fill 1.4s var(--ease-out) forwards' }}/>
                </div>
              </div>
            )}
            {enrollPhase === 'done' && (
              <div style={{ textAlign: 'center' }}>
                <div style={{ width: 60, height: 60, borderRadius: 30, background: 'var(--color-success)', color: '#FAF6EE', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 12 }}>
                  <Icon name="check" size={26}/>
                </div>
                <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 16, color: 'var(--color-fg-emphasis)' }}>{kindCopy.doneTitle}</div>
                <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 4, display: 'block' }}>{enrollKind === 'platform' ? 'StrongBox · age1strongbox1qfn4mt6jr3xc...' : 'serial 24 619 482 · age1yubikey1qfn4mt6jr3xc...'}</Mono>
              </div>
            )}
          </div>
          <div style={{
            fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-secondary)',
            textAlign: 'center', marginTop: 6,
          }}>
            {enrollPhase === 'idle' && kindCopy.idleHint}
            {enrollPhase === 'listening' && kindCopy.listeningHint}
            {enrollPhase === 'found' && 'Authenticator detected.'}
            {enrollPhase === 'generating' && (enrollKind === 'platform' ? 'Confirm with your fingerprint.' : 'Touch the authenticator to confirm key generation.')}
            {enrollPhase === 'done' && 'Recorded as a recipient in your "RageDroid Recipients" secure note.'}
          </div>
        </div>

        <StatusMessage tone="info" style={{ marginBottom: 14 }}>
          If this authenticator is lost <em style={{ fontFamily: 'var(--font-serif)' }}>and</em> you've enrolled no backup recipients, your protected secrets become unrecoverable. We'll add a backup in step 3.
        </StatusMessage>

        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="ghost" onClick={() => { setEnrollKind(null); setEnrollPhase('idle'); }}>Back</Button>
          {enrollPhase === 'idle' && <Button fullWidth onClick={trigger} icon="tap">Tap to begin</Button>}
          {enrollPhase !== 'idle' && enrollPhase !== 'done' && <Button fullWidth disabled>Enrolling...</Button>}
          {enrollPhase === 'done' && <Button fullWidth onClick={() => setStep(3)} icon="arrowRight">Continue</Button>}
        </div>
      </Step>
    );
  }

  if (step === 3) return (
    <Step>
      <StepTitle kicker="Step 3 of 3" title="Add a backup recipient" sub="A second way in, in case your YubiKey is lost. Recommended."/>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'yk-backup', kind: 'yubikey', name: 'A second YubiKey', desc: 'Physical key kept somewhere safe. Same model or different.', recommended: true },
          { id: 'strongbox', kind: 'strongbox', name: 'This phone (StrongBox)', desc: 'TEE-backed key on this device. Convenient, but tied to this hardware.' },
          { id: 'recovery', kind: 'recovery', name: 'Paper recovery identity', desc: 'Printable age identity. Print, store offline, never type into a screen.' },
        ].map(o => (
          <div key={o.id} style={{
            padding: '14px 14px',
            background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
            borderRadius: 10, cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'flex-start',
          }} onClick={() => { toast?.(`${o.name} -- set up later in Settings`); setStep(4); }}>
            <div style={{
              width: 36, height: 36, borderRadius: 8,
              background: 'var(--color-tile)', color: 'var(--color-accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
            }}>
              <Icon name={recipientKindIcon(o.kind)} size={18}/>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)', whiteSpace: 'nowrap' }}>{o.name}</span>
                {o.recommended && <span style={{
                  fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
                  textTransform: 'uppercase', letterSpacing: '0.06em',
                  color: 'var(--color-success)', padding: '2px 6px',
                  border: '1px solid var(--color-success)', borderRadius: 4,
                }}>Recommended</span>}
              </div>
              <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.45 }}>{o.desc}</div>
            </div>
            <Icon name="chevronRight" size={18} style={{ color: 'var(--color-fg-secondary)', marginTop: 8 }}/>
          </div>
        ))}
      </div>
      <div style={{ flex: 1 }}/>
      <div style={{ display: 'flex', gap: 8 }}>
        <Button variant="ghost" onClick={() => setStep(2)}>Back</Button>
        <Button variant="secondary" fullWidth onClick={onDone}>Skip -- I'll add later</Button>
      </div>
    </Step>
  );

  return (
    <Step>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <div style={{
          width: 64, height: 64, borderRadius: 32, background: 'var(--color-success)',
          color: '#FAF6EE', display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          marginBottom: 24,
        }}>
          <Icon name="check" size={32}/>
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 30, lineHeight: 1.15, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.015em', marginBottom: 16 }}>
          Setup complete.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 16, lineHeight: 1.55, color: 'var(--color-fg-primary)', marginBottom: 12 }}>
          Your vault is now syncing. New items default to <em>protected</em>. Existing items are unchanged -- you can convert them in batches from Settings.
        </div>
        <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14, fontStyle: 'italic', color: 'var(--color-fg-secondary)', lineHeight: 1.5 }}>
          One tap per reveal. No caching, no exceptions.
        </div>
      </div>
      <Button fullWidth onClick={onDone} icon="arrowRight">Open vault</Button>
    </Step>
  );
};

const TYPE_TITLE_NEW  = { login: 'New login',  card: 'New card',  note: 'New note',  identity: 'New identity',  ssh: 'New SSH key' };
const TYPE_TITLE_EDIT = { login: 'Edit login', card: 'Edit card', note: 'Edit note', identity: 'Edit identity', ssh: 'Edit SSH key' };

const AddItemScreen = ({ itemType = 'login', existing = null, defaultRecipientIds, onBack, onSave, toast }) => {
  const isEdit = !!existing;
  const it = existing?.kind || itemType;
  const [name, setName]       = useStateW(existing?.name      || '');
  const [user, setUser]       = useStateW(existing?.username  || '');
  const [site, setSite]       = useStateW(existing?.site      || '');
  const [pw, setPw]           = useStateW(existing?.password  || '');
  const [notes, setNotes]     = useStateW(existing?.body      || existing?.notes || '');
  const [cardholder, setCardholder] = useStateW(existing?.cardholder || '');
  const [cardNumber, setCardNumber] = useStateW(existing?.cardNumber || '');
  const [cardExp, setCardExp]       = useStateW(existing?.cardExp    || '');
  const [cardCvv, setCardCvv]       = useStateW(existing?.cardCvv    || '');
  const [idFirst, setIdFirst] = useStateW(existing?.firstName || '');
  const [idLast, setIdLast]   = useStateW(existing?.lastName  || '');
  const [idEmail, setIdEmail] = useStateW(existing?.email     || '');
  const [idPhone, setIdPhone] = useStateW(existing?.phone     || '');
  const [sshType, setSshType] = useStateW(existing?.sshType   || 'ed25519');
  const [sshPriv, setSshPriv] = useStateW(existing?.privateKey || '');

  const [folder, setFolder]   = useStateW(existing?.folder    || null);
  const [protect, setProtect] = useStateW(existing ? !!existing.rage : true);
  const [chosen, setChosen]   = useStateW(existing?.recipients || defaultRecipientIds || ['yk-primary', 'yk-backup', 'recovery']);
  const [showPicker, setShowPicker] = useStateW(false);
  const [showGen, setShowGen] = useStateW(false);
  const [showFolder, setShowFolder] = useStateW(false);

  const save = () => {
    onSave({
      ...(existing || {}),
      name: name || ('Untitled ' + it),
      kind: it, username: user, site, password: pw,
      rage: protect, recipients: chosen, folder,
    });
    toast?.(isEdit
      ? 'Saved · re-encrypting under ' + chosen.length + ' recipient' + (chosen.length === 1 ? '' : 's')
      : 'Saved · re-encrypting under ' + chosen.length + ' recipient' + (chosen.length === 1 ? '' : 's'));
  };

  const titleMap = isEdit ? TYPE_TITLE_EDIT : TYPE_TITLE_NEW;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title={titleMap[it] || (isEdit ? 'Edit item' : 'New item')} left={<IconBtn name="arrowLeft" onClick={onBack}/>}
        right={<Button size="sm" onClick={save}>Save</Button>}/>

      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px 24px' }}>

        <Field label="Name"><TextInput value={name} onChange={setName} placeholder={
          it === 'card' ? 'e.g. Amex -- personal' :
          it === 'note' ? 'e.g. Apartment alarm code' :
          it === 'identity' ? 'e.g. Maya -- primary' :
          it === 'ssh' ? 'e.g. ed25519 -- laptop' :
          'e.g. Stripe -- production'
        }/></Field>

        {it === 'login' && (
          <>
            <Field label="Website"><TextInput value={site} onChange={setSite} placeholder="dashboard.stripe.com" mono/></Field>
            <Field label="Username"><TextInput value={user} onChange={setUser} placeholder="you@example.com"/></Field>
            <Field label="Password" hint="Generate a strong password -- RageDroid will encrypt it before saving.">
              <div style={{ display: 'flex', gap: 8 }}>
                <TextInput value={pw} onChange={setPw} placeholder="••••••" type="password" mono/>
                <Button variant="secondary" size="sm" icon="refresh" onClick={() => setShowGen(true)}>Gen</Button>
              </div>
            </Field>
          </>
        )}

        {it === 'card' && (
          <>
            <Field label="Cardholder"><TextInput value={cardholder} onChange={setCardholder} placeholder="Maya Voss"/></Field>
            <Field label="Card number"><TextInput value={cardNumber} onChange={setCardNumber} placeholder="•••• •••• •••• ••••" mono/></Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Field label="Expiry"><TextInput value={cardExp} onChange={setCardExp} placeholder="MM / YY" mono/></Field>
              <Field label="CVV"><TextInput value={cardCvv} onChange={setCardCvv} placeholder="•••" mono type="password"/></Field>
            </div>
          </>
        )}

        {it === 'note' && (
          <Field label="Note" hint="Plaintext encrypted under your recipients. No structure.">
            <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={8} placeholder="Anything that should never be in plaintext."
              style={{
                width: '100%', boxSizing: 'border-box', resize: 'vertical',
                padding: '10px 12px', borderRadius: 8,
                background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
                fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.5,
                color: 'var(--color-fg-primary)',
              }}/>
          </Field>
        )}

        {it === 'identity' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Field label="First name"><TextInput value={idFirst} onChange={setIdFirst} placeholder="Maya"/></Field>
              <Field label="Last name"><TextInput value={idLast} onChange={setIdLast} placeholder="Voss"/></Field>
            </div>
            <Field label="Email"><TextInput value={idEmail} onChange={setIdEmail} placeholder="maya@feldspar.fm"/></Field>
            <Field label="Phone"><TextInput value={idPhone} onChange={setIdPhone} placeholder="+1 ..." mono/></Field>
          </>
        )}

        {it === 'ssh' && (
          <>
            <Field label="Key type">
              <div style={{ display: 'flex', background: 'var(--color-tile)', borderRadius: 8, padding: 3 }}>
                {['ed25519','rsa-4096','ecdsa-p256'].map(k => (
                  <button key={k} onClick={() => setSshType(k)} style={{
                    flex: 1, padding: '8px 8px',
                    background: sshType === k ? 'var(--color-surface)' : 'transparent',
                    border: 'none', borderRadius: 6,
                    fontFamily: 'ui-monospace, monospace', fontSize: 12, fontWeight: 600,
                    color: sshType === k ? 'var(--color-fg-emphasis)' : 'var(--color-fg-secondary)',
                    cursor: 'pointer',
                  }}>{k}</button>
                ))}
              </div>
            </Field>
            <Field label="Private key" hint="Paste an existing key, or tap Generate to create one on this device.">
              <textarea value={sshPriv} onChange={e => setSshPriv(e.target.value)} rows={5} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..."
                style={{
                  width: '100%', boxSizing: 'border-box', resize: 'vertical',
                  padding: '10px 12px', borderRadius: 8,
                  background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
                  fontFamily: 'ui-monospace, monospace', fontSize: 12, lineHeight: 1.45,
                  color: 'var(--color-fg-primary)',
                }}/>
              <div style={{ marginTop: 8 }}>
                <Button size="sm" variant="secondary" icon="refresh" onClick={() => { setSshPriv('-----BEGIN OPENSSH PRIVATE KEY-----\n...generated on device...\n-----END OPENSSH PRIVATE KEY-----'); toast?.('Generated ' + sshType); }}>Generate {sshType}</Button>
              </div>
            </Field>
          </>
        )}

        <Field label="Folder">
          <button onClick={() => setShowFolder(true)} style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 12px', borderRadius: 8,
            background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
            cursor: 'pointer', textAlign: 'left',
          }}>
            <Icon name="folder" size={16} style={{ color: folder ? 'var(--color-accent)' : 'var(--color-fg-secondary)' }}/>
            <span style={{ flex: 1, fontFamily: 'var(--font-sans)', fontSize: 13.5, color: folder ? 'var(--color-fg-emphasis)' : 'var(--color-fg-secondary)' }}>
              {folder ? (FOLDER_FIXTURE.find(f => f.id === folder)?.name || 'Folder') : 'Unfiled'}
            </span>
            <Icon name="chevronDown" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
          </button>
        </Field>

        <div style={{
          padding: '12px 14px',
          background: protect ? 'var(--color-tile)' : 'var(--color-surface-sunken)',
          border: '1px solid ' + (protect ? 'var(--color-accent)' : 'var(--color-border)'),
          borderRadius: 10, marginBottom: 14,
          transition: 'all var(--dur-base) var(--ease-out)',
        }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
            <div style={{
              width: 36, height: 36, borderRadius: 8,
              background: 'var(--color-surface)', border: '1px solid var(--color-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: protect ? 'var(--color-accent)' : 'var(--color-fg-secondary)',
              flexShrink: 0,
            }}>
              <Icon name="chain" size={18}/>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)' }}>Protect with RageDroid</div>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
                Each reveal will require a tap on one of the recipients below.
              </div>
            </div>
            <span style={{
              width: 40, height: 24, borderRadius: 12, position: 'relative',
              background: protect ? 'var(--color-accent)' : 'var(--color-border)',
              transition: 'background var(--dur-fast)',
              flexShrink: 0,
            }}>
              <span style={{
                position: 'absolute', top: 2, left: protect ? 18 : 2,
                width: 20, height: 20, borderRadius: 10, background: '#FAF6EE',
                transition: 'left var(--dur-fast) var(--ease-out)',
              }}/>
            </span>
            <input type="checkbox" checked={protect} onChange={e => setProtect(e.target.checked)} style={{ display: 'none' }}/>
          </label>
        </div>

        {protect && (
          <Field label="Unlock recipients" hint="Any of the selected recipients can decrypt this item.">
            <button onClick={() => setShowPicker(true)} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 12px', borderRadius: 8, textAlign: 'left',
              background: 'var(--color-surface-sunken)', border: '1px solid var(--color-border)',
              cursor: 'pointer',
            }}>
              <div style={{ flex: 1, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
                {chosen.length === 0 ? (
                  <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-secondary)' }}>Pick at least one recipient</span>
                ) : chosen.map(rid => {
                  const r = RECIPIENTS.find(x => x.id === rid);
                  if (!r) return null;
                  return (
                    <span key={rid} style={{
                      display: 'inline-flex', alignItems: 'center', gap: 5,
                      padding: '3px 8px', borderRadius: 12,
                      background: 'var(--color-tile)',
                      fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 500,
                      color: 'var(--color-fg-emphasis)',
                    }}>
                      <RecipientPip kind={r.kind} size={8}/>
                      {r.name}
                    </span>
                  );
                })}
              </div>
              <Icon name="chevronRight" size={14} style={{ color: 'var(--color-fg-secondary)' }}/>
            </button>
          </Field>
        )}
      </div>

      <RecipientPickerSheet
        open={showPicker} onClose={() => setShowPicker(false)}
        value={chosen} onChange={setChosen} toast={toast}
      />
      <PasswordGeneratorSheet
        open={showGen} onClose={() => setShowGen(false)}
        onUse={(p) => setPw(p)} toast={toast}
      />
      <MoveToFolderSheet
        open={showFolder} onClose={() => setShowFolder(false)} current={folder}
        onPick={(f) => setFolder(f.id)} toast={toast}
      />
    </div>
  );
};

const RecipientCard = ({ r, onClick }) => (
  <div onClick={onClick} style={{
    padding: '14px 14px', display: 'flex', gap: 12, alignItems: 'flex-start',
    borderBottom: '1px solid var(--color-divider)', cursor: 'pointer',
  }}>
    <div style={{
      width: 40, height: 40, borderRadius: 8,
      background: 'var(--color-tile)', color: 'var(--color-accent)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      flexShrink: 0,
    }}>
      <Icon name={recipientKindIcon(r.kind)} size={20}/>
    </div>
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
        <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)', letterSpacing: '-0.005em' }}>{r.name}</span>
        <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)' }}>{r.lastUsed}</span>
      </div>
      <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginTop: 3 }}>
        {recipientKindLabel(r.kind)}
      </div>
      <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 4, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {r.fingerprint}
      </Mono>
      <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, height: 3, background: 'var(--color-surface-sunken)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ width: `${(r.coverage / VAULT.filter(v => v.rage).length) * 100}%`, height: '100%', background: 'var(--color-accent)' }}/>
        </div>
        <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-fg-secondary)' }}>
          {r.coverage} / {VAULT.filter(v => v.rage).length} items
        </span>
      </div>
    </div>
  </div>
);

const SettingsScreen = ({ onBack, onAddRecipient, onOpenRecipient, onOpenAuditLog, toast }) => (
  <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
    <AppBar title="Settings" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
    <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 24px' }}>

      <div style={{ padding: '16px 18px 8px' }}>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginBottom: 8 }}>Account</div>
        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10, padding: '12px 14px' }}>
          <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)' }}>maya@feldspar.fm</div>
          <Mono size={11} style={{ color: 'var(--color-fg-secondary)', marginTop: 2, display: 'block' }}>vault.feldspar.fm · 36 items synced</Mono>
        </div>
      </div>

      <div style={{ padding: '20px 18px 0' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)' }}>Recipients</div>
          <button onClick={onAddRecipient} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 0, display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--color-accent)', fontFamily: 'var(--font-sans)', fontSize: 12.5, fontWeight: 600 }}>
            <Icon name="plus" size={13}/> Add
          </button>
        </div>
      </div>
      <div style={{ background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}>
        {RECIPIENTS.map(r => <RecipientCard key={r.id} r={r} onClick={() => onOpenRecipient ? onOpenRecipient(r) : toast?.(`${r.name} -- detail not implemented`)}/>)}
      </div>

      <div style={{ padding: '20px 18px 0' }}>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginBottom: 8 }}>Activity</div>
      </div>
      <div style={{ background: 'var(--color-surface)', borderTop: '1px solid var(--color-border)', borderBottom: '1px solid var(--color-border)' }}>
        <button onClick={onOpenAuditLog} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 12,
          padding: '14px 18px', background: 'transparent', border: 'none', cursor: 'pointer',
          textAlign: 'left',
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, background: 'var(--color-tile)',
            color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}><Icon name="clock" size={16}/></div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>Recent unlocks</div>
            <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11.5, color: 'var(--color-fg-secondary)', marginTop: 2 }}>
              {typeof ACTIVITY !== 'undefined' ? `${ACTIVITY.length} entries · stored on this device` : 'On-device audit log'}
            </div>
          </div>
          <Icon name="chevronRight" size={16} style={{ color: 'var(--color-fg-secondary)' }}/>
        </button>
      </div>

      <div style={{ padding: '20px 18px 8px' }}>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-fg-secondary)', marginBottom: 8 }}>Security posture</div>
        <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden' }}>
          {[
            { label: 'Tap-per-reveal', value: 'Enforced', kind: 'success' },
            { label: 'Decrypted-secret cache', value: 'Disabled', kind: 'success' },
            { label: 'Autofill', value: 'One tap per fill' },
            { label: 'TOTP support', value: 'Built in' },
          ].map((row, i, arr) => (
            <div key={row.label} style={{
              padding: '12px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              borderBottom: i < arr.length - 1 ? '1px solid var(--color-divider)' : 'none',
            }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13.5, color: 'var(--color-fg-primary)' }}>{row.label}</span>
              <span style={{
                fontFamily: 'var(--font-sans)', fontSize: 12.5, fontWeight: 600,
                color: row.kind === 'success' ? 'var(--color-success)' : row.kind === 'muted' ? 'var(--color-fg-secondary)' : 'var(--color-fg-primary)',
              }}>{row.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: '24px 18px 0', textAlign: 'center' }}>
        <div style={{ fontFamily: 'var(--font-serif)', fontStyle: 'italic', fontSize: 13.5, lineHeight: 1.5, color: 'var(--color-fg-secondary)' }}>
          RageDroid 0.4.1 · A LocalForge product<br/>
          age 1.2.0 · yubikit-android 2.5
        </div>
      </div>
    </div>
  </div>
);

const AddRecipientScreen = ({ onBack, onPaperRecovery, onAddPasskey, toast }) => {
  const [phase, setPhase] = useStateW('pick');
  const [kind, setKind] = useStateW(null);
  const [enrollPhase, setEnrollPhase] = useStateW('idle');
  const [enrollError, setEnrollError] = useStateW(null);

  const trigger = (k) => {
    if (k === 'recovery' && onPaperRecovery) { onPaperRecovery(); return; }
    setKind(k);
    setEnrollError(null);
    setPhase('enroll');
    if (k === 'fido2' && typeof onAddPasskey === 'function') {
      setEnrollPhase('listening');
      Promise.resolve(onAddPasskey({ label: 'Browser passkey' }))
        .then(() => {
          setEnrollPhase('done');
        })
        .catch((err) => {
          setEnrollError((err && err.message) || String(err));
          setEnrollPhase('idle');
        });
      return;
    }
    setEnrollPhase('listening');
    setTimeout(() => setEnrollPhase('found'), 1400);
    setTimeout(() => setEnrollPhase('done'), 2800);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <AppBar title="Add recipient" left={<IconBtn name="arrowLeft" onClick={onBack}/>}/>
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 16px 24px' }}>
        {phase === 'pick' && (() => {
          const enrolledKinds = new Set(RECIPIENTS.map(r => r.kind));
          const yubiCount = RECIPIENTS.filter(r => r.kind === 'yubikey').length;
          const hasRecovery = enrolledKinds.has('recovery');
          const hasStrongbox = enrolledKinds.has('strongbox');

          const ALL = [
            { k: 'yubikey',   name: 'YubiKey (PIV slot)',     desc: 'X25519 keypair on the device. Identical to age-plugin-yubikey.' },
            { k: 'fido2',     name: 'FIDO2 hmac-secret',      desc: 'Any FIDO2 authenticator. Tap is built into the protocol.' },
            { k: 'strongbox', name: 'This phone (StrongBox)', desc: 'TEE-backed key. Convenient, but tied to this device.' },
            { k: 'recovery',  name: 'Paper recovery identity',desc: 'Printable age identity. No-network backup.' },
          ];

          const reason = (k) => {
            if (k === 'recovery' && !hasRecovery) return 'Survives losing every device.';
            if (k === 'yubikey' && yubiCount < 2) return yubiCount === 0 ? 'Hardware-rooted protection.' : 'A backup key prevents single-point-of-failure lockout.';
            if (k === 'fido2' && yubiCount === 0) return 'Use any passkey-capable authenticator.';
            if (k === 'strongbox' && !hasStrongbox) return 'Convenience tier for everyday unlocks.';
            return null;
          };

          const groups = { recommended: [], available: [], enrolled: [] };
          ALL.forEach(o => {
            const r = reason(o.k);
            if (o.k === 'strongbox' && hasStrongbox) groups.enrolled.push({ ...o, note: 'Enrolled on this device' });
            else if (o.k === 'recovery' && hasRecovery) groups.enrolled.push({ ...o, note: 'Recovery identity active -- re-print available in Settings' });
            else if (r) groups.recommended.push({ ...o, reason: r });
            else groups.available.push(o);
          });

          const Card = ({ o, recommended }) => (
            <div onClick={() => trigger(o.k)} style={{
              padding: '14px', marginBottom: 8,
              background: 'var(--color-surface-elevated)',
              border: '1px solid ' + (recommended ? 'var(--color-accent)' : 'var(--color-border)'),
              borderRadius: 10, cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'flex-start',
              position: 'relative',
            }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8, background: 'var(--color-tile)',
                color: 'var(--color-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}><Icon name={recipientKindIcon(o.k)} size={18}/></div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 15, color: 'var(--color-fg-emphasis)' }}>{o.name}</span>
                  {recommended && (
                    <span style={{
                      fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 600,
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                      color: 'var(--color-accent)',
                      padding: '2px 6px', borderRadius: 4,
                      background: 'var(--color-tile)',
                    }}>Recommended</span>
                  )}
                </div>
                <div style={{ fontFamily: 'var(--font-serif)', fontSize: 13.5, color: 'var(--color-fg-secondary)', lineHeight: 1.4, marginTop: 2 }}>{o.desc}</div>
                {o.reason && (
                  <div style={{
                    fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-accent)',
                    marginTop: 6, fontWeight: 600,
                  }}>{o.reason}</div>
                )}
              </div>
              <Icon name="chevronRight" size={18} style={{ color: 'var(--color-fg-secondary)', marginTop: 8 }}/>
            </div>
          );

          const SectionLabel = ({ children }) => (
            <div style={{
              fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 600,
              letterSpacing: '0.08em', textTransform: 'uppercase',
              color: 'var(--color-fg-secondary)', marginTop: 18, marginBottom: 8,
            }}>{children}</div>
          );

          return (
            <div style={{ padding: '6px 0' }}>
              <div style={{
                fontFamily: 'var(--font-serif)', fontSize: 16, lineHeight: 1.5,
                color: 'var(--color-fg-secondary)', marginBottom: 16, padding: '0 2px',
              }}>
                A recipient is anything that can decrypt one of the age stanzas in your vault. Pick a kind.
              </div>

              {groups.recommended.length > 0 && (
                <>
                  <SectionLabel>Recommended next</SectionLabel>
                  {groups.recommended.map(o => <Card key={o.k} o={o} recommended/>)}
                </>
              )}

              {groups.available.length > 0 && (
                <>
                  <SectionLabel>Other options</SectionLabel>
                  {groups.available.map(o => <Card key={o.k} o={o}/>)}
                </>
              )}

              {groups.enrolled.length > 0 && (
                <>
                  <SectionLabel>Already enrolled</SectionLabel>
                  {groups.enrolled.map(o => (
                    <div key={o.k} style={{
                      padding: '12px 14px', marginBottom: 8,
                      background: 'var(--color-surface-sunken)',
                      border: '1px solid var(--color-border)', borderRadius: 10,
                      display: 'flex', gap: 12, alignItems: 'flex-start', opacity: 0.7,
                    }}>
                      <div style={{
                        width: 32, height: 32, borderRadius: 8, background: 'var(--color-tile)',
                        color: 'var(--color-fg-secondary)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        flexShrink: 0,
                      }}><Icon name={recipientKindIcon(o.k)} size={16}/></div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 14, color: 'var(--color-fg-emphasis)' }}>{o.name}</div>
                        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-fg-secondary)', marginTop: 2 }}>{o.note}</div>
                      </div>
                      <Icon name="check" size={14} style={{ color: 'var(--color-success)', marginTop: 6 }}/>
                    </div>
                  ))}
                </>
              )}
            </div>
          );
        })()}

        {phase === 'enroll' && (
          <div style={{ padding: '24px 8px' }}>
            <div style={{
              background: 'var(--color-surface-elevated)', border: '1px solid var(--color-border)',
              borderRadius: 12, padding: 24, textAlign: 'center', position: 'relative', overflow: 'hidden',
            }}>
              <div style={{ height: 110, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
                {enrollPhase === 'listening' && [0, 0.5].map(d => (
                  <span key={d} style={{ position: 'absolute', width: 90, height: 90, borderRadius: '50%', border: '2px solid var(--color-accent)', opacity: 0.25, animation: `ripple 1.6s var(--ease-out) infinite ${d}s` }}/>
                ))}
                <div style={{
                  width: 64, height: 64, borderRadius: 32,
                  background: enrollPhase === 'done' ? 'var(--color-success)' : 'var(--color-tile)',
                  color: enrollPhase === 'done' ? '#FAF6EE' : 'var(--color-accent)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1,
                  transition: 'all var(--dur-base) var(--ease-out)',
                }}>
                  <Icon name={enrollPhase === 'done' ? 'check' : recipientKindIcon(kind)} size={28}/>
                </div>
              </div>
              <div style={{ fontFamily: 'var(--font-serif)', fontWeight: 700, fontSize: 18, color: 'var(--color-fg-emphasis)', marginTop: 4 }}>
                {enrollPhase === 'listening' && 'Listening...'}
                {enrollPhase === 'found' && 'Touch to confirm'}
                {enrollPhase === 'done' && 'Recipient enrolled'}
              </div>
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: 13, color: 'var(--color-fg-secondary)', marginTop: 6, lineHeight: 1.5 }}>
                {enrollPhase !== 'done' ? 'Hold steady against the back of the phone.' : 'Re-encrypting protected items in batch...'}
              </div>
              {enrollError && (
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 12,
                  color: 'var(--color-danger)', marginTop: 12,
                  padding: '8px 10px', background: 'var(--color-tile)',
                  borderRadius: 6, wordBreak: 'break-word',
                }}>{enrollError}</div>
              )}
            </div>
            {enrollPhase === 'done' && (
              <div style={{ marginTop: 18, display: 'flex', gap: 8 }}>
                <Button fullWidth onClick={() => { toast?.('Recipient added'); onBack(); }}>Done</Button>
              </div>
            )}
            {enrollError && enrollPhase !== 'done' && (
              <div style={{ marginTop: 18, display: 'flex', gap: 8 }}>
                <Button fullWidth variant="ghost" onClick={() => setPhase('pick')}>Back</Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

window.FirstRun = FirstRun;
window.AddItemScreen = AddItemScreen;
window.SettingsScreen = SettingsScreen;
window.AddRecipientScreen = AddRecipientScreen;
