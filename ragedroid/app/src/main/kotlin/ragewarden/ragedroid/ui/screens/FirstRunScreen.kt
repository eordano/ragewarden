package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.platform.testTag
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.material.icons.outlined.PriorityHigh
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowForward
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.SessionStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.identities.enrollKeystoreIdentity
import ragewarden.ragedroid.identities.enrollPasskeyWithPrf
import ragewarden.ragedroid.identities.enrollYubiKeyPiv
import ragewarden.ragedroid.identities.isStrongBoxAvailable
import ragewarden.ragedroid.identities.passkeyEnrollmentSupported
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.findActivity
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

internal enum class FirstRunStep { Welcome, SignIn, Enroll, Backup, Done }

internal enum class FirstRunEnrollKind { Platform, SecurityKey, YubikeyPiv }

/**
 * Idle is a genuinely dead state: no NFC/USB discovery and no biometric prompt
 * exists until the user presses Start, so the screen must never imply it is
 * already waiting for a key. Listening covers the whole suspend call (that is
 * where the key is discovered *and* generates its material); Found is only
 * entered once that call has returned something.
 */
internal enum class FirstRunEnrollPhase { Idle, Listening, Found, DoneEnroll }

@Composable
fun FirstRunScreen(
    onComplete: () -> Unit,
    onPickPaperRecoveryBackup: () -> Unit = {},
    showToast: (String) -> Unit = {},
) {
    val strings = androidx.compose.ui.platform.LocalContext.current
    val c = rageColors
    val rawContext = LocalContext.current
    val context = rawContext.applicationContext
    val activity = rawContext.findActivity() as? FragmentActivity
    val scope = rememberCoroutineScope()
    val sessionStore = remember(context) { SessionStore(context) }
    val repo = remember(context) { context.appEntryPoint().bitwardenRepo() }
    val recipientStore = remember(context) { context.appEntryPoint().recipientStore() }
    fun currentAccountId(): String = VaultBridge.repository()?.accountId.orEmpty()

    var step by androidx.compose.runtime.saveable.rememberSaveable { mutableStateOf(FirstRunStep.Welcome) }
    androidx.activity.compose.BackHandler(
        enabled = step == FirstRunStep.SignIn || step == FirstRunStep.Enroll || step == FirstRunStep.Backup,
    ) {
        step = when (step) {
            FirstRunStep.Backup -> FirstRunStep.Enroll
            FirstRunStep.Enroll -> FirstRunStep.SignIn
            else -> FirstRunStep.Welcome
        }
    }
    // These three MUST stay empty. They once held a live test server, account and
    // master password; this file is in src/main with no build-type gate, so those
    // literals compiled straight into every release APK -- a shipped credential and
    // a prefilled sign-in form pointing every user at someone else's vault.
    //
    // Do not "helpfully" restore a dev default here, not even behind BuildConfig:
    // the only build-type constant this app has is MOCK_HARDWARE_ALLOWED (mock
    // authenticators -- wrong semantics to overload), and it is read through a
    // getter rather than a `const`, so the literal would survive into the release
    // string pool anyway. Type the server into the field, or use rageterm.
    var serverUrl by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var enrollKind by remember { mutableStateOf<FirstRunEnrollKind?>(null) }
    var enrollPhase by remember { mutableStateOf(FirstRunEnrollPhase.Idle) }
    var unboundConsentOpen by remember { mutableStateOf(false) }
    val enrollPlatform: suspend () -> ragewarden.ragedroid.data.StoredRecipient = {
        val biometric = ragewarden.ragedroid.identities.isBiometricEnrollable(rawContext)
        val (recipient, _) = enrollKeystoreIdentity(
            displayName = if (biometric) uiString(R.string.this_phone) else uiString(R.string.this_phone_no_confirmation),
            useStrongBox = isStrongBoxAvailable(rawContext),
            requireBiometric = biometric,
        )
        recipient
    }
    var showAdvanced by remember { mutableStateOf(false) }
    var signInBusy by remember { mutableStateOf(false) }
    var legacyKdfIterations by remember { mutableStateOf<Int?>(null) }
    var signInError by remember { mutableStateOf<String?>(null) }
    var pinPromptOpen by remember { mutableStateOf(false) }
    var enrollError by remember { mutableStateOf<String?>(null) }

    val auditFeed = remember(context) { context.appEntryPoint().auditFeed() }

    suspend fun persistRecipient(recipient: StoredRecipient) {
        withContext(NonCancellable) {
            val id = currentAccountId()
            require(id.isNotBlank()) { "no signed-in account; cannot persist recipient" }
            recipientStore.add(id, recipient)
            auditFeed.record(
                action = ragewarden.ragedroid.data.audit.AuditAction.EnrollIdentity,
                item = recipient.displayName,
                recipient = recipient.id,
                reason = uiString(R.string.recipient_added_2, recipient.kind),
            )
            VaultBridge.repository()?.pushRecipientRegistry()
        }
    }

    fun runEnrollment(block: suspend () -> StoredRecipient) {
        enrollError = null
        enrollPhase = FirstRunEnrollPhase.Listening
        scope.launch {
            try {
                // Found used to be set *before* block(), so the screen showed a
                // green check and "Authenticator detected." while nothing had
                // been detected -- the user was still hunting for the NFC
                // antenna. Only the returned recipient proves a key answered.
                val recipient = block()
                enrollPhase = FirstRunEnrollPhase.Found
                persistRecipient(recipient)
                enrollPhase = FirstRunEnrollPhase.DoneEnroll
            } catch (ce: CancellationException) {
                enrollPhase = FirstRunEnrollPhase.Idle
                throw ce
            } catch (t: ragewarden.ragedroid.data.StoreUnreadableException) {
                enrollPhase = FirstRunEnrollPhase.Idle
                enrollError = context.getString(R.string.key_list_unreadable_enrol)
            } catch (t: Throwable) {
                enrollPhase = FirstRunEnrollPhase.Idle
                enrollError = t.message?.takeIf { it.isNotBlank() } ?: context.getString(R.string.enrol_failed)
                android.util.Log.w("FirstRunEnroll", "enrollment failed", t)
            }
        }
    }

    LaunchedEffect(Unit) {
        if (sessionStore.has()) {
            VaultBridge.installRepository(repo)
            onComplete()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .imePadding(),
    ) {
        if (unboundConsentOpen) {
            UnboundKeyConsent(
                onSetScreenLock = {
                    unboundConsentOpen = false
                    runCatching {
                        rawContext.startActivity(
                            android.content.Intent(android.app.admin.DevicePolicyManager.ACTION_SET_NEW_PASSWORD)
                                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }
                },
                onEnrolAnyway = {
                    unboundConsentOpen = false
                    runEnrollment { enrollPlatform() }
                },
                onCancel = { unboundConsentOpen = false },
            )
        }
        legacyKdfIterations?.let { iterations ->
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { legacyKdfIterations = null },
                title = { androidx.compose.material3.Text(stringResource(R.string.strengthen_this_account)) },
                text = {
                    androidx.compose.material3.Text(
                        stringResource(R.string.this_account_stretches_its_master_password, iterations),
                    )
                },
                confirmButton = {
                    androidx.compose.material3.TextButton(onClick = {
                        legacyKdfIterations = null
                        signInBusy = true
                        scope.launch {
                            val result = repo.login(serverUrl.trim(), email.trim(), password, allowLegacyKdf = true)
                            signInBusy = false
                            result.fold(
                                onSuccess = {
                                    VaultBridge.installRepository(repo)
                                    step = FirstRunStep.Enroll
                                },
                                onFailure = { e -> signInError = e.message ?: uiString(R.string.sign_in_failed) },
                            )
                        }
                    }) { androidx.compose.material3.Text(stringResource(R.string.sign_in_and_strengthen)) }
                },
                dismissButton = {
                    androidx.compose.material3.TextButton(onClick = { legacyKdfIterations = null }) {
                        androidx.compose.material3.Text(stringResource(R.string.cancel))
                    }
                },
            )
        }
        when (step) {
            FirstRunStep.Welcome -> WelcomeStep(onBegin = { step = FirstRunStep.SignIn })
            FirstRunStep.SignIn -> SignInStep(
                serverUrl = serverUrl,
                email = email,
                password = password,
                busy = signInBusy,
                error = signInError,
                onServerChange = { serverUrl = it },
                onEmailChange = { email = it },
                onPasswordChange = { password = it },
                onBack = { step = FirstRunStep.Welcome },
                onContinue = {
                    // Guard before the call, not after: with no client-side
                    // check an empty form reached the core, which answered with
                    // its own message about a URL the user never typed
                    // ("server URL is not https: /api").
                    val problem = signInFormProblem(serverUrl, email, password)
                    if (problem != null) {
                        signInError = problem
                    } else {
                        signInBusy = true
                        signInError = null
                        scope.launch {
                            val result = repo.login(serverUrl.trim(), email.trim(), password)
                            signInBusy = false
                            result.fold(
                                onSuccess = {
                                    VaultBridge.installRepository(repo)
                                    step = FirstRunStep.Enroll
                                },
                                onFailure = { e ->
                                    if (e is ragewarden.ragedroid.data.BitwardenVaultRepository.LegacyKdfException) {
                                        legacyKdfIterations = e.iterations
                                    } else {
                                        signInError = e.message ?: uiString(R.string.sign_in_failed)
                                    }
                                },
                            )
                        }
                    }
                },
            )
            FirstRunStep.Enroll -> EnrollStep(
                enrollKind = enrollKind,
                enrollPhase = enrollPhase,
                enrollError = enrollError,
                showAdvanced = showAdvanced,
                onDismissError = { enrollError = null },
                onPickKind = {
                    enrollKind = it
                    enrollPhase = FirstRunEnrollPhase.Idle
                    enrollError = null
                },
                onShowAdvanced = { showAdvanced = true },
                onResetKind = {
                    enrollKind = null
                    enrollPhase = FirstRunEnrollPhase.Idle
                    enrollError = null
                },
                onBack = { step = FirstRunStep.SignIn },
                onTrigger = {
                    when (enrollKind) {
                        FirstRunEnrollKind.Platform -> {
                            if (ragewarden.ragedroid.identities.isBiometricEnrollable(rawContext)) {
                                runEnrollment { enrollPlatform() }
                            } else {
                                unboundConsentOpen = true
                            }
                        }
                        FirstRunEnrollKind.SecurityKey -> {
                            if (!passkeyEnrollmentSupported()) {
                                showToast(strings.getString(R.string.passkey_enrollment_not_available_on_this))
                                enrollPhase = FirstRunEnrollPhase.Idle
                            } else if (activity == null) {
                                showToast(strings.getString(R.string.need_an_activity_context))
                                enrollPhase = FirstRunEnrollPhase.Idle
                            } else {
                                runEnrollment {
                                    val (recipient, _) = enrollPasskeyWithPrf(
                                        activity = activity,
                                        accountId = currentAccountId(),
                                    )
                                    recipient
                                }
                            }
                        }
                        FirstRunEnrollKind.YubikeyPiv -> {
                            if (activity == null) {
                                showToast(strings.getString(R.string.need_an_activity_context))
                                enrollPhase = FirstRunEnrollPhase.Idle
                            } else {
                                pinPromptOpen = true
                            }
                        }
                        null -> Unit
                    }
                },
                onContinue = { step = FirstRunStep.Backup },
                onSkip = {
                    showToast(strings.getString(R.string.hardware_enrollment_skipped_you_can_add))
                    step = FirstRunStep.Backup
                },
            )
            FirstRunStep.Backup -> BackupStep(
                onBack = { step = FirstRunStep.Enroll },
                onPickRecovery = onPickPaperRecoveryBackup,
                onSkip = { step = FirstRunStep.Done },
            )
            FirstRunStep.Done -> {
                val enrolled = currentAccountId().takeIf { it.isNotBlank() }
                    ?.let { recipientStore.forAccount(it) }
                    .orEmpty()
                DoneStep(
                    keyEnrolled = enrolled.any { it.defaultEncrypt && it.kind != ragewarden.ragedroid.model.RecipientKind.Recovery },
                    backupEnrolled = enrolled.any { it.kind == ragewarden.ragedroid.model.RecipientKind.Recovery },
                    onOpenVault = onComplete,
                )
            }
        }

        if (pinPromptOpen && activity != null) {
            YubiKeyPinPrompt(
                onCancel = { pinPromptOpen = false },
                onSubmit = { chars ->
                    pinPromptOpen = false
                    runEnrollment {
                        try {
                            val (recipient, _) = enrollYubiKeyPiv(
                                activity = activity,
                                pin = chars,
                                displayName = null,
                            )
                            recipient
                        } finally {
                            for (i in chars.indices) chars[i] = ' '
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun StepScaffold(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .verticalScroll(rememberScrollState())
            .padding(start = 22.dp, end = 22.dp, top = 24.dp, bottom = 18.dp),
        content = content,
    )
}

@Composable
private fun Logo() {
    val c = rageColors
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(c.fgEmphasis, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Link,
                contentDescription = null,
                tint = c.background,
                modifier = Modifier.size(18.dp),
            )
        }
        Column {
            Text(
                text = stringResource(R.string.ragedroid),
                style = RageType.h2.copy(
                    fontSize = 18.sp,
                    lineHeight = 18.sp,
                    letterSpacing = (-0.01).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = stringResource(R.string.a_localforge_product),
                style = RageType.sansBody.copy(fontSize = 10.sp, lineHeight = 12.sp),
                color = c.fgSecondary,
            )
        }
    }
}

@Composable
private fun StepTitle(kicker: String, title: String, sub: String? = null) {
    val c = rageColors
    Column(modifier = Modifier.padding(bottom = 20.dp)) {
        Text(
            text = kicker.uppercase(),
            style = RageType.eyebrow.copy(letterSpacing = 0.08.em),
            color = c.accent,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = title,
            style = RageType.h1.copy(
                fontSize = 28.sp,
                lineHeight = 32.sp,
                letterSpacing = (-0.015).em,
            ),
            color = c.fgEmphasis,
        )
        if (sub != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = sub,
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 24.sp),
                color = c.fgSecondary,
            )
        }
    }
}

@Composable
internal fun WelcomeStep(onBegin: () -> Unit) {
    val c = rageColors
    StepScaffold {
        Logo()
        Spacer(modifier = Modifier.height(36.dp))
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.a_phishing_resistant_bitwarden_client),
                style = RageType.body.copy(fontSize = 14.sp, fontStyle = FontStyle.Italic),
                color = c.fgSecondary,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = stringResource(R.string.the_master_password_leaking_does_not),
                style = RageType.h1.copy(
                    fontSize = 32.sp,
                    lineHeight = 35.sp,
                    letterSpacing = (-0.02).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.ragedroid_wraps_every_secret_in_an),
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.both_layers_are_needed_to_read),
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
        }
        Spacer(modifier = Modifier.height(32.dp))
        RageButton(
            label = stringResource(R.string.begin_setup),
            onClick = onBegin,
            icon = Icons.AutoMirrored.Outlined.ArrowForward,
            fullWidth = true,
        )
        Spacer(modifier = Modifier.height(14.dp))
        Text(
            text = stringResource(R.string.existing_bitwarden_vault_required_age_rage),
            style = RageType.sansBody.copy(fontSize = 11.sp, textAlign = TextAlign.Center),
            color = c.fgSecondary,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun SignInStep(
    serverUrl: String,
    email: String,
    password: String,
    busy: Boolean,
    error: String?,
    onServerChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onBack: () -> Unit,
    onContinue: () -> Unit,
) {
    val c = rageColors
    StepScaffold {
        StepTitle(
            kicker = stringResource(R.string.step_1_of_3),
            title = stringResource(R.string.sign_in_to_your_vault),
            sub = stringResource(R.string.connect_your_bitwarden_vault_self_hosted),
        )
        Column(modifier = Modifier.fillMaxWidth()) {
            FirstRunFieldLabel(stringResource(R.string.server))
            FirstRunInput(
                value = serverUrl,
                onChange = onServerChange,
                mono = true,
                placeholder = stringResource(R.string.https_vault_bitwarden_com),
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                autoCorrect = false,
                tag = "signin-server",
            )
            Spacer(modifier = Modifier.height(16.dp))
            FirstRunFieldLabel(stringResource(R.string.email))
            FirstRunInput(
                value = email,
                onChange = onEmailChange,
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Email,
                autoCorrect = false,
                tag = "signin-email",
            )
            Spacer(modifier = Modifier.height(16.dp))
            FirstRunFieldLabel(stringResource(R.string.master_password))
            FirstRunInput(value = password, onChange = onPasswordChange, password = true, tag = "signin-password")
            if (error != null) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(text = error, style = RageType.body, color = c.fgEmphasis)
            }
        }
        Spacer(modifier = Modifier.height(20.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RageButton(
                label = stringResource(R.string.back),
                onClick = onBack,
                variant = ButtonVariant.Ghost,
            )
            Box(modifier = Modifier.weight(1f)) {
                RageButton(
                    label = if (busy) stringResource(R.string.working) else stringResource(R.string.sign_in_continue),
                    onClick = onContinue,
                    icon = Icons.AutoMirrored.Outlined.ArrowForward,
                    fullWidth = true,
                    enabled = !busy,
                )
            }
        }
    }
}

/**
 * First-line validation for the sign-in form; null means "worth sending".
 *
 * The scheme rule mirrors `core/src/sync.rs::server_url_is_secure` -- https
 * anywhere, http only against loopback -- so the field is rejected here, naming
 * the field, instead of by the core three layers down with a message about a
 * URL string the user never typed. Deliberately stricter than the core on one
 * point: it accepts any 127.0.0.0/8 address, this only spells out the common
 * ones. Erring towards refusal is the right side to err on.
 */
private fun signInFormProblem(serverUrl: String, email: String, password: String): String? {
    val server = serverUrl.trim()
    val account = email.trim()
    return when {
        server.isEmpty() -> uiString(R.string.enter_your_vault_server_e_g)
        !serverSchemeAccepted(server) ->
            uiString(R.string.server_must_start_with_https_plain)
        account.isEmpty() -> uiString(R.string.enter_the_email_address_of_your)
        !account.contains('@') || account.any { it.isWhitespace() } ->
            uiString(R.string.that_doesn_t_look_like_an)
        password.isEmpty() -> uiString(R.string.enter_your_master_password)
        else -> null
    }
}

private fun serverSchemeAccepted(server: String): Boolean {
    val lower = server.lowercase()
    val rest = when {
        lower.startsWith("https://") -> return lower.length > "https://".length
        lower.startsWith("http://") -> lower.removePrefix("http://")
        else -> return false
    }
    val host = rest.takeWhile { it != '/' && it != '?' && it != '#' }
        .substringAfterLast('@')
        .let { if (it.startsWith("[")) it.removePrefix("[").substringBefore(']') else it.substringBefore(':') }
    return host == "localhost" || host == "::1" || host.startsWith("127.")
}

@Composable
private fun FirstRunFieldLabel(text: String) {
    val c = rageColors
    Text(
        text = text.uppercase(),
        style = RageType.eyebrow,
        color = c.fgSecondary,
        modifier = Modifier.padding(bottom = 6.dp),
    )
}

@Composable
private fun FirstRunInput(
    value: String,
    onChange: (String) -> Unit,
    mono: Boolean = false,
    password: Boolean = false,
    placeholder: String? = null,
    keyboardType: androidx.compose.ui.text.input.KeyboardType = androidx.compose.ui.text.input.KeyboardType.Text,
    autoCorrect: Boolean = true,
    tag: String? = null,
) {
    val c = rageColors
    val style = if (mono) RageType.mono.copy(color = c.fgPrimary) else RageType.sansBody.copy(color = c.fgPrimary)
    val resolvedKeyboardType = if (password) androidx.compose.ui.text.input.KeyboardType.Password else keyboardType
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceSunken, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        androidx.compose.foundation.text.BasicTextField(
            value = value,
            onValueChange = onChange,
            textStyle = style,
            singleLine = true,
            cursorBrush = androidx.compose.ui.graphics.SolidColor(c.accent),
            visualTransformation = if (password) {
                androidx.compose.ui.text.input.PasswordVisualTransformation()
            } else {
                androidx.compose.ui.text.input.VisualTransformation.None
            },
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = resolvedKeyboardType,
                autoCorrect = autoCorrect,
            ),
            modifier = Modifier.fillMaxWidth().let { m -> if (tag != null) m.testTag(tag) else m },
            decorationBox = { inner ->
                Box {
                    // Never on a password field -- a hint under the dots would be
                    // read as the value.
                    if (placeholder != null && value.isEmpty() && !password) {
                        Text(
                            text = placeholder,
                            style = style.copy(color = c.fgSecondary),
                            maxLines = 1,
                        )
                    }
                    inner()
                }
            },
        )
    }
}

@Composable
private fun EnrollStep(
    enrollKind: FirstRunEnrollKind?,
    enrollPhase: FirstRunEnrollPhase,
    enrollError: String?,
    showAdvanced: Boolean,
    onDismissError: () -> Unit,
    onPickKind: (FirstRunEnrollKind) -> Unit,
    onShowAdvanced: () -> Unit,
    onResetKind: () -> Unit,
    onBack: () -> Unit,
    onTrigger: () -> Unit,
    onContinue: () -> Unit,
    onSkip: () -> Unit,
) {
    if (enrollKind == null) {
        EnrollPicker(
            showAdvanced = showAdvanced,
            onPickKind = onPickKind,
            onShowAdvanced = onShowAdvanced,
            onBack = onBack,
            onSkip = onSkip,
        )
    } else {
        EnrollProgress(
            enrollKind = enrollKind,
            phase = enrollPhase,
            error = enrollError,
            onDismissError = onDismissError,
            onBack = onResetKind,
            onTrigger = onTrigger,
            onContinue = onContinue,
        )
    }
}

private data class EnrollOption(
    val kind: FirstRunEnrollKind,
    @androidx.annotation.StringRes val name: Int,
    @androidx.annotation.StringRes val description: Int,
    val icon: ImageVector,
    @androidx.annotation.StringRes val tag: Int? = null,
    val recommended: Boolean = false,
)

private val PRIMARY_OPTIONS = listOf(
    EnrollOption(
        kind = FirstRunEnrollKind.Platform,
        name = R.string.this_phone,
        description = R.string.use_the_secure_element_biometrics_already,
        icon = Icons.Outlined.Fingerprint,
        tag = R.string.fastest,
        recommended = true,
    ),
    EnrollOption(
        kind = FirstRunEnrollKind.SecurityKey,
        name = R.string.a_security_key,
        description = R.string.yubikey_solo_titan_or_any_fido2,
        icon = Icons.Outlined.Nfc,
    ),
)

private val ADVANCED_OPTIONS = listOf(
    EnrollOption(
        kind = FirstRunEnrollKind.YubikeyPiv,
        name = R.string.yubikey_piv_mode,
        description = R.string.pin_a_key_to_piv_slot_2,
        icon = Icons.Outlined.Usb,
    ),
)

@Composable
private fun EnrollPicker(
    showAdvanced: Boolean,
    onPickKind: (FirstRunEnrollKind) -> Unit,
    onShowAdvanced: () -> Unit,
    onBack: () -> Unit,
    onSkip: () -> Unit,
) {
    StepScaffold {
        StepTitle(
            kicker = stringResource(R.string.step_2_of_3),
            title = stringResource(R.string.add_your_first_key),
            sub = stringResource(R.string.pick_how_you_want_to_authorize),
        )
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            PRIMARY_OPTIONS.forEach { option ->
                EnrollOptionRow(option = option, onClick = { onPickKind(option.kind) })
            }
        }
        Spacer(modifier = Modifier.height(14.dp))
        if (!showAdvanced) {
            Row(
                modifier = Modifier.clickable(onClick = onShowAdvanced),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = stringResource(R.string.more_options),
                    style = RageType.button.copy(fontSize = 12.sp),
                    color = rageColors.fgSecondary,
                )
                Icon(
                    imageVector = Icons.Outlined.KeyboardArrowDown,
                    contentDescription = null,
                    tint = rageColors.fgSecondary,
                    modifier = Modifier.size(12.dp),
                )
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ADVANCED_OPTIONS.forEach { option ->
                    EnrollOptionRow(option = option, onClick = { onPickKind(option.kind) })
                }
            }
        }
        Spacer(modifier = Modifier.height(20.dp))
        Row(modifier = Modifier.fillMaxWidth()) {
            RageButton(
                label = stringResource(R.string.back),
                onClick = onBack,
                variant = ButtonVariant.Ghost,
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onSkip)
                .padding(vertical = 10.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.skip_set_up_later),
                style = RageType.caption,
                color = rageColors.fgSecondary,
            )
        }
    }
}

@Composable
private fun EnrollOptionRow(option: EnrollOption, onClick: () -> Unit) = OptionRow(
    option.icon, stringResource(option.name), stringResource(option.description), option.recommended, option.tag?.let { stringResource(it) },
    Modifier.padding(top = 8.dp).size(18.dp), onClick,
)

@Composable
private fun OptionRow(
    icon: ImageVector,
    name: String,
    description: String,
    recommended: Boolean,
    tag: String?,
    arrowModifier: Modifier,
    onClick: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.border, RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(18.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = name,
                    style = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp),
                    color = c.fgEmphasis,
                )
                if (recommended) {
                    Box(
                        modifier = Modifier
                            .border(1.dp, c.success, RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.recommended_2).uppercase(),
                            style = RageType.eyebrow.copy(fontSize = 10.sp, lineHeight = 12.sp),
                            color = c.success,
                        )
                    }
                } else if (tag != null) {
                    Text(
                        text = tag.uppercase(),
                        style = RageType.eyebrow.copy(fontSize = 10.sp, lineHeight = 12.sp),
                        color = c.fgSecondary,
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = description,
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 19.5.sp),
                color = c.fgSecondary,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = arrowModifier,
        )
    }
}

@Composable
private fun EnrollProgress(
    enrollKind: FirstRunEnrollKind,
    phase: FirstRunEnrollPhase,
    error: String? = null,
    onDismissError: () -> Unit = {},
    onBack: () -> Unit,
    onTrigger: () -> Unit,
    onContinue: () -> Unit,
) {
    val c = rageColors
    val copy = enrollCopy(enrollKind)
    StepScaffold {
        StepTitle(
            kicker = stringResource(R.string.step_2_of_3),
            title = stringResource(copy.title),
            sub = stringResource(copy.sub),
        )
        // The card itself is not clickable. It used to be the *only* way to
        // begin enrollment -- an invisible full-card hit target next to copy that
        // told the user to present their key -- so anyone who followed the
        // instructions waited on a screen that was not listening. The Start
        // button below is now the single affordance that arms discovery.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                .padding(18.dp),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(130.dp),
                contentAlignment = Alignment.Center,
            ) {
                when (phase) {
                    FirstRunEnrollPhase.Idle, FirstRunEnrollPhase.Listening -> EnrollIdleVisual(
                        kind = enrollKind,
                        listening = phase == FirstRunEnrollPhase.Listening,
                    )
                    FirstRunEnrollPhase.Found -> EnrollFoundVisual()
                    FirstRunEnrollPhase.DoneEnroll -> EnrollDoneVisual(copy = copy)
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = when (phase) {
                    FirstRunEnrollPhase.Idle -> stringResource(copy.idleHint)
                    FirstRunEnrollPhase.Listening -> stringResource(copy.listeningHint)
                    FirstRunEnrollPhase.Found -> stringResource(R.string.authenticator_detected_recording_it_as_a)
                    FirstRunEnrollPhase.DoneEnroll -> stringResource(R.string.recorded_as_a_recipient_in_your)
                },
                style = RageType.sansBody.copy(textAlign = TextAlign.Center),
                color = c.fgSecondary,
                modifier = Modifier.fillMaxWidth(),
            )
            // Hidden while an error is up: the error card carries its own "Try
            // again", and two live start buttons is the duplication this screen
            // already had too much of.
            if (phase == FirstRunEnrollPhase.Idle && error == null) {
                Spacer(modifier = Modifier.height(14.dp))
                RageButton(
                    label = stringResource(copy.startLabel),
                    onClick = onTrigger,
                    icon = if (enrollKind == FirstRunEnrollKind.Platform) {
                        Icons.Outlined.Fingerprint
                    } else {
                        Icons.Outlined.Nfc
                    },
                    fullWidth = true,
                )
            }
        }
        Spacer(modifier = Modifier.height(14.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min)
                .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                .border(1.dp, c.border, RoundedCornerShape(8.dp)),
            verticalAlignment = Alignment.Top,
        ) {
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .fillMaxHeight()
                    .background(c.info),
            )
            Text(
                text = stringResource(R.string.if_this_device_is_lost_and),
                style = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 17.sp),
                color = c.fgSecondary,
                modifier = Modifier
                    .padding(start = 10.dp, top = 10.dp, end = 12.dp, bottom = 10.dp),
            )
        }
        if (error != null) {
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(IntrinsicSize.Min)
                    .background(c.surfaceSunken, RoundedCornerShape(8.dp))
                    .border(1.dp, c.danger, RoundedCornerShape(8.dp)),
                verticalAlignment = Alignment.Top,
            ) {
                Box(
                    modifier = Modifier
                        .width(3.dp)
                        .fillMaxHeight()
                        .background(c.danger),
                )
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 10.dp, top = 10.dp, end = 12.dp, bottom = 10.dp),
                ) {
                    Text(
                        text = stringResource(R.string.enrollment_failed),
                        style = RageType.sansBody.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold),
                        color = c.danger,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = error,
                        style = RageType.sansBody.copy(fontSize = 11.5.sp, lineHeight = 17.sp),
                        color = c.fgPrimary,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        RageButton(label = stringResource(R.string.try_again), onClick = onTrigger, variant = ButtonVariant.Primary)
                        RageButton(label = stringResource(R.string.dismiss), onClick = onDismissError, variant = ButtonVariant.Ghost)
                    }
                }
            }
        }
        if (phase == FirstRunEnrollPhase.DoneEnroll) {
            Spacer(modifier = Modifier.height(14.dp))
            RageButton(
                label = stringResource(R.string.continue_),
                onClick = onContinue,
                icon = Icons.AutoMirrored.Outlined.ArrowForward,
                fullWidth = true,
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        // One way out of this screen, not two. It also carried a "Skip -- set up
        // later" that jumped straight to step 3; the picker one tap back already
        // offers exactly that, and side by side the pair read as two different
        // escapes when only this one keeps the method choice reachable.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onBack)
                .padding(vertical = 12.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.back_choose_a_different_method),
                style = RageType.caption,
                color = c.fgSecondary,
            )
        }
    }
}

private data class EnrollCopy(
    @androidx.annotation.StringRes val title: Int,
    @androidx.annotation.StringRes val sub: Int,
    /** Label of the Start button. Must name what pressing it actually does. */
    @androidx.annotation.StringRes val startLabel: Int,
    @androidx.annotation.StringRes val idleHint: Int,
    @androidx.annotation.StringRes val listeningHint: Int,
    @androidx.annotation.StringRes val doneTitle: Int,
    @androidx.annotation.StringRes val doneMeta: Int,
)

// The idle hints all lead with Start. They used to open with "Insert via USB-C,
// or hold the key to the back of the phone" while the app had no NFC or USB
// discovery running at all -- nothing existed to insert a key into until the
// trigger fired.
private fun enrollCopy(kind: FirstRunEnrollKind): EnrollCopy = when (kind) {
    FirstRunEnrollKind.Platform -> EnrollCopy(
        title = R.string.enroll_this_phone,
        sub = R.string.generates_a_passkey_backed_by_the,
        // Not "confirm with biometrics": enrollKeystoreIdentity falls back to a
        // non-biometric key when the device has none enrolled.
        startLabel = R.string.start_enroll_this_phone,
        idleHint = R.string.tap_start_to_generate_the_key,
        listeningHint = R.string.confirm_with_your_fingerprint_to_finish,
        doneTitle = R.string.this_phone_enrolled,
        doneMeta = R.string.strongbox_p_256,
    )
    FirstRunEnrollKind.SecurityKey -> EnrollCopy(
        title = R.string.enroll_a_security_key,
        sub = R.string.the_key_generates_its_own_keypair,
        startLabel = R.string.start_listen_for_the_key,
        idleHint = R.string.tap_start_then_present_your_key,
        listeningHint = R.string.listening_for_nfc_and_usb_c,
        doneTitle = R.string.security_key_enrolled,
        doneMeta = R.string.fido2_x25519,
    )
    FirstRunEnrollKind.YubikeyPiv -> EnrollCopy(
        title = R.string.enroll_a_yubikey_piv,
        sub = R.string.ragedroid_generates_an_x25519_keypair_on,
        startLabel = R.string.start_enter_your_pin,
        idleHint = R.string.tap_start_and_enter_your_piv,
        listeningHint = R.string.listening_for_nfc_and_usb_c_2,
        doneTitle = R.string.yubikey_enrolled,
        doneMeta = R.string.piv_slot_95_x25519,
    )
}

@Composable
private fun EnrollIdleVisual(kind: FirstRunEnrollKind, listening: Boolean) {
    val c = rageColors
    val pulseAlpha by animateFloatAsState(
        targetValue = if (listening) 0.35f else 0f,
        animationSpec = tween(durationMillis = 800, easing = LinearEasing),
        label = stringResource(R.string.enroll_pulse),
    )
    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(110.dp)) {
        if (listening) {
            Box(
                modifier = Modifier
                    .size(110.dp)
                    .border(2.dp, c.accent.copy(alpha = pulseAlpha), RoundedCornerShape(55.dp)),
            )
        }
        Box(
            modifier = Modifier
                .size(80.dp)
                .background(c.tile, RoundedCornerShape(40.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = if (kind == FirstRunEnrollKind.Platform) Icons.Outlined.Fingerprint else Icons.Outlined.Nfc,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(36.dp),
            )
        }
    }
}

@Composable
private fun EnrollFoundVisual() {
    val c = rageColors
    Box(
        modifier = Modifier
            .size(80.dp)
            .background(c.success, RoundedCornerShape(40.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.Outlined.Check,
            contentDescription = null,
            tint = Color(0xFFFAF6EE),
            modifier = Modifier.size(36.dp),
        )
    }
}

@Composable
private fun EnrollDoneVisual(copy: EnrollCopy) {
    val c = rageColors
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            modifier = Modifier
                .size(60.dp)
                .background(c.success, RoundedCornerShape(30.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Check,
                contentDescription = null,
                tint = Color(0xFFFAF6EE),
                modifier = Modifier.size(26.dp),
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(copy.doneTitle),
            style = RageType.rowTitle.copy(fontSize = 16.sp, lineHeight = 20.sp),
            color = c.fgEmphasis,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Mono(text = stringResource(copy.doneMeta), size = 11, color = c.fgSecondary)
    }
}

private data class BackupOption(
    @androidx.annotation.StringRes val name: Int,
    @androidx.annotation.StringRes val description: Int,
    val icon: ImageVector,
    val recommended: Boolean = false,
)

/**
 * The only backup this step can actually set up.
 *
 * "A second YubiKey" and "This phone (StrongBox)" used to sit below it, but
 * neither enrolled anything: both fell through to a toast saying to set it up
 * later in Settings and then advanced to Done -- the same outcome as the Skip
 * button an inch further down, dressed up as three choices.
 */
private val RECOVERY_BACKUP_OPTION = BackupOption(
    name = R.string.paper_recovery_phrase,
    description = R.string.s_24_bip39_words_write_them_down,
    icon = Icons.Outlined.Description,
    recommended = true,
)

@Composable
internal fun BackupStep(
    onBack: () -> Unit,
    onPickRecovery: () -> Unit,
    onSkip: () -> Unit,
) {
    StepScaffold {
        StepTitle(
            kicker = stringResource(R.string.step_3_of_3),
            title = stringResource(R.string.add_a_backup_recipient),
            sub = stringResource(R.string.a_second_way_in_in_case),
        )
        BackupOptionRow(option = RECOVERY_BACKUP_OPTION, onClick = onPickRecovery)
        Spacer(modifier = Modifier.height(20.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RageButton(label = stringResource(R.string.back), onClick = onBack, variant = ButtonVariant.Ghost)
            Box(modifier = Modifier.weight(1f)) {
                RageButton(
                    label = stringResource(R.string.write_down_a_recovery_phrase),
                    onClick = onPickRecovery,
                    fullWidth = true,
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button, onClick = onSkip)
                .defaultMinSize(minHeight = 48.dp)
                .padding(vertical = 10.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.skip_i_ll_add_later),
                style = RageType.caption,
                color = rageColors.fgSecondary,
            )
        }
    }
}

@Composable
private fun BackupOptionRow(option: BackupOption, onClick: () -> Unit) = OptionRow(
    option.icon, stringResource(option.name), stringResource(option.description), option.recommended, null,
    Modifier.size(18.dp).padding(top = 8.dp), onClick,
)

@Composable
internal fun DoneStep(keyEnrolled: Boolean, backupEnrolled: Boolean, onOpenVault: () -> Unit) {
    val c = rageColors
    StepScaffold {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            verticalArrangement = Arrangement.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .background(if (keyEnrolled) c.success else c.warning, RoundedCornerShape(32.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (keyEnrolled) Icons.Outlined.Check else Icons.Outlined.PriorityHigh,
                    contentDescription = null,
                    tint = Color(0xFFFAF6EE),
                    modifier = Modifier.size(32.dp),
                )
            }
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = stringResource(if (keyEnrolled) R.string.setup_complete else R.string.vault_not_protected_yet),
                style = RageType.h1.copy(
                    fontSize = 30.sp,
                    lineHeight = 35.sp,
                    letterSpacing = (-0.015).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(if (keyEnrolled) R.string.done_sync_protected else R.string.done_sync_unprotected),
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
            if (keyEnrolled) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.done_each_secret_needs_key),
                    style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp, fontStyle = FontStyle.Italic),
                    color = c.fgSecondary,
                )
            }
            val todo = buildList {
                if (!keyEnrolled) add(R.string.todo_add_a_key)
                if (!backupEnrolled) add(R.string.todo_add_paper_backup)
            }
            if (todo.isNotEmpty()) {
                Spacer(modifier = Modifier.height(20.dp))
                Text(
                    text = stringResource(R.string.still_to_do).uppercase(),
                    style = RageType.eyebrow,
                    color = c.fgSecondary,
                )
                todo.forEach { res ->
                    Text(
                        text = stringResource(res),
                        style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp),
                        color = c.fgPrimary,
                        modifier = Modifier.padding(top = 6.dp).testTag("done-todo"),
                    )
                }
            }
        }
        RageButton(
            label = stringResource(R.string.open_vault),
            onClick = onOpenVault,
            icon = Icons.AutoMirrored.Outlined.ArrowForward,
            fullWidth = true,
        )
    }
}

