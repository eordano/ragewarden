package ragewarden.ragedroid.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.SessionStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.identities.enrollKeystoreIdentity
import ragewarden.ragedroid.identities.enrollPasskeyWithPrf
import ragewarden.ragedroid.identities.enrollYubiKeyPivX25519
import ragewarden.ragedroid.identities.isStrongBoxAvailable
import ragewarden.ragedroid.identities.passkeyEnrollmentSupported
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.SecurePinField
import ragewarden.ragedroid.ui.components.rememberSecurePinFieldState
import ragewarden.ragedroid.ui.findActivity
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

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
    val c = rageColors
    val rawContext = LocalContext.current
    val context = rawContext.applicationContext
    val activity = rawContext.findActivity() as? FragmentActivity
    val scope = rememberCoroutineScope()
    val sessionStore = remember(context) { SessionStore(context) }
    val repo = remember(context) { context.appEntryPoint().bitwardenRepo() }
    val recipientStore = remember(context) { context.appEntryPoint().recipientStore() }
    fun currentAccountId(): String = VaultBridge.repository()?.accountId.orEmpty()

    var step by remember { mutableStateOf(FirstRunStep.Welcome) }
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
    var showAdvanced by remember { mutableStateOf(false) }
    var signInBusy by remember { mutableStateOf(false) }
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
                action = ragewarden.ragedroid.data.audit.AuditAction.Enroll,
                item = recipient.displayName,
                recipient = recipient.id,
                reason = "${recipient.kind} recipient added",
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
            } catch (t: Throwable) {
                enrollPhase = FirstRunEnrollPhase.Idle
                val parts = listOfNotNull(
                    t.javaClass.simpleName,
                    t.message,
                    t.cause?.let { "cause: ${it.javaClass.simpleName}: ${it.message}" },
                )
                enrollError = parts.joinToString(" -- ")
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
                                    signInError = e.message ?: "Sign-in failed"
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
                            runEnrollment {
                                val biometric = ragewarden.ragedroid.identities.isBiometricEnrollable(rawContext)
                                val (recipient, _) = enrollKeystoreIdentity(
                                    displayName = if (biometric) "This phone" else "This phone (no biometric)",
                                    useStrongBox = isStrongBoxAvailable(rawContext),
                                    requireBiometric = biometric,
                                )
                                recipient
                            }
                        }
                        FirstRunEnrollKind.SecurityKey -> {
                            if (!passkeyEnrollmentSupported()) {
                                showToast("Passkey enrollment not available on this build")
                                enrollPhase = FirstRunEnrollPhase.Idle
                            } else if (activity == null) {
                                showToast("Need an Activity context")
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
                                showToast("Need an Activity context")
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
                    showToast("Hardware enrollment skipped -- you can add a recipient later in Settings")
                    step = FirstRunStep.Backup
                },
            )
            FirstRunStep.Backup -> BackupStep(
                onBack = { step = FirstRunStep.Enroll },
                onPickRecovery = onPickPaperRecoveryBackup,
                onSkip = { step = FirstRunStep.Done },
            )
            FirstRunStep.Done -> DoneStep(onOpenVault = onComplete)
        }

        if (pinPromptOpen && activity != null) {
            FirstRunYubiKeyPinPrompt(
                onCancel = { pinPromptOpen = false },
                onSubmit = { chars ->
                    pinPromptOpen = false
                    runEnrollment {
                        try {
                            val (recipient, _) = enrollYubiKeyPivX25519(
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
private fun FirstRunYubiKeyPinPrompt(
    onCancel: () -> Unit,
    onSubmit: (CharArray) -> Unit,
) {
    val pinState = rememberSecurePinFieldState()
    AlertDialog(
        onDismissRequest = {
            pinState.zero()
            onCancel()
        },
        title = { Text("YubiKey PIN") },
        text = {
            Column {
                Text(
                    text = "Enter your YubiKey PIV PIN. The default is 123456 if you haven't set one.",
                    style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                )
                Spacer(modifier = Modifier.height(12.dp))
                SecurePinField(state = pinState)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val chars = pinState.submit()
                pinState.zero()
                onSubmit(chars)
            }) { Text("Continue") }
        },
        dismissButton = {
            TextButton(onClick = {
                pinState.zero()
                onCancel()
            }) { Text("Cancel") }
        },
    )
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
                text = "RageDroid",
                style = RageType.h2.copy(
                    fontSize = 18.sp,
                    lineHeight = 18.sp,
                    letterSpacing = (-0.01).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "A LocalForge product",
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
                text = "A phishing-resistant Bitwarden client.",
                style = RageType.body.copy(fontSize = 14.sp, fontStyle = FontStyle.Italic),
                color = c.fgSecondary,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = "The master password leaking does not leak any of the actual secrets.",
                style = RageType.h1.copy(
                    fontSize = 32.sp,
                    lineHeight = 35.sp,
                    letterSpacing = (-0.02).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = "RageDroid wraps every secret in an additional age envelope. Unlocking any individual credential requires a hardware tap -- your YubiKey, the FIDO2 authenticator in your laptop, or this phone's secure element.",
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Both layers are needed to read a secret. Steal one, learn nothing.",
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
        }
        Spacer(modifier = Modifier.height(32.dp))
        RageButton(
            label = "Begin setup",
            onClick = onBegin,
            icon = Icons.AutoMirrored.Outlined.ArrowForward,
            fullWidth = true,
        )
        Spacer(modifier = Modifier.height(14.dp))
        Text(
            text = "Existing Bitwarden vault required · age/rage compatible · open source",
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
            kicker = "Step 1 of 3",
            title = "Sign in to your vault",
            sub = "Connect your Bitwarden vault. Self-hosted Vaultwarden works too.",
        )
        Column(modifier = Modifier.fillMaxWidth()) {
            FirstRunFieldLabel("Server")
            FirstRunInput(
                value = serverUrl,
                onChange = onServerChange,
                mono = true,
                placeholder = "https://vault.bitwarden.com",
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                autoCorrect = false,
            )
            Spacer(modifier = Modifier.height(16.dp))
            FirstRunFieldLabel("Email")
            FirstRunInput(
                value = email,
                onChange = onEmailChange,
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Email,
                autoCorrect = false,
            )
            Spacer(modifier = Modifier.height(16.dp))
            FirstRunFieldLabel("Master password")
            FirstRunInput(value = password, onChange = onPasswordChange, password = true)
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
                label = "Back",
                onClick = onBack,
                variant = ButtonVariant.Ghost,
            )
            Box(modifier = Modifier.weight(1f)) {
                RageButton(
                    label = if (busy) "Working..." else "Sign in & continue",
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
        server.isEmpty() -> "Enter your vault server, e.g. https://vault.bitwarden.com"
        !serverSchemeAccepted(server) ->
            "Server must start with https:// -- plain http:// is only allowed for localhost."
        account.isEmpty() -> "Enter the email address of your vault account."
        !account.contains('@') || account.any { it.isWhitespace() } ->
            "That doesn't look like an email address."
        password.isEmpty() -> "Enter your master password."
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
            modifier = Modifier.fillMaxWidth(),
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
    val name: String,
    val description: String,
    val icon: ImageVector,
    val tag: String? = null,
    val recommended: Boolean = false,
)

private val PRIMARY_OPTIONS = listOf(
    EnrollOption(
        kind = FirstRunEnrollKind.Platform,
        name = "This phone",
        description = "Use the secure element + biometrics already on this device.",
        icon = Icons.Outlined.Fingerprint,
        tag = "Fastest",
        recommended = true,
    ),
    EnrollOption(
        kind = FirstRunEnrollKind.SecurityKey,
        name = "A security key",
        description = "YubiKey, Solo, Titan, or any FIDO2 authenticator. Tap to confirm each unlock.",
        icon = Icons.Outlined.Nfc,
    ),
)

private val ADVANCED_OPTIONS = listOf(
    EnrollOption(
        kind = FirstRunEnrollKind.YubikeyPiv,
        name = "YubiKey (PIV mode)",
        description = "Pin a key to PIV slot 95 with an X25519 keypair. Power-user path.",
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
            kicker = "Step 2 of 3",
            title = "Enroll your first passkey",
            sub = "Pick how you want to authorize unlocks. Each unlock takes a tap. The private key is generated on the device and never leaves it.",
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
                    text = "More options",
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
                label = "Back",
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
                text = "Skip -- set up later",
                style = RageType.caption,
                color = rageColors.fgSecondary,
            )
        }
    }
}

@Composable
private fun EnrollOptionRow(option: EnrollOption, onClick: () -> Unit) {
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
                imageVector = option.icon,
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
                    text = option.name,
                    style = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp),
                    color = c.fgEmphasis,
                )
                if (option.recommended) {
                    Box(
                        modifier = Modifier
                            .border(1.dp, c.success, RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = "Recommended".uppercase(),
                            style = RageType.eyebrow.copy(fontSize = 10.sp, lineHeight = 12.sp),
                            color = c.success,
                        )
                    }
                } else if (option.tag != null) {
                    Text(
                        text = option.tag.uppercase(),
                        style = RageType.eyebrow.copy(fontSize = 10.sp, lineHeight = 12.sp),
                        color = c.fgSecondary,
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = option.description,
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 19.5.sp),
                color = c.fgSecondary,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier
                .padding(top = 8.dp)
                .size(18.dp),
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
            kicker = "Step 2 of 3",
            title = copy.title,
            sub = copy.sub,
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
                    FirstRunEnrollPhase.Idle -> copy.idleHint
                    FirstRunEnrollPhase.Listening -> copy.listeningHint
                    FirstRunEnrollPhase.Found -> "Authenticator detected. Recording it as a recipient..."
                    FirstRunEnrollPhase.DoneEnroll -> "Recorded as a recipient in your \"RageDroid Recipients\" secure note."
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
                    label = copy.startLabel,
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
                text = "If this device is lost and you've enrolled no backup recipients, your protected secrets become unrecoverable. Step 3 lets you pick a second way in.",
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
                        text = "Enrollment failed",
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
                        RageButton(label = "Try again", onClick = onTrigger, variant = ButtonVariant.Primary)
                        RageButton(label = "Dismiss", onClick = onDismissError, variant = ButtonVariant.Ghost)
                    }
                }
            }
        }
        if (phase == FirstRunEnrollPhase.DoneEnroll) {
            Spacer(modifier = Modifier.height(14.dp))
            RageButton(
                label = "Continue",
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
                text = "Back -- choose a different method",
                style = RageType.caption,
                color = c.fgSecondary,
            )
        }
    }
}

private data class EnrollCopy(
    val title: String,
    val sub: String,
    /** Label of the Start button. Must name what pressing it actually does. */
    val startLabel: String,
    val idleHint: String,
    val listeningHint: String,
    val doneTitle: String,
    val doneMeta: String,
)

// The idle hints all lead with Start. They used to open with "Insert via USB-C,
// or hold the key to the back of the phone" while the app had no NFC or USB
// discovery running at all -- nothing existed to insert a key into until the
// trigger fired.
private fun enrollCopy(kind: FirstRunEnrollKind): EnrollCopy = when (kind) {
    FirstRunEnrollKind.Platform -> EnrollCopy(
        title = "Enroll this phone",
        sub = "Generates a passkey backed by the device secure element. Biometric to unlock.",
        // Not "confirm with biometrics": enrollKeystoreIdentity falls back to a
        // non-biometric key when the device has none enrolled.
        startLabel = "Start -- enroll this phone",
        idleHint = "Tap Start to generate the key in this phone's secure element. You'll confirm with biometrics if the device has them.",
        listeningHint = "Confirm with your fingerprint to finish generating the key.",
        doneTitle = "This phone enrolled",
        doneMeta = "StrongBox · P-256",
    )
    FirstRunEnrollKind.SecurityKey -> EnrollCopy(
        title = "Enroll a security key",
        sub = "The key generates its own keypair. Nothing is listening for it until you press Start.",
        startLabel = "Start -- listen for the key",
        idleHint = "Tap Start, then present your key: insert via USB-C, or hold it to the back of the phone.",
        listeningHint = "Listening for NFC and USB-C... touch the key when it lights up.",
        doneTitle = "Security key enrolled",
        doneMeta = "FIDO2 · X25519",
    )
    FirstRunEnrollKind.YubikeyPiv -> EnrollCopy(
        title = "Enroll a YubiKey (PIV)",
        sub = "RageDroid generates an X25519 keypair on the YubiKey itself. The private key never leaves the device.",
        startLabel = "Start -- enter your PIN",
        idleHint = "Tap Start and enter your PIV PIN, then present the YubiKey: USB-C, or held to the back of the phone.",
        listeningHint = "Listening for NFC and USB-C... hold the key steady while it generates the keypair.",
        doneTitle = "YubiKey enrolled",
        doneMeta = "PIV slot 95 · X25519",
    )
}

@Composable
private fun EnrollIdleVisual(kind: FirstRunEnrollKind, listening: Boolean) {
    val c = rageColors
    val pulseAlpha by animateFloatAsState(
        targetValue = if (listening) 0.35f else 0f,
        animationSpec = tween(durationMillis = 800, easing = LinearEasing),
        label = "enroll-pulse",
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
            text = copy.doneTitle,
            style = RageType.rowTitle.copy(fontSize = 16.sp, lineHeight = 20.sp),
            color = c.fgEmphasis,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Mono(text = copy.doneMeta, size = 11, color = c.fgSecondary)
    }
}

private data class BackupOption(
    val name: String,
    val description: String,
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
    name = "Paper recovery phrase",
    description = "24 BIP39 words. Write them down once, keep them safe -- they unlock your vault on any new device.",
    icon = Icons.Outlined.Description,
    recommended = true,
)

@Composable
private fun BackupStep(
    onBack: () -> Unit,
    onPickRecovery: () -> Unit,
    onSkip: () -> Unit,
) {
    StepScaffold {
        StepTitle(
            kicker = "Step 3 of 3",
            title = "Add a backup recipient",
            sub = "A second way in, in case this device is lost. Recommended.",
        )
        BackupOptionRow(option = RECOVERY_BACKUP_OPTION, onClick = onPickRecovery)
        Spacer(modifier = Modifier.height(20.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RageButton(label = "Back", onClick = onBack, variant = ButtonVariant.Ghost)
            Box(modifier = Modifier.weight(1f)) {
                RageButton(
                    label = "Skip -- I'll add later",
                    onClick = onSkip,
                    variant = ButtonVariant.Secondary,
                    fullWidth = true,
                )
            }
        }
    }
}

@Composable
private fun BackupOptionRow(option: BackupOption, onClick: () -> Unit) {
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
                imageVector = option.icon,
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
                    text = option.name,
                    style = RageType.rowTitle.copy(fontSize = 15.sp, lineHeight = 19.sp),
                    color = c.fgEmphasis,
                )
                if (option.recommended) {
                    Box(
                        modifier = Modifier
                            .border(1.dp, c.success, RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = "Recommended".uppercase(),
                            style = RageType.eyebrow.copy(fontSize = 10.sp, lineHeight = 12.sp),
                            color = c.success,
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = option.description,
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 19.5.sp),
                color = c.fgSecondary,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier
                .size(18.dp)
                .padding(top = 8.dp),
        )
    }
}

@Composable
private fun DoneStep(onOpenVault: () -> Unit) {
    val c = rageColors
    val syncBody = buildAnnotatedString {
        append("Your vault is now syncing. New items default to ")
        withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
            append("protected")
        }
        append(". Existing items are unchanged -- you can convert them in batches from Settings.")
    }
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
                    .background(c.success, RoundedCornerShape(32.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Check,
                    contentDescription = null,
                    tint = Color(0xFFFAF6EE),
                    modifier = Modifier.size(32.dp),
                )
            }
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "Setup complete.",
                style = RageType.h1.copy(
                    fontSize = 30.sp,
                    lineHeight = 35.sp,
                    letterSpacing = (-0.015).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = syncBody,
                style = RageType.body.copy(fontSize = 16.sp, lineHeight = 25.sp),
                color = c.fgPrimary,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "One tap per reveal. No caching, no exceptions.",
                style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp, fontStyle = FontStyle.Italic),
                color = c.fgSecondary,
            )
        }
        RageButton(
            label = "Open vault",
            onClick = onOpenVault,
            icon = Icons.AutoMirrored.Outlined.ArrowForward,
            fullWidth = true,
        )
    }
}

