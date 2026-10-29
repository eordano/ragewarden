package ragewarden.ragedroid.ui.screens

import androidx.compose.ui.res.stringResource
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.describe
import androidx.compose.ui.platform.testTag
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import ragewarden.ragedroid.di.appEntryPoint
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowForward
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.components.TextInput
import ragewarden.ragedroid.ui.findActivity
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

private enum class LockPhase { Idle, Scanning, Success, Password, Failed }

/**
 * The vault lock.
 *
 * There are exactly two ways off this screen and both are authenticated or
 * destructive: [onUnlock] (biometric/device credential, or the master password
 * verified by `BitwardenVaultRepository.verifyMasterPassword`) and [onSignOut],
 * which drops the session entirely.
 *
 * It used to also carry a "Settings" affordance -- the least visible text on the
 * screen, 10.5 sp at 70% alpha -- wired to `Stage.Settings`, whose own back
 * handler went to `Stage.Vault`. That was the whole bypass: two taps from locked
 * to unlocked, no authentication. It is replaced by the sign-out escape hatch it
 * was presumably standing in for, which is now stated plainly.
 */
@Composable
fun LockScreen(
    onUnlock: () -> Unit,
    onSignOut: () -> Unit,
    onToast: (String) -> Unit = {},
    repo: BitwardenVaultRepository? = VaultBridge.repository(),
) {
    val c = rageColors
    val context = LocalContext.current
    // findActivity(), not a bare cast: LocalContext is a ContextThemeWrapper
    // around the Activity in some hosts, and a null here silently downgrades
    // this screen to password-only.
    val activity = context.findActivity() as? FragmentActivity
    val scope = rememberCoroutineScope()
    var phase by remember { mutableStateOf(LockPhase.Idle) }
    var pw by remember { mutableStateOf("") }
    var pwError by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    var promptRequested by remember { mutableStateOf(false) }

    val biometricSupported = remember(activity) {
        if (activity == null) {
            false
        } else {
            BiometricManager.from(activity)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        }
    }
    val keyWrap = remember(context) { runCatching { context.appEntryPoint().sessionKeyWrap() }.getOrNull() }

    val identityLabel = remember(repo) {
        val mail = repo?.email.orEmpty()
        val srv = repo?.serverUrl.orEmpty()
        when {
            mail.isNotEmpty() && srv.isNotEmpty() -> "$mail · $srv"
            mail.isNotEmpty() -> mail
            srv.isNotEmpty() -> srv
            else -> uiString(R.string.signed_in_vault)
        }
    }

    val launchPrompt: () -> Unit = launch@{
        val cipher = if (activity != null && biometricSupported && repo != null) keyWrap?.decryptCipher() else null
        if (activity == null || cipher == null) {
            phase = LockPhase.Password
            return@launch
        }
        if (phase == LockPhase.Scanning) return@launch
        phase = LockPhase.Scanning
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authed = result.cryptoObject?.cipher
                scope.launch {
                    val unlocked = authed?.let { c -> runCatching { keyWrap?.unwrap(c) }.getOrNull() }
                    val ok = unlocked != null && repo?.unlockWithSessionBlob(unlocked)?.isSuccess == true
                    unlocked?.fill(0)
                    if (ok) {
                        phase = LockPhase.Success
                        onUnlock()
                    } else {
                        keyWrap?.clear()
                        phase = LockPhase.Password
                        onToast(uiString(R.string.biometric_unlock_needs_setting_up_again))
                    }
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                phase = LockPhase.Idle
                when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED,
                    -> Unit
                    BiometricPrompt.ERROR_HW_UNAVAILABLE,
                    BiometricPrompt.ERROR_HW_NOT_PRESENT,
                    -> {
                        promptRequested = false
                    }
                    else -> {
                        promptRequested = false
                        if (errString.isNotEmpty()) onToast(errString.toString())
                    }
                }
            }

            override fun onAuthenticationFailed() {
                phase = LockPhase.Failed
            }
        }
        val prompt = BiometricPrompt(activity, executor, callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(uiString(R.string.unlock_ragedroid))
            .setSubtitle(identityLabel)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(uiString(R.string.use_master_password))
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    val finishPasswordUnlock: () -> Unit = finish@{
        val wrap = keyWrap
        val enrollCipher = if (activity != null && biometricSupported && wrap != null && !wrap.isEnrolled() && !wrap.declined) {
            wrap.encryptCipher()
        } else {
            null
        }
        val session = repo?.unlockedSessionForWrapping()
        if (activity == null || wrap == null || enrollCipher == null || session == null) {
            session?.fill(0)
            phase = LockPhase.Success
            onUnlock()
            return@finish
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                result.cryptoObject?.cipher?.let { c -> runCatching { wrap.store(c, session) } }
                session.fill(0)
                phase = LockPhase.Success
                onUnlock()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) wrap.declined = true
                session.fill(0)
                phase = LockPhase.Success
                onUnlock()
            }
        }
        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(uiString(R.string.unlock_with_biometrics_next_time))
                .setSubtitle(uiString(R.string.your_vault_key_is_sealed_to))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(uiString(R.string.not_now))
                .build(),
            BiometricPrompt.CryptoObject(enrollCipher),
        )
    }

    LaunchedEffect(activity, biometricSupported) {
        if (!promptRequested && activity != null && biometricSupported && phase == LockPhase.Idle) {
            promptRequested = true
            launchPrompt()
        } else if (activity == null || !biometricSupported) {
            phase = LockPhase.Password
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, activity, biometricSupported) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME &&
                activity != null &&
                biometricSupported &&
                phase == LockPhase.Idle &&
                !promptRequested
            ) {
                promptRequested = true
                launchPrompt()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val submitPassword: () -> Unit = submit@{
        if (working || pw.isEmpty()) return@submit
        pwError = null
        if (repo == null) {
            // Fail closed. This used to accept *any* non-empty string and call
            // onUnlock() when no repository was installed -- which is precisely
            // the state a cold, locked launch is in, because the stage tree that
            // calls VaultBridge.ensureBackend is not composed behind the lock.
            // Nothing here can verify the password, so nothing here may pass it.
            pwError = uiString(R.string.no_vault_session_on_this_device)
            return@submit
        }
        working = true
        scope.launch {
            val result = repo.unlockWithPassword(pw)
            working = false
            result.fold(
                onSuccess = { ok ->
                    if (ok) {
                        pw = ""
                        finishPasswordUnlock()
                    } else {
                        pwError = uiString(R.string.wrong_master_password)
                    }
                },
                onFailure = {
                    pwError = uiString(R.string.couldn_t_check_the_password_a)
                },
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 24.dp, end = 24.dp, top = 40.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .size(56.dp)
                    .background(c.fgEmphasis, RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Link,
                    contentDescription = null,
                    tint = c.background,
                    modifier = Modifier.size(28.dp),
                )
            }
            Spacer(modifier = Modifier.height(18.dp))
            Text(
                text = stringResource(R.string.ragedroid),
                style = RageType.h1.copy(
                    fontSize = 28.sp,
                    lineHeight = 31.sp,
                    letterSpacing = (-0.015).em,
                ),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = identityLabel,
                style = RageType.caption.copy(fontSize = 12.5.sp),
                color = c.fgSecondary,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
            )
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (phase != LockPhase.Password) {
                Box(
                    modifier = Modifier
                        .size(132.dp)
                        .background(
                            if (phase == LockPhase.Success) c.success else c.tile,
                            RoundedCornerShape(66.dp),
                        )
                        .clickable(
                            enabled = phase == LockPhase.Idle || phase == LockPhase.Failed,
                            onClick = launchPrompt,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    if (phase == LockPhase.Scanning) {
                        Box(
                            modifier = Modifier
                                .size(152.dp)
                                .border(2.dp, c.accent.copy(alpha = 0.3f), RoundedCornerShape(76.dp)),
                        )
                    }
                    Icon(
                        imageVector = if (phase == LockPhase.Success) Icons.Outlined.Check else Icons.Outlined.Fingerprint,
                        contentDescription = null,
                        tint = if (phase == LockPhase.Success) c.background else c.accent,
                        modifier = Modifier.size(56.dp),
                    )
                }
                Spacer(modifier = Modifier.height(28.dp))
                Text(
                    text = when (phase) {
                        LockPhase.Idle -> if (biometricSupported) stringResource(R.string.touch_the_sensor_to_unlock) else stringResource(R.string.use_master_password_to_unlock)
                        LockPhase.Scanning -> stringResource(R.string.authenticating)
                        LockPhase.Success -> stringResource(R.string.welcome_back)
                        LockPhase.Failed -> stringResource(R.string.try_again)
                        LockPhase.Password -> ""
                    },
                    style = RageType.h2.copy(fontSize = 18.sp, lineHeight = 22.sp),
                    color = c.fgEmphasis,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.unlocks_the_vault_each_protected_item),
                    style = RageType.caption.copy(fontSize = 12.5.sp, lineHeight = 19.sp),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.widthIn(max = 280.dp),
                )
            } else {
                Column(
                    modifier = Modifier.widthIn(max = 320.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .background(c.tile, RoundedCornerShape(24.dp)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Lock,
                            contentDescription = null,
                            tint = c.accent,
                            modifier = Modifier.size(22.dp),
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.master_password),
                        style = RageType.h2.copy(fontSize = 20.sp),
                        color = c.fgEmphasis,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = stringResource(
                            R.string.master_password_stretched_here,
                            repo?.kdf?.describe(context.resources) ?: stringResource(R.string.master_password),
                        ),
                        style = RageType.caption,
                        color = c.fgSecondary,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(modifier = Modifier.height(24.dp))
                    TextInput(
                        value = pw,
                        onValueChange = {
                            pw = it
                            pwError = null
                        },
                        placeholder = "••••••••••••",
                        password = true,
                        modifier = Modifier.testTag("lock-password"),
                    )
                    if (pwError != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = pwError!!,
                            style = RageType.caption.copy(fontSize = 12.5.sp),
                            color = c.dangerStrong,
                            textAlign = TextAlign.Center,
                        )
                    }
                    Spacer(modifier = Modifier.height(14.dp))
                    RageButton(
                        label = if (working) stringResource(R.string.verifying) else stringResource(R.string.unlock),
                        onClick = submitPassword,
                        icon = Icons.AutoMirrored.Outlined.ArrowForward,
                        fullWidth = true,
                        enabled = pw.isNotEmpty() && !working,
                    )
                }
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 24.dp, end = 24.dp, bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (biometricSupported) {
                Row(
                    modifier = Modifier
                        .clickable {
                            if (phase != LockPhase.Password) {
                                phase = LockPhase.Password
                            } else {
                                phase = LockPhase.Idle
                                pw = ""
                                pwError = null
                            }
                        }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = if (phase != LockPhase.Password) {
                            stringResource(R.string.use_master_password_instead)
                        } else {
                            stringResource(R.string.use_fingerprint_instead)
                        },
                        style = RageType.button.copy(fontSize = 13.sp),
                        color = c.fgSecondary,
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier
                    .clickable(onClick = onSignOut)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                Text(
                    text = stringResource(R.string.sign_out_of_this_vault),
                    style = RageType.button.copy(fontSize = 13.sp),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
