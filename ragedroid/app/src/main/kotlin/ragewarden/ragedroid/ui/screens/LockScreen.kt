package ragewarden.ragedroid.ui.screens

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
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
            val manager = BiometricManager.from(activity)
            val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            manager.canAuthenticate(allowed) == BiometricManager.BIOMETRIC_SUCCESS
        }
    }

    val identityLabel = remember(repo) {
        val mail = repo?.email.orEmpty()
        val srv = repo?.serverUrl.orEmpty()
        when {
            mail.isNotEmpty() && srv.isNotEmpty() -> "$mail · $srv"
            mail.isNotEmpty() -> mail
            srv.isNotEmpty() -> srv
            else -> "Signed-in vault"
        }
    }

    val launchPrompt: () -> Unit = launch@{
        if (activity == null || !biometricSupported) {
            phase = LockPhase.Password
            return@launch
        }
        if (phase == LockPhase.Scanning) return@launch
        phase = LockPhase.Scanning
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                phase = LockPhase.Success
                onUnlock()
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
            .setTitle("Unlock RageDroid")
            .setSubtitle(identityLabel)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()
        prompt.authenticate(info)
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
            pwError = "No vault session on this device to check the password against. " +
                "Sign out and sign in again."
            return@submit
        }
        working = true
        scope.launch {
            val result = repo.verifyMasterPassword(pw)
            working = false
            result.fold(
                onSuccess = { ok ->
                    if (ok) {
                        phase = LockPhase.Success
                        onUnlock()
                    } else {
                        pwError = "Wrong master password."
                    }
                },
                onFailure = { e ->
                    pwError = e.message ?: "Could not verify password."
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
                text = "RageDroid",
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
                        LockPhase.Idle -> if (biometricSupported) "Touch the sensor to unlock" else "Use master password to unlock"
                        LockPhase.Scanning -> "Authenticating..."
                        LockPhase.Success -> "Welcome back"
                        LockPhase.Failed -> "Try again"
                        LockPhase.Password -> ""
                    },
                    style = RageType.h2.copy(fontSize = 18.sp, lineHeight = 22.sp),
                    color = c.fgEmphasis,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Unlocks the vault. Each protected item still needs its own tap.",
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
                        text = "Master password",
                        style = RageType.h2.copy(fontSize = 20.sp),
                        color = c.fgEmphasis,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "PBKDF2 KDF, run on this device.",
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
                        label = if (working) "Verifying..." else "Unlock",
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
                            "Use master password instead"
                        } else {
                            "Use fingerprint instead"
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
                    text = "Sign out of this vault",
                    style = RageType.button.copy(fontSize = 13.sp),
                    color = c.fgSecondary,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
