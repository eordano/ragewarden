package ragewarden.ragedroid.ui.components

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

/** Scans an otpauth:// QR code and hands its contents to [onScanned]. */
@Composable
fun TotpScanButton(onScanned: (String) -> Unit, modifier: Modifier = Modifier) {
    val c = rageColors
    val launcher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf { it.isNotBlank() }?.let(onScanned)
    }
    val prompt = stringResource(R.string.scan_totp_qr_code)
    Box(
        modifier = modifier
            .background(c.surface, RoundedCornerShape(8.dp))
            .border(1.dp, c.border, RoundedCornerShape(8.dp))
            .buttonTarget {
                launcher.launch(
                    ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt(prompt)
                        setBeepEnabled(false)
                        setOrientationLocked(false)
                    },
                )
            }
            .padding(horizontal = 12.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(imageVector = Icons.Outlined.QrCodeScanner, contentDescription = null, tint = c.fgPrimary, modifier = Modifier.size(14.dp))
            Text(text = stringResource(R.string.scan), style = RageType.button, color = c.fgPrimary)
        }
    }
}
