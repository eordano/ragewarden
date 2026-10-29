package ragewarden.ragedroid.ui.screens

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

enum class AddItemKind(val id: String, @androidx.annotation.StringRes val label: Int) {
    Login("login", R.string.login),
    Card("card", R.string.card),
    Note("note", R.string.secure_note),
    Identity("identity", R.string.identity),
    Ssh("ssh", R.string.ssh_key),
}

private data class TypeOption(
    val kind: AddItemKind,
    val icon: ImageVector,
    @androidx.annotation.StringRes val description: Int,
)

private val TYPE_OPTIONS = listOf(
    TypeOption(AddItemKind.Login, Icons.Outlined.Link, R.string.username_password_optionally_with_totp),
    TypeOption(AddItemKind.Card, Icons.Outlined.CreditCard, R.string.credit_debit_card_number_and_cvv),
    TypeOption(AddItemKind.Note, Icons.Outlined.Description, R.string.free_form_encrypted_text_no_structure),
    TypeOption(AddItemKind.Identity, Icons.Outlined.Person, R.string.name_address_id_numbers_for_autofill),
    TypeOption(AddItemKind.Ssh, Icons.Outlined.Terminal, R.string.private_key_gated_public_key_always),
)

@Composable
fun AddItemTypePickerScreen(
    onBack: () -> Unit,
    onPick: (AddItemKind) -> Unit,
) {
    val c = rageColors
    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.new_item),
            subtitle = stringResource(R.string.pick_a_type),
            leading = { BackButton(onBack) },
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        ) {
            TYPE_OPTIONS.forEachIndexed { index, option ->
                if (index > 0) Spacer(modifier = Modifier.height(8.dp))
                TypeOptionRow(option = option, onClick = { onPick(option.kind) })
            }
        }
    }
}

@Composable
private fun TypeOptionRow(option: TypeOption, onClick: () -> Unit) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(12.dp))
            .border(1.dp, c.border, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .background(c.tile, RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = option.icon,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(20.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(option.kind.label),
                style = RageType.rowTitle.copy(fontSize = 16.sp, lineHeight = 20.sp),
                color = c.fgEmphasis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = stringResource(option.description),
                style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 19.sp),
                color = c.fgSecondary,
            )
        }
        Box(modifier = Modifier.padding(top = 12.dp)) {
            Icon(
                imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
