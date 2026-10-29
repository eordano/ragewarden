package ragewarden.ragedroid.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import ragewarden.ragedroid.ui.screens.AddItemKind
import ragewarden.ragedroid.ui.screens.TapFailureKind

class StageCodecTest {
    @Test
    fun every_stage_survives_a_saved_state_round_trip() {
        val stages = listOf(
            Stage.FirstRun, Stage.Vault, Stage.Search, Stage.Settings, Stage.Account, Stage.AddRecipient,
            Stage.Folders, Stage.FolderEdit, Stage.AddItemTypePicker, Stage.AuditLog, Stage.BackfillWizard,
            Stage.BulkProtect, Stage.PaperRecovery, Stage.RecoverFromPhrase, Stage.RecipientsList,
            Stage.TokenExpired, Stage.AutofillPickerPreview, Stage.ImePreview,
            Stage.RecipientDetail("r-1"), Stage.ItemHistory("i-1"),
            Stage.TapFailure("i-2", TapFailureKind.WrongKey),
        ) + AddItemKind.entries.map { Stage.AddItem(it) }
        stages.forEach { assertEquals(it, StageCodec.decode(StageCodec.encode(it))) }
    }
}
