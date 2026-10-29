package ragewarden.ragedroid.ui

import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.screens.BackupStep
import ragewarden.ragedroid.ui.screens.DoneStep
import ragewarden.ragedroid.ui.theme.RageTheme

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp")
class FirstRunBackupDoneTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun the_backup_steps_main_action_writes_the_phrase_and_skip_is_a_caption() {
        var picked = 0
        var skipped = 0
        composeRule.setContent {
            RageTheme { BackupStep(onBack = {}, onPickRecovery = { picked++ }, onSkip = { skipped++ }) }
        }
        composeRule.onNodeWithText(context.getString(R.string.write_down_a_recovery_phrase))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))
            .performClick()
        composeRule.onNodeWithText(context.getString(R.string.skip_i_ll_add_later), useUnmergedTree = true)
            .performClick()
        assertEquals(1, picked)
        assertEquals(1, skipped)
    }

    @Test
    fun done_with_nothing_enrolled_says_unprotected_and_lists_both_tasks() {
        composeRule.setContent { RageTheme { DoneStep(keyEnrolled = false, backupEnrolled = false, onOpenVault = {}) } }
        composeRule.onNodeWithText(context.getString(R.string.vault_not_protected_yet)).assertExists()
        composeRule.onAllNodesWithTag("done-todo").assertCountEquals(2)
        composeRule.onNodeWithText(context.getString(R.string.todo_add_a_key)).assertExists()
        composeRule.onNodeWithText(context.getString(R.string.todo_add_paper_backup)).assertExists()
    }

    @Test
    fun done_with_a_key_but_no_backup_lists_only_the_backup() {
        composeRule.setContent { RageTheme { DoneStep(keyEnrolled = true, backupEnrolled = false, onOpenVault = {}) } }
        composeRule.onNodeWithText(context.getString(R.string.setup_complete)).assertExists()
        composeRule.onAllNodesWithTag("done-todo").assertCountEquals(1)
        composeRule.onNodeWithText(context.getString(R.string.todo_add_paper_backup)).assertExists()
    }

    @Test
    fun done_with_both_lists_nothing() {
        composeRule.setContent { RageTheme { DoneStep(keyEnrolled = true, backupEnrolled = true, onOpenVault = {}) } }
        composeRule.onNodeWithText(context.getString(R.string.setup_complete)).assertExists()
        composeRule.onAllNodesWithTag("done-todo").assertCountEquals(0)
    }
}
