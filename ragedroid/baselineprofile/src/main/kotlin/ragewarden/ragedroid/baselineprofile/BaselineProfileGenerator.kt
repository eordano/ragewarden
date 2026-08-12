package ragewarden.ragedroid.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BaselineProfileGenerator {
    @get:Rule val rule = BaselineProfileRule()

    @Test
    fun coldStartThenVaultThenReveal() = rule.collect(
        packageName = PACKAGE_NAME,
        includeInStartupProfile = true,
    ) {
        pressHome()
        startActivityAndWait()

        device.wait(Until.hasObject(By.descContains("Vault")), READY_TIMEOUT_MS)

        val firstItem = device.wait(
            Until.findObject(By.descContains("vault item")),
            ITEM_TIMEOUT_MS,
        )
        firstItem?.click()

        device.wait(Until.hasObject(By.descContains("Reveal")), READY_TIMEOUT_MS)
        val revealButton = device.findObject(By.descContains("Reveal"))
        revealButton?.click()

        device.wait(Until.hasObject(By.text("Authorize")), READY_TIMEOUT_MS)
    }

    private companion object {
        const val PACKAGE_NAME = "ragewarden.ragedroid"
        const val READY_TIMEOUT_MS = 5_000L
        const val ITEM_TIMEOUT_MS = 3_000L
    }
}
