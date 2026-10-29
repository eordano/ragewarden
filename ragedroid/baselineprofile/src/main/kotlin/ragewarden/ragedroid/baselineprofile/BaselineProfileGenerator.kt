package ragewarden.ragedroid.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BaselineProfileGenerator {
    @get:Rule val rule = BaselineProfileRule()

    @Test
    fun coldStartThenVaultThenReveal() = rule.collect(
        packageName = BenchVault.packageName,
        includeInStartupProfile = true,
    ) {
        pressHome()
        startActivityAndWait()
        BenchVault.openVault(device)
        BenchVault.find(device, By.res(BenchVault.LIST), "the vault list")
        BenchVault.itemRow(device).click()
        BenchVault.find(device, By.res(BenchVault.REVEAL), "the Reveal action").click()
        BenchVault.find(device, By.res(BenchVault.HIDE), "the revealed password's Hide").click()
        device.pressBack()
    }
}
