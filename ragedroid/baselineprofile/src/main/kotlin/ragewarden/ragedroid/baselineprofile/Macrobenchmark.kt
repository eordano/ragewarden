package ragewarden.ragedroid.baselineprofile

import androidx.benchmark.macro.FrameTimingMetric
import androidx.benchmark.macro.StartupMode
import androidx.benchmark.macro.StartupTimingMetric
import androidx.benchmark.macro.junit4.MacrobenchmarkRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Macrobenchmark {
    @get:Rule val rule = MacrobenchmarkRule()

    @Before
    fun signIn() {
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        BenchVault.launch(device)
        BenchVault.openVault(device)
    }

    @Test
    fun coldStartup() = rule.measureRepeated(
        packageName = BenchVault.packageName,
        metrics = listOf(StartupTimingMetric()),
        iterations = ITERATIONS,
        startupMode = StartupMode.COLD,
    ) {
        pressHome()
        startActivityAndWait()
        BenchVault.find(device, By.res("lock-password"), "the lock screen after a cold start")
    }

    @Test
    fun vaultListScroll() = rule.measureRepeated(
        packageName = BenchVault.packageName,
        metrics = listOf(FrameTimingMetric()),
        iterations = ITERATIONS,
        setupBlock = {
            BenchVault.launch(device)
            BenchVault.openVault(device)
        },
    ) {
        val list = BenchVault.find(device, By.res(BenchVault.LIST), "the vault list")
        repeat(SCROLL_REPEATS) {
            list.fling(Direction.DOWN)
            device.waitForIdle()
            list.fling(Direction.UP)
            device.waitForIdle()
        }
    }

    @Test
    fun detailOpenClose() = rule.measureRepeated(
        packageName = BenchVault.packageName,
        metrics = listOf(FrameTimingMetric()),
        iterations = ITERATIONS,
        setupBlock = {
            BenchVault.launch(device)
            BenchVault.openVault(device)
        },
    ) {
        repeat(DETAIL_REPEATS) {
            BenchVault.itemRow(device).click()
            BenchVault.find(device, By.res(BenchVault.REVEAL), "the detail screen")
            device.pressBack()
            device.wait(Until.hasObject(By.res(BenchVault.LIST)), BenchVault.UI_TIMEOUT_MS)
        }
    }

    @Test
    fun detailReveal() = rule.measureRepeated(
        packageName = BenchVault.packageName,
        metrics = listOf(FrameTimingMetric()),
        iterations = ITERATIONS,
        setupBlock = {
            BenchVault.launch(device)
            BenchVault.openVault(device)
        },
    ) {
        BenchVault.itemRow(device).click()
        repeat(REVEAL_REPEATS) {
            BenchVault.find(device, By.res(BenchVault.REVEAL), "the Reveal action").click()
            BenchVault.find(device, By.res(BenchVault.HIDE), "the revealed password's Hide").click()
        }
        device.pressBack()
        device.wait(Until.hasObject(By.res(BenchVault.LIST)), BenchVault.UI_TIMEOUT_MS)
    }

    private companion object {
        const val ITERATIONS = 10
        const val SCROLL_REPEATS = 4
        const val DETAIL_REPEATS = 4
        const val REVEAL_REPEATS = 3
    }
}
