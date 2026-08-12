package ragewarden.ragedroid.baselineprofile

import androidx.benchmark.macro.ExperimentalMetricApi
import androidx.benchmark.macro.FrameTimingMetric
import androidx.benchmark.macro.StartupMode
import androidx.benchmark.macro.StartupTimingMetric
import androidx.benchmark.macro.TraceSectionMetric
import androidx.benchmark.macro.junit4.MacrobenchmarkRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.Until
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Macrobenchmark {
    @get:Rule val rule = MacrobenchmarkRule()

    private fun androidx.benchmark.macro.MacrobenchmarkScope.skipOnboardingIfPresent() {
        device.executeShellCommand(
            "am start -n $PACKAGE_NAME/.MainActivity --ez ragewarden.demo true",
        )
        device.wait(Until.hasObject(By.text(FIRST_ITEM_NAME)), READY_TIMEOUT_MS)
    }

    @Test
    fun coldStartup() = rule.measureRepeated(
        packageName = PACKAGE_NAME,
        metrics = listOf(StartupTimingMetric()),
        iterations = ITERATIONS,
        startupMode = StartupMode.COLD,
    ) {
        pressHome()
        startActivityAndWait()
        skipOnboardingIfPresent()
    }

    @Test
    fun vaultListScroll() = rule.measureRepeated(
        packageName = PACKAGE_NAME,
        metrics = listOf(FrameTimingMetric()),
        iterations = ITERATIONS,
        startupMode = StartupMode.WARM,
    ) {
        pressHome()
        startActivityAndWait()
        skipOnboardingIfPresent()

        val list = device.findObject(By.scrollable(true))
        if (list != null) {
            repeat(SCROLL_REPEATS) {
                list.fling(Direction.DOWN)
                device.waitForIdle()
                list.fling(Direction.UP)
                device.waitForIdle()
            }
        }
    }

    @Test
    fun detailOpenClose() = rule.measureRepeated(
        packageName = PACKAGE_NAME,
        metrics = listOf(FrameTimingMetric()),
        iterations = ITERATIONS,
        startupMode = StartupMode.WARM,
    ) {
        pressHome()
        startActivityAndWait()
        skipOnboardingIfPresent()

        repeat(DETAIL_REPEATS) {
            val item = device.wait(
                Until.findObject(By.text(FIRST_ITEM_NAME)),
                ITEM_TIMEOUT_MS,
            ) ?: return@repeat
            item.click()
            device.wait(Until.hasObject(By.text("Username")), READY_TIMEOUT_MS)
            device.pressBack()
            device.wait(Until.hasObject(By.text(FIRST_ITEM_NAME)), READY_TIMEOUT_MS)
        }
    }

    @OptIn(ExperimentalMetricApi::class)
    @Test
    fun detailTapReveal() = rule.measureRepeated(
        packageName = PACKAGE_NAME,
        metrics = listOf(
            FrameTimingMetric(),
            TraceSectionMetric("ragewarden.decrypt", TraceSectionMetric.Mode.Sum),
        ),
        iterations = ITERATIONS,
        startupMode = StartupMode.WARM,
    ) {
        pressHome()
        startActivityAndWait()
        skipOnboardingIfPresent()

        val item = device.wait(
            Until.findObject(By.text(FIRST_ITEM_NAME)),
            ITEM_TIMEOUT_MS,
        ) ?: return@measureRepeated
        item.click()
        device.wait(Until.hasObject(By.text("Reveal")), READY_TIMEOUT_MS)

        repeat(REVEAL_REPEATS) {
            val reveal = device.wait(
                Until.findObject(By.text("Reveal")),
                ITEM_TIMEOUT_MS,
            ) ?: return@repeat
            reveal.click()
            val authorize = device.wait(
                Until.findObject(By.text("Authorize")),
                READY_TIMEOUT_MS,
            ) ?: return@repeat
            authorize.click()
            device.wait(Until.hasObject(By.text("Hide")), READY_TIMEOUT_MS)
            val hide = device.findObject(By.text("Hide"))
            hide?.click()
            device.wait(Until.hasObject(By.text("Reveal")), READY_TIMEOUT_MS)
        }
    }

    private companion object {
        const val PACKAGE_NAME = "ragewarden.ragedroid"
        const val FIRST_ITEM_NAME = "GitHub"
        const val ITERATIONS = 20
        const val SCROLL_REPEATS = 4
        const val DETAIL_REPEATS = 4
        const val REVEAL_REPEATS = 3
        const val READY_TIMEOUT_MS = 5_000L
        const val ITEM_TIMEOUT_MS = 3_000L
        const val ONBOARDING_TIMEOUT_MS = 3_000L
    }
}
