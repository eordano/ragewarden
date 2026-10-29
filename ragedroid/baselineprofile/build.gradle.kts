import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.test)
    alias(libs.plugins.androidx.baselineprofile)
}

android {
    namespace = "ragewarden.ragedroid.baselineprofile"
    compileSdk = 37
    // The one build-tools the #android devshell installs (devshells/android.nix); left
    // unset, AGP asks for its own default and fails on the read-only SDK.
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 31
        targetSdk = 36
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets["main"].kotlin.directories += "src/main/kotlin"

    targetProjectPath = ":app"

    buildTypes {
        create("benchmark") {
            isDebuggable = false
        }
    }

    flavorDimensions += "distribution"
    productFlavors {
        create("standard") {
            dimension = "distribution"
            testInstrumentationRunnerArguments["benchPackage"] = "ragewarden.ragedroid"
        }
        create("fdroid") {
            dimension = "distribution"
            testInstrumentationRunnerArguments["benchPackage"] = "ragewarden.ragedroid.fdroid"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

baselineProfile {
    useConnectedDevices = true
    // The plugin's default passes androidx.benchmark.skipOnEmulator=true, which skips
    // every macrobenchmark on the emulator tests/journey/run.sh drives; run.sh passes
    // suppressErrors=EMULATOR so they run, and their numbers are labelled emulator ones.
    skipBenchmarksOnEmulator = false
}

dependencies {
    implementation(libs.androidx.test.ext.junit)
    implementation(libs.androidx.test.espresso.core)
    implementation(libs.androidx.test.uiautomator)
    implementation(libs.androidx.benchmark.macro.junit4)
}
