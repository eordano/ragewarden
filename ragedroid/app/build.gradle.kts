import org.gradle.api.tasks.Exec
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
    alias(libs.plugins.androidx.baselineprofile)
    alias(libs.plugins.roborazzi)
}

// The environment variables that carry the release signing material. The signingConfig
// and the `requireReleaseSigning` guard below both read this list so the two cannot
// drift apart -- adding a variable here is enough to make it mandatory.
val keystoreEnv = "RAGEDROID_KEYSTORE"
val releaseSigningEnv = listOf(
    keystoreEnv,
    "RAGEDROID_KEYSTORE_PASSWORD",
    "RAGEDROID_KEY_ALIAS",
    "RAGEDROID_KEY_PASSWORD",
)

// `-PunsignedBuild=true` is the only sanctioned way to build a release variant with no
// keystore: scripts/repro/verify-ragedroid.sh passes it so the hash it records is not
// contaminated by a per-build signature (SECURITY.md, "Reproducible-build verification").
// An unsigned APK is self-evidently unsigned -- no device will install it -- which is why
// it is an acceptable escape hatch and a debug-signed one was not.
// Only the literal `true` opens the hatch. This used to be `it != "false"`, which made a
// bare `-PunsignedBuild` (Gradle passes the empty string), `-PunsignedBuild=0` and
// `-PunsignedBuild=no` all disable the signing gate -- the opposite of what any of them
// reads as. Anything unrecognised is refused rather than guessed at.
val unsignedBuild: Boolean = providers.gradleProperty("unsignedBuild")
    .map {
        when (it.trim().lowercase()) {
            "true" -> true
            "false" -> false
            else -> throw GradleException(
                "-PunsignedBuild takes 'true' or 'false'; got '$it'. " +
                "Write -PunsignedBuild=true to build a deliberately unsigned release APK, " +
                "or drop the flag entirely to require real signing material."
            )
        }
    }
    .getOrElse(false)

// The version the APK claims, from the environment. These used to be the literals below,
// so every `v*` tag published an APK with versionCode 1: the package manager refuses to
// install an APK whose versionCode did not increase, which made the release-to-release
// upgrade path impossible. .github/workflows/release.yml derives both from the tag and
// exports them under exactly these two names.
//
// Read at configuration time, unlike `requireReleaseSigning` below: `defaultConfig` wants
// the values themselves, not a promise of them. The reason that gate defers to execution
// time -- that an empty environment must not break `assembleDebug` -- does not apply here,
// because an unset variable is not an error. It falls back to the literal that used to be
// hardcoded, so a developer's `assembleFdroidDebug` builds exactly as it did before.
//
// Read through `providers` rather than System.getenv (the idiom the keystore uses) because
// a configuration-time read has to be a declared build input: under --configuration-cache
// a System.getenv here would be baked into the cached configuration, and a later build
// with a *different* RAGEDROID_VERSION_CODE would silently reuse the old number -- the same
// class of bug this replaces. `providers.environmentVariable` invalidates the cache
// instead. An execution-time read is not an option: nothing would be left to hand the
// value to.
val versionCodeEnv = "RAGEDROID_VERSION_CODE"
val versionNameEnv = "RAGEDROID_VERSION_NAME"
val defaultVersionCode = 1
val defaultVersionName = "0.1.0"

// A malformed value fails the build instead of falling back. Falling back would mean a
// typo'd tag ships versionCode 1 again, silently, which is the entire bug being fixed --
// and it would only be discovered by a user whose update refuses to install.
val ragedroidVersionCode: Int = providers.environmentVariable(versionCodeEnv)
    .map { raw ->
        val value = raw.trim()
        if (value.isEmpty()) {
            defaultVersionCode
        } else {
            // Parsed as a Long so that an over-large number is reported as out of range
            // rather than as "not a number": toIntOrNull() returns null on overflow too,
            // and "3000000000 is not a whole number" would send the reader hunting for a
            // typo that is not there.
            val parsed = value.toLongOrNull() ?: throw GradleException(
                "$versionCodeEnv must be a positive whole number (Android's versionCode); " +
                "got '$raw'. It is a monotonically increasing integer, not a version " +
                "string -- pass 10203, not v1.2.3. Leave it unset for a local build; it " +
                "then defaults to $defaultVersionCode."
            )
            // Zero and negatives cannot ship at all, and the platform caps versionCode at
            // 2100000000 (below Int.MAX_VALUE, so the toInt() below cannot overflow).
            if (parsed < 1 || parsed > 2_100_000_000) {
                throw GradleException(
                    "$versionCodeEnv must be between 1 and 2100000000; got '$parsed'. " +
                    "Android will not install an APK whose versionCode did not increase, " +
                    "so a zero or negative one can never be an upgrade of anything, and " +
                    "the platform rejects anything above the cap outright."
                )
            }
            parsed.toInt()
        }
    }
    .getOrElse(defaultVersionCode)

val ragedroidVersionName: String = providers.environmentVariable(versionNameEnv)
    .map { it.trim().ifEmpty { defaultVersionName } }
    .getOrElse(defaultVersionName)

android {
    namespace = "ragewarden.ragedroid"
    compileSdk = 37

    // Must be stated. Left unset, AGP falls back to *its* default build-tools and then
    // tries to download it -- which on NixOS means writing into the read-only nix store
    // and a "Failed to install the following SDK components" failure before a single
    // source file compiles. The version has to be one the toolchain actually ships:
    // devshells/android.nix installs exactly this one and points the aapt2 override at
    // the same directory, so changing it here means changing it there too.
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "ragewarden.ragedroid"
        minSdk = 31
        targetSdk = 36
        // See versionCodeEnv / versionNameEnv above. The fdroid flavour still appends its
        // `-fdroid` versionNameSuffix to whatever lands here.
        versionCode = ragedroidVersionCode
        versionName = ragedroidVersionName
        buildConfigField("String", "YUBIKIT_VERSION", "\"${libs.versions.yubikit.get()}\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // The journey package (JourneyTest, DeliveryFlowsTest) and the registry package
        // (RegistryPushInstrumentedTest) cannot run on their own: they need the
        // journeyServer/... or registryServer/... instrumentation arguments, and the
        // Vaultwarden, the accounts and the `adb reverse` that make them mean anything are
        // set up by tests/journey/run.sh. Without them the journey tests throw and the
        // registry test trips its assumption, which AGP's result XML records as a failure
        // under a green build. Filter each package out of exactly the runs that lack its
        // arguments. run.sh passes them, so its runs are unfiltered and the tests are
        // neither weakened nor skipped where they can actually execute. One value per
        // filter key: with the two packages comma-joined into notPackage, the unfiltered
        // run reached the device as `-e notPackage ragewarden.ragedroid.journey` and still
        // ran the registry test.
        fun driven(arg: String) = providers
            .gradleProperty("android.testInstrumentationRunnerArguments.$arg")
            .isPresent
        if (!driven("journeyServer")) {
            testInstrumentationRunnerArguments["notPackage"] = "ragewarden.ragedroid.journey"
        }
        if (!driven("registryServer")) {
            testInstrumentationRunnerArguments["notClass"] = "ragewarden.ragedroid.registry.RegistryPushInstrumentedTest"
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        // Release signing reads from the environment (see releaseSigningEnv above).
        //
        // There is deliberately no fallback. This used to drop to the *debug* signing
        // config when RAGEDROID_KEYSTORE was unset, and the release workflow -- which
        // passed no keystore at all -- published the result as a "signed APK". The debug
        // key is a well-known, publicly-derivable key: anyone can mint an APK that the
        // package manager accepts as an upgrade of ours. An incomplete environment now
        // fails the build in `requireReleaseSigning` instead of shipping that.
        create("release") {
            val storePath = System.getenv(keystoreEnv)
            if (!storePath.isNullOrBlank()) {
                storeFile = file(storePath)
                storePassword = System.getenv("RAGEDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("RAGEDROID_KEY_ALIAS")
                keyPassword = System.getenv("RAGEDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Mock hardware is a compile-time constant here, so `MockHardware.enabled()`
            // folds to `false` and no simulated authenticator can be switched on at
            // runtime in a shipped APK (see identities/MockHardware.kt).
            buildConfigField("boolean", "MOCK_HARDWARE_ALLOWED", "false")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Never the debug config. Either the release keystore is configured, or this
            // is an explicitly-unsigned reproducibility build, or `requireReleaseSigning`
            // fails the packaging task.
            signingConfig = if (unsignedBuild) null else signingConfigs.getByName("release")
        }
        debug {
            buildConfigField("boolean", "MOCK_HARDWARE_ALLOWED", "true")
            isMinifyEnabled = false
            isPseudoLocalesEnabled = true
        }
        create("benchmark") {
            // initWith copies release's buildConfigFields, so MOCK_HARDWARE_ALLOWED
            // stays false here too.
            initWith(getByName("release"))
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += "release"
            isDebuggable = false
            isProfileable = true
        }
    }

    flavorDimensions += "distribution"
    productFlavors {
        create("standard") {
            dimension = "distribution"
        }
        create("fdroid") {
            dimension = "distribution"
            applicationIdSuffix = ".fdroid"
            versionNameSuffix = "-fdroid"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        // Required for MOCK_HARDWARE_ALLOWED above.
        buildConfig = true
    }

    sourceSets["main"].kotlin.directories += "src/main/kotlin"
    sourceSets["test"].kotlin.directories += "src/test/kotlin"
    sourceSets["androidTest"].kotlin.directories += "src/androidTest/kotlin"
    sourceSets["main"].jniLibs.directories += "src/main/jniLibs"
    sourceSets["standard"].kotlin.directories += "src/standard/kotlin"
    sourceSets["fdroid"].kotlin.directories += "src/fdroid/kotlin"

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
            // Robolectric 4.17's FileDescriptor interceptor reaches into
            // jdk.internal.access.SharedSecrets; without the export every test that
            // touches a file fails in setUpApplicationState with IllegalAccessException.
            all { it.jvmArgs("--add-exports=java.base/jdk.internal.access=ALL-UNNAMED") }
        }
        managedDevices {
            localDevices {
                create("pixel6Api34") {
                    device = "Pixel 6"
                    apiLevel = 34
                    systemImageSource = "aosp"
                }
            }
        }
        animationsDisabled = true
    }
}

androidComponents {
    // The baselineprofile plugin adds nonMinifiedRelease and benchmarkRelease as copies of
    // release, signing config included. They only ever run on a test device, like the
    // debug-signed benchmark type above; with no release keystore, generateBaselineProfile
    // stopped in validateSigningFdroidNonMinifiedRelease. Release itself is untouched.
    finalizeDsl { ext ->
        ext.buildTypes.matching { it.name == "nonMinifiedRelease" || it.name == "benchmarkRelease" }.configureEach {
            signingConfig = ext.signingConfigs.getByName("debug")
        }
    }
    onVariants { variant ->
        val variantName = variant.name.replaceFirstChar { it.uppercase() }
        tasks.matching { it.name == "merge${variantName}JniLibFolders" }.configureEach {
            dependsOn(tasks.named("cargoNdkBuild"))
        }
        // Packaging a release APK with no signing material must fail rather than silently
        // emit an unsigned (or, historically, debug-signed) APK that CI then publishes as
        // signed. The check hangs off the per-variant package task instead of the
        // configuration block above so that `assembleDebug`, the benchmark variant, unit
        // tests and IDE syncs all keep working with an empty environment.
        if (variant.buildType == "release" && !unsignedBuild) {
            tasks.matching { it.name == "package$variantName" }.configureEach {
                dependsOn(tasks.named("requireReleaseSigning"))
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

baselineProfile {
    mergeIntoMain = true
    saveInSrc = true
    automaticGenerationDuringBuild = false
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.autofill)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.savedstate)
    implementation(libs.androidx.savedstate.ktx)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.collections.immutable)

    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.androidx.credentials)
    "standardImplementation"(libs.androidx.credentials.play.services.auth)

    implementation(libs.androidx.profileinstaller)
    implementation(libs.androidx.tracing.ktx)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.yubikit.android)
    implementation(libs.yubikit.piv)
    implementation(libs.zxing.android.embedded)
    implementation(libs.guava)
    implementation(libs.hilt.android)
    implementation(libs.androidx.hilt.navigation.compose)
    ksp(libs.hilt.compiler)
    "baselineProfile"(project(":baselineprofile"))

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(platform(libs.compose.bom))
    testImplementation(libs.compose.ui.test.junit4)
    testImplementation(libs.compose.ui.test.manifest)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(libs.roborazzi.junit.rule)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.core.ktx)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso.core)
    androidTestImplementation(libs.androidx.test.espresso.intents)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    debugImplementation(libs.compose.ui.test.manifest)
    androidTestImplementation(libs.kotlinx.collections.immutable)
}

val workspaceRoot: String = providers
    .gradleProperty("ragewarden.workspace.root")
    .map { rootProject.projectDir.resolve(it).canonicalPath }
    .getOrElse(rootProject.projectDir.parentFile.canonicalPath)

val jniLibsDir: File = file("src/main/jniLibs")

tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Cross-compile the ragedroid-jni Rust crate for the configured Android ABIs " +
        "and copy the resulting .so files into src/main/jniLibs/<abi>/."

    workingDir = file(workspaceRoot)

    // -P is the API level the NDK linker targets, and it is read from `minSdk` above
    // rather than hardcoded so the native floor cannot drift below the Kotlin one.
    // cargo-ndk defaults it to 21 when unset, silently -- an earlier attempt to pin it
    // from the nix devshell used CARGO_NDK_MIN_SDK_VERSION, which cargo-ndk 4.x does
    // not read (the variable it honours is CARGO_NDK_PLATFORM), so the .so was built
    // for API 21 while everything else claimed 31. Passing it on the command line
    // means the value is visible in the build log instead of in an environment.
    val ndkPlatform = android.defaultConfig.minSdk
        ?: error("minSdk must be set; cargoNdkBuild derives the NDK API level from it")

    commandLine = listOf(
        "cargo", "ndk",
        "-o", jniLibsDir.absolutePath,
        "-P", ndkPlatform.toString(),
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "build",
        "--profile", "android",
        "-p", "ragedroid-jni"
    )

    doFirst {
        val ndkHome = System.getenv("ANDROID_NDK_HOME")
            ?: System.getenv("ANDROID_NDK_ROOT")
        if (ndkHome.isNullOrBlank()) {
            logger.warn(
                "ANDROID_NDK_HOME / ANDROID_NDK_ROOT not set; cargo-ndk will fail. " +
                "Set it to the path of an installed NDK (e.g. " +
                "\$ANDROID_HOME/ndk/26.x.x)."
            )
        }
        jniLibsDir.mkdirs()
    }
}

/*
 * Fail-closed gate in front of every release packaging task.
 *
 * It runs at execution time, not configuration time, on purpose: reading the
 * environment while the build is being configured would make `assembleDebug` and
 * `testDebugUnitTest` unbuildable on a developer machine that has no keystore, and
 * the point is only to stop a *release artifact* from existing without a signature.
 */
tasks.register("requireReleaseSigning") {
    group = "verification"
    description = "Fail the build if a release APK would be packaged without real signing material."

    // Captured here rather than calling file() inside doLast: a relative RAGEDROID_KEYSTORE
    // must resolve exactly the way the signingConfig's file(storePath) resolves it, and
    // reaching for the Project object at execution time is what breaks under
    // --configuration-cache.
    val projectDirForKeystore = layout.projectDirectory.asFile

    doLast {
        val missing = releaseSigningEnv.filter { System.getenv(it).isNullOrBlank() }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "Refusing to package a release APK without signing material.\n" +
                "  missing environment variables: ${missing.joinToString(", ")}\n" +
                "Set all of: ${releaseSigningEnv.joinToString(", ")}\n" +
                "(.github/workflows/release.yml feeds these from repository secrets), or pass\n" +
                "-PunsignedBuild=true for a deliberately unsigned APK -- reproducibility checks\n" +
                "only; it will not install on a device."
            )
        }
        // File.resolve() hands back an absolute argument unchanged, so this is a no-op
        // for the usual absolute path and mirrors file() for a relative one.
        val store = projectDirForKeystore.resolve(System.getenv(keystoreEnv))
        if (!store.isFile) {
            throw GradleException(
                "$keystoreEnv points at ${store.absolutePath}, which is not a file. " +
                "A release build cannot be signed with a missing keystore."
            )
        }
    }
}

tasks.register<Delete>("cargoNdkClean") {
    group = "rust"
    description = "Delete app/src/main/jniLibs."
    delete(jniLibsDir)
}
