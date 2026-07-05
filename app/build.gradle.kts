import com.android.build.api.artifact.SingleArtifact
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

dependencies {
    compileOnly("androidx.annotation:annotation:1.9.1")
    compileOnly(project(":stub"))
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
}

val verName: String by rootProject.extra
val verType: String by rootProject.extra
val verCode: Int by rootProject.extra
val verHash: String by rootProject.extra

android {
    namespace = "com.dere3046.forgestore"
    buildToolsVersion = "36.0.0"
    ndkVersion = "25.1.8937393"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
        targetSdk = 36
        versionCode = verCode
        versionName = verName
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }

    buildTypes {
        debug {
            versionNameSuffix = "-d"
        }
        release {
            isMinifyEnabled = true
            vcsInfo.include = false
            proguardFiles("proguard-rules.pro")
        }
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/**"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }

    dependenciesInfo {
        includeInApk = false
    }

    tasks.withType<JavaCompile> {
        options.compilerArgs.add("-Xlint:deprecation")
        options.compilerArgs.add("-Xlint:unchecked")
        options.compilerArgs.add("-Xdiags:verbose")
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalized = variant.name.replaceFirstChar { it.uppercase() }

        val tempModuleDir = project.layout.buildDirectory.dir("module/${variant.name}")
        val zipFileName = "forgestore-$verName-$verCode-$verHash-$capitalized.zip"

        val prepareModuleFilesTask = tasks.register<Sync>("prepareModuleFiles${capitalized}") {
            group = "ForgeStore Module Packaging"
            description = "Prepares module files for ${variant.name}."

            dependsOn("package${capitalized}")
            dependsOn("strip${capitalized}DebugSymbols")

            from(variant.artifacts.get(SingleArtifact.APK)) {
                include("*.apk")
                rename { "service.apk" }
            }

            from(
                project.layout.buildDirectory.dir(
                    "intermediates/stripped_native_libs/${variant.name}/strip${capitalized}DebugSymbols/out/lib"
                )
            ) {
                into("lib")
                include("**/libforgestore.so", "**/libinject.so")
            }

            val sourceModuleDir = rootProject.projectDir.resolve("module")
            from(sourceModuleDir) {
                exclude("module.prop")
            }
            from(sourceModuleDir) {
                include("module.prop")
                expand(
                    "REPLACEMEVERCODE" to verCode.toString(),
                    "REPLACEMEVER" to "$verName ($verCode-$verHash-${variant.name})",
                )
            }

            into(tempModuleDir)
        }

        val generateSha256Task = tasks.register("generateSha256${capitalized}") {
            group = "ForgeStore Module Packaging"
            description = "Generates .sha256 sidecar files for all module files."
            dependsOn(prepareModuleFilesTask)
            doLast {
                val dir = tempModuleDir.get().asFile
                val proc = ProcessBuilder("sh", "-c",
                    "find . -type f ! -name '*.sha256' | while read f; do sha256sum \"\$f\" | cut -d' ' -f1 > \"\${f}.sha256\"; done"
                ).directory(dir).inheritIO().start()
                proc.waitFor()
                if (proc.exitValue() != 0) throw RuntimeException("sha256 generation failed")
            }
        }

        val zipTask = tasks.register<Zip>("zip${capitalized}") {
            group = "ForgeStore Module Packaging"
            description = "Creates flashable zip for ${variant.name}."
            dependsOn(generateSha256Task)

            archiveFileName.set(zipFileName)
            destinationDirectory.set(rootProject.projectDir.resolve("out"))
            from(tempModuleDir)
        }

        val pushTask = tasks.register<Exec>("push${capitalized}") {
            group = "ForgeStore Module Installation"
            description = "Pushes module to device."
            dependsOn(zipTask)
            commandLine("adb", "push", zipTask.get().archiveFile.get().asFile, "/data/local/tmp")
        }

        tasks.register<Exec>("installMagisk${capitalized}") {
            group = "ForgeStore Module Installation"
            description = "Installs module via Magisk."
            dependsOn(pushTask)
            commandLine("adb", "shell", "su", "-c", "magisk --install-module /data/local/tmp/$zipFileName")
        }

        tasks.register<Exec>("installKernelSU${capitalized}") {
            group = "ForgeStore Module Installation"
            description = "Installs module via KernelSU."
            dependsOn(pushTask)
            commandLine("adb", "shell", "su", "-c", "ksud module install /data/local/tmp/$zipFileName")
        }
    }
}