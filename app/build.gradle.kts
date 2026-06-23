import com.android.build.api.artifact.SingleArtifact
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

abstract class GitExecutor @Inject constructor(private val execOperations: ExecOperations) {
    fun execute(command: String, currentWorkingDir: File): String {
        val byteOut = ByteArrayOutputStream()
        execOperations.exec {
            workingDir = currentWorkingDir
            commandLine = command.split("\\s".toRegex())
            standardOutput = byteOut
        }
        return String(byteOut.toByteArray()).trim()
    }
}

val gitExecutor = objects.newInstance(GitExecutor::class.java)
val gitCommitCount = gitExecutor.execute("git rev-list HEAD --count", rootDir).toIntOrNull() ?: 0
val gitCommitHash = gitExecutor.execute("git rev-parse --verify --short HEAD", rootDir).ifEmpty { "local" }
val verName = "v0.1"
val appId = "com.dere3046.forgemint"

android {
    namespace = appId
    compileSdk = 36
    ndkVersion = "25.1.8937393"

    defaultConfig {
        applicationId = appId
        minSdk = 29
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = verName
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { buildConfig = true }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/versions/**",
            )
        }
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDirs("src/main/kotlin")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.bcpkix)
    implementation(libs.bcprov)
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalized = variant.name.replaceFirstChar { it.uppercase() }

        val tempModuleDir = project.layout.buildDirectory.dir("module/${variant.name}")
        val zipFileName = "forgemint-$verName-$gitCommitCount-$gitCommitHash-$capitalized.zip"

        val prepareModuleFilesTask =
            tasks.register<Sync>("prepareModuleFiles${capitalized}") {
                group = "ForgeMint Module Packaging"
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
                    include("**/libforgemint.so", "**/libinject.so")
                }

                val sourceModuleDir = rootProject.projectDir.resolve("module")
                from(sourceModuleDir) {
                    exclude("module.prop")
                }
                from(sourceModuleDir) {
                    include("module.prop")
                    expand(
                        "REPLACEMEVERCODE" to gitCommitCount.toString(),
                        "REPLACEMEVER" to "$verName ($gitCommitCount-$gitCommitHash-${variant.name})",
                    )
                }

                into(tempModuleDir)
            }

        val generateSha256Task =
            tasks.register("generateSha256${capitalized}") {
                group = "ForgeMint Module Packaging"
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

        val zipTask =
            tasks.register<Zip>("zip${capitalized}") {
                group = "ForgeMint Module Packaging"
                description = "Creates flashable zip for ${variant.name}."
                dependsOn(generateSha256Task)

                archiveFileName.set(zipFileName)
                destinationDirectory.set(rootProject.projectDir.resolve("out"))
                from(tempModuleDir)
            }

        tasks.register<Exec>("push${capitalized}") {
            group = "ForgeMint Module Installation"
            description = "Pushes module to device."
            dependsOn(zipTask)
            commandLine("adb", "push", zipTask.get().archiveFile.get().asFile, "/data/local/tmp")
        }

        tasks.register<Exec>("installMagisk${capitalized}") {
            group = "ForgeMint Module Installation"
            description = "Installs module via Magisk."
            dependsOn(zipTask)
            commandLine("adb", "shell", "su", "-c", "magisk --install-module /data/local/tmp/$zipFileName")
        }
    }
}
