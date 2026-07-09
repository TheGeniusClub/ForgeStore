import java.security.Signature
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec

import io.github.rctcwyvrn.blake3.Blake3

buildscript {
    dependencies {
        classpath("io.github.rctcwyvrn:blake3:1.3")
    }
}

plugins {
    id("base")
}

val moduleId:   String by rootProject.extra
val moduleName: String by rootProject.extra
val verName:    String by rootProject.extra
val verType:    String by rootProject.extra
val verCode:       Int by rootProject.extra
val verHash:    String by rootProject.extra

listOf(
    "debug",
    "release"
).forEach { variantName ->
    val variantCapped = variantName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    val variantLowered = variantName.lowercase()
    val moduleDir = layout.buildDirectory.dir("outputs/module/${variantLowered}")
    val moduleDirAsFile = moduleDir.get().asFile
    val zipFileName = "${moduleName}-${verName}-${verCode}-${verHash}-${variantName}.zip".replace(' ', '-')

    val prepareModuleFilesTask = tasks.register<Copy>("prepareModuleFiles${variantCapped}") {
        group = "module"
        description = "Prepares module files for ${variantName}."

        dependsOn(
            ":service:assemble${variantCapped}",
            ":library:strip${variantCapped}DebugSymbols"
        )

        doFirst {
            with(moduleDirAsFile) {
                deleteRecursively()
            }
        }

        into(moduleDir)
            from(project(":service").layout.buildDirectory.file("outputs/apk/${variantLowered}")) {
                include(
                    "service-${variantLowered}.apk"
                )
                rename(
                    "service-${variantLowered}.apk",
                    "service.apk"
                )
            }
            from("${projectDir}/src") {
                include(
                    "module.prop"
                )
                expand(
                    "moduleId" to "${moduleId}",
                    "moduleName" to "${moduleName}",
                    "versionName" to "${verName}${verType} (${verCode}-${verHash}-${variantLowered})",
                    "versionCode" to "${verCode}"
                )
            }
            from("${projectDir}/src") {
                exclude(
                    ".DS_Store",
                    "module.prop"
                )
            }
        into("lib") {
            from(project(":library").layout.buildDirectory.dir("intermediates/stripped_native_libs/${variantLowered}/strip${variantCapped}DebugSymbols/out/lib")) {
                include(
                    "**/libforgestore.so",
                    "**/libinject.so"
                )
            }
        }

        doLast {
            val libDir = File(moduleDirAsFile, "lib")
            mapOf(
                "x86_64"      to "x64",
                "armeabi-v7a" to "arm",
                "arm64-v8a"   to "arm64"
            ).forEach { (oldName, newName) ->
                File(libDir, oldName).renameTo(File(libDir, newName))
            }
        }
    }

    val signModuleFilesTask = tasks.register("signModule${variantCapped}") {
        group = "module"
        description = "Sign module files for ${variantName}."
    
        dependsOn(prepareModuleFilesTask)

        doLast {
            fun sha256Sum() {
                fileTree(moduleDir) {
                    exclude("MANIFEST")
                }.visit {
                    if (isDirectory) return@visit

                    val messageDigest = MessageDigest.getInstance("SHA3-256")
                    file.forEachBlock(4096) { bytes, size ->
                        messageDigest.update(bytes, 0, size)
                    }

                    val sha256File = File(moduleDirAsFile, "MANIFEST/${file.relativeTo(moduleDirAsFile)}.sha256")
                    sha256File.parentFile.mkdirs()
                    sha256File.writeText(messageDigest.digest().joinToString("") { "%02x".format(it) })
                }
            }
            val privateKeyFile = project.file("private_key")
            val archs = File(moduleDirAsFile, "lib").listFiles { file -> file.isDirectory }.map { it.name }
            if (privateKeyFile.exists()) {
                val publicKey = project.file("public_key").readBytes()
                val signType = Signature.getInstance("ed25519")
                val privateKey = privateKeyFile.readBytes()
                fun mistylakeSign(arch: String) {
                    val mistyFile = File(moduleDirAsFile, "mistylake.${arch}")
                    val set = LinkedHashSet<File>().apply {
                        listOf(
                            "lib/${arch}/libforgestore.so",
                            "lib/${arch}/libinject.so",
                            "daemon",
                            "module.prop",
                            "sepolicy.rule",
                            "service.apk",
                            "service.sh",
                        ).forEach { fileName ->
                            add(File(moduleDirAsFile, fileName))
                        }
                    }

                    println("=== Arch: ${arch} ===")
                    set.forEach {
                        println(it.absolutePath.replace("${moduleDirAsFile.absolutePath}/", ""))
                    }

                    val BLAKE3Builder = StringBuilder()
                    set.forEach { file ->
                        val hasher = Blake3.newInstance()
                        val buffer = ByteArray(4096)
                        file.inputStream().use { input ->
                            var bytesRead: Int
                            while (input.read(buffer).also { bytesRead = it } != -1) {
                                if (bytesRead == buffer.size) {
                                    hasher.update(buffer)
                                } else {
                                    hasher.update(buffer.copyOf(bytesRead))
                                }
                            }
                        }
                        val fileHash = hasher.digest()
                        BLAKE3Builder.append(fileHash.joinToString("") { "%02x".format(it) })
                    }
                    val BLAKE3Hash = BLAKE3Builder.toString()

                    println(BLAKE3Hash)

                    signType.initSign(KeyFactory.getInstance("ed25519").generatePrivate(EdECPrivateKeySpec(NamedParameterSpec("ed25519"), privateKey)))
                    signType.update(BLAKE3Hash.toByteArray())

                    val signature = signType.sign()

                    mistyFile.writeBytes(signature.copyOfRange(0, 16))
                    mistyFile.appendBytes(publicKey.copyOfRange(0, 16))
                    mistyFile.appendBytes(signature.copyOfRange(16, 48))
                    mistyFile.appendBytes(publicKey.copyOfRange(16, 32))
                    mistyFile.appendBytes(signature.copyOfRange(48, 64))
                }

                archs.forEach { arch ->
                    mistylakeSign(arch)
                }

                sha256Sum()

                println("=== Guards the peace of Misty Lake ===")
            } else {
                println("no private_key found, this build will not be signed")

                archs.forEach { arch ->
                    File(moduleDirAsFile, "mistylake.${arch}").createNewFile()
                }

                sha256Sum()
            }
        }
    }

    val zipTask = tasks.register<Zip>("zip${variantCapped}") {
        group = "module"
        description = "Create module zip for ${variantCapped}."

        dependsOn(signModuleFilesTask)

        archiveFileName.set(zipFileName)
        destinationDirectory.set(layout.buildDirectory.file("outputs/${variantLowered}").get().asFile)
        from(moduleDir)
    }

    val pushTask = tasks.register<Exec>("push${variantCapped}") {
        group = "module"
        description = "Push module to device."

        dependsOn(zipTask)

        commandLine("adb", "push", zipTask.get().archiveFile.get().asFile, "/data/local/tmp")
    }

    tasks.register<Exec>("Magisk${variantCapped}") {
        group = "module"
        description = "Installs module via Magisk."

        dependsOn(pushTask)

        commandLine("adb", "shell", "su", "-c", "magisk --install-module /data/local/tmp/${zipFileName}")
    }

    tasks.register<Exec>("KernelSU${variantCapped}") {
        group = "module"
        description = "Installs module via KernelSU."

        dependsOn(pushTask)

        commandLine("adb", "shell", "su", "-c", "ksud module install /data/local/tmp/${zipFileName}")
    }
}

tasks.register("zip") {
    group = "module"
    description = "Create module zip for Github Release."

    dependsOn(
        "zipDebug",
        "zipRelease"
    )
}