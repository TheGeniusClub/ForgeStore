/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

package com.dere3046.forgestore

import android.os.FileObserver
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap

object ConfigManager {

    enum class Mode { GENERATE, PATCH, AUTO }

    data class CustomPatchLevel(
        val system: Int?,
        val vendor: Int?,
        val boot: Int?,
        val all: Int?,
    )

    private const val CONFIG_DIR = "/data/adb/forge_store"
    private const val TARGET_FILE = "target.txt"
    private const val TEE_STATUS_FILE = "tee_status.txt"
    private const val PATCH_FILE = "security_patch.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val CONFIG_FILE = "config"

    private val configDefaults = mapOf(
        "debug" to false,
        "verbose_log" to false,
        "fallback" to false,
        "whitelist_mode" to false,
    )
    private val configMap = ConcurrentHashMap<String, Boolean>()

    private val configRoot = File(CONFIG_DIR)
    private val targetFile = File(configRoot, TARGET_FILE)
    private val teeStatusFile = File(configRoot, TEE_STATUS_FILE)
    private val patchFile = File(configRoot, PATCH_FILE)
    private val keyboxFile = File(configRoot, KEYBOX_FILE)

    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile private var isTeBroken: Boolean? = null
    @Volatile private var globalPatchLevel: CustomPatchLevel? = null
    private val uidPackageCache = ConcurrentHashMap<Int, List<String>>()

    private var observer: FileObserver? = null

    fun initConfig() {
        configRoot.mkdirs()
        loadConfig()
    }

    fun initialize() {
        configRoot.mkdirs()
        loadConfig()
        Logger.d("Config root: ${configRoot.absolutePath}")
        loadTargetPackages()
        loadSecurityPatchLevels()
        loadTeeStatus()
        startObserver()
        Logger.i("Config initialized: ${packageModes.size} packages, global patch level: ${globalPatchLevel != null}")
    }

    private fun loadConfig() {
        configDefaults.entries.forEach { configMap.put(it.key, it.value) }
        val configFile = File(configRoot, CONFIG_FILE)
        if (!configFile.exists()) return
        try {
            for (line in configFile.readLines()) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                val eqIdx = trimmed.indexOf('=')
                if (eqIdx < 0) continue
                val key = trimmed.substring(0, eqIdx).trim()
                val value = trimmed.substring(eqIdx + 1).trim()
                if (key in configDefaults) {
                    configMap[key] = value == "true"
                }
            }
        } catch (e: Exception) {
            Logger.e("Failed to load config", e)
        }
    }

    private fun getBool(key: String): Boolean = configMap[key] ?: configDefaults[key] ?: false

    val isDebugEnabled: Boolean get() = getBool("debug")
    val isVerboseLog: Boolean get() = getBool("verbose_log")
    val isFallbackEnabled: Boolean get() = getBool("fallback")
    val isWhitelistMode: Boolean get() = getBool("whitelist_mode")

    fun shouldGenerate(uid: Int): Boolean = getModeForUid(uid) == Mode.GENERATE

    fun shouldPatch(uid: Int): Boolean = getModeForUid(uid) == Mode.PATCH

    fun shouldSkip(uid: Int): Boolean {
        val hasMode = getModeForUid(uid) != null
        return if (isWhitelistMode) hasMode else !hasMode
    }

    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? = globalPatchLevel

    fun getPackagesForUid(uid: Int): List<String> {
        return uidPackageCache.getOrPut(uid) {
            try {
                val pmBinder = ServiceManager.getService("package") ?: return@getOrPut emptyList()
                val pm = android.content.pm.IPackageManager.Stub.asInterface(pmBinder)
                pm.getPackagesForUid(uid)?.toList() ?: emptyList()
            } catch (e: Exception) {
                Logger.w("Failed to get packages for UID $uid", e)
                emptyList()
            }
        }
    }

    private fun getModeForUid(uid: Int): Mode? {
        val packages = uidPackageCache[uid] ?: getPackagesForUid(uid)
        if (packages.isEmpty()) return null
        if (isTeBroken == null) loadTeeStatus()
        for (pkg in packages) {
            packageModes[pkg]?.let { mode ->
                return when (mode) {
                    Mode.AUTO -> if (isTeBroken == true) Mode.GENERATE else Mode.PATCH
                    else -> mode
                }
            }
        }
        return null
    }

    private fun loadTargetPackages() {
        if (!targetFile.exists()) {
            Logger.w("target.txt not found: ${targetFile.absolutePath}")
            return
        }
        try {
            val newModes = mutableMapOf<String, Mode>()
            targetFile.readLines().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                when {
                    trimmed.endsWith("!") -> {
                        val pkg = trimmed.removeSuffix("!").trim()
                        if (pkg.isNotEmpty()) newModes[pkg] = Mode.GENERATE
                    }
                    trimmed.endsWith("?") -> {
                        val pkg = trimmed.removeSuffix("?").trim()
                        if (pkg.isNotEmpty()) newModes[pkg] = Mode.PATCH
                    }
                    else -> {
                        if (trimmed.isNotEmpty()) newModes[trimmed] = Mode.AUTO
                    }
                }
            }
            packageModes = newModes
            uidPackageCache.clear()
            Logger.d("Loaded ${newModes.size} package modes")
        } catch (e: Exception) {
            Logger.e("Failed to load target.txt", e)
        }
    }

    private fun loadSecurityPatchLevels() {
        if (!patchFile.exists()) return
        try {
            var sys: Int? = null
            var ven: Int? = null
            var boo: Int? = null
            var all: Int? = null
            var sysProp = false
            var venProp = false
            var bootProp = false

            for (line in patchFile.readLines()) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                val eqIdx = trimmed.indexOf('=')
                if (eqIdx < 0) continue
                val key = trimmed.substring(0, eqIdx).trim().lowercase()
                val value = trimmed.substring(eqIdx + 1).trim()
                val isProp = value == "prop"
                val parsed = parsePatchValue(value)
                when (key) {
                    "system" -> { sys = parsed; sysProp = isProp }
                    "vendor" -> { ven = parsed; venProp = isProp }
                    "boot" -> { boo = parsed; bootProp = isProp }
                    "all" -> { all = parsed; sysProp = isProp; venProp = isProp; bootProp = isProp }
                }
            }

            if (sysProp && !venProp) ven = null
            if (sysProp && !bootProp) boo = null

            if (sys != null || ven != null || boo != null || all != null || sysProp || venProp || bootProp) {
                globalPatchLevel = CustomPatchLevel(sys, ven, boo, all)
                Logger.i("Loaded global patch level: system=${sys} vendor=${ven} boot=${boo} all=${all}")
            }
        } catch (e: Exception) {
            Logger.e("Failed to load $PATCH_FILE", e)
        }
    }

    private fun parsePatchValue(value: String): Int? {
        if (value == "prop") return null
        val digits = value.replace("-", "")
        return when (digits.length) {
            8 -> digits.take(8).toIntOrNull()
            6 -> "${digits.take(6)}01".toIntOrNull()
            else -> null
        }
    }

    fun checkTeeStatus() {
        isTeBroken = try {
            val result = TeeChecker.isTeeFunctional()
            teeStatusFile.writeText("tee_broken=${!result}")
            Logger.i("TEE status: ${if (result) "functional" else "broken"}")
            !result
        } catch (e: Exception) {
            Logger.e("TEE check failed", e)
            true
        }
    }

    private fun loadTeeStatus() {
        isTeBroken = if (teeStatusFile.exists()) {
            teeStatusFile.readText().trim() == "tee_broken=true"
        } else null
    }

    private fun startObserver() {
        observer?.stopWatching()
        observer = object : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == TARGET_FILE) {
                    Logger.i("target.txt changed, reloading")
                    loadTargetPackages()
                }
                if (path == TEE_STATUS_FILE) {
                    loadTeeStatus()
                }
                if (path == PATCH_FILE) {
                    Logger.i("security_patch.txt changed, reloading")
                    loadSecurityPatchLevels()
                }
                if (path == KEYBOX_FILE) {
                    Logger.i("keybox.xml changed, clearing caches")
                    KeyboxReader.clearCache()
                }
                if (path == CONFIG_FILE) {
                    Logger.i("config changed, reloading")
                    loadConfig()
                }
            }
        }.apply { startWatching() }
    }
}
