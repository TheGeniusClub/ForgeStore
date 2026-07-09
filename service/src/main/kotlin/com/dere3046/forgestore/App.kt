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

import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.os.ServiceManager
import android.system.keystore2.IKeystoreService
import android.hardware.security.keymint.SecurityLevel
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

object App {

    private const val KEYSTORE2_SERVICE = "android.system.keystore2.IKeystoreService/default"
    private const val KEYSTORE1_SERVICE = "android.security.keystore"
    private const val RETRY_DELAY_MS = 1000L
    private const val MAX_RETRIES = 5

    private val isOldKeystore by lazy { Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R }
    private val keystoreServiceName by lazy { if (isOldKeystore) KEYSTORE1_SERVICE else KEYSTORE2_SERVICE }
    private val processName by lazy { if (isOldKeystore) "keystore" else "keystore2" }

    private lateinit var modDir: String
    private var retryCount = 0
    private var injectionAttempted = false

    @JvmStatic
    fun main(args: Array<String>) {
        modDir = System.getProperty("moddir") ?: "/data/adb/modules/forge_store"

        ConfigManager.initConfig()
        Logger.enabled = ConfigManager.isDebugEnabled
        Logger.verbose = ConfigManager.isVerboseLog
        Logger.i("ForgeStore daemon starting (moddir=$modDir, sdk=${Build.VERSION.SDK_INT})")
        prepareEnvironment()
        setupProviders()
        ConfigManager.initialize()
        initBootProperties()

        while (true) {
            try {
                val ksBinder = ServiceManager.getService(keystoreServiceName)
                if (ksBinder == null) {
                    Thread.sleep(RETRY_DELAY_MS)
                    continue
                }
                ksBinder.linkToDeath({ onServiceDeath() }, 0)

                if (connectInterceptor(ksBinder)) {
                    retryCount = 0
                    Logger.i("Interceptors registered, checking TEE status")
                    ConfigManager.checkTeeStatus()
                    DeviceAttestationService.cachedData
                    Logger.d("TEE attestation cached=${DeviceAttestationService.cachedData != null}")
                    break
                }
            } catch (e: Exception) {
                Logger.e("Connection attempt failed", e)
            }
            checkRetryLimit()
            Thread.sleep(RETRY_DELAY_MS)
        }

        Logger.i("ForgeStore daemon ready")
        Looper.loop()
    }

    private fun prepareEnvironment() {
        if (Looper.getMainLooper() == null) {
            @Suppress("deprecation") Looper.prepareMainLooper()
        }
        try {
            val atClass = Class.forName("android.app.ActivityThread")
            val activityThread = atClass.getMethod("systemMain").invoke(null)
            val systemContext = atClass.getMethod("getSystemContext").invoke(activityThread)
            val app = Class.forName("android.app.Application").getDeclaredConstructor().newInstance()
            val attachMethod = Class.forName("android.content.ContextWrapper")
                .getDeclaredMethod("attachBaseContext", Class.forName("android.content.Context"))
            attachMethod.isAccessible = true
            attachMethod.invoke(app, systemContext)
            val field = atClass.getDeclaredField("mInitialApplication")
            field.isAccessible = true
            field.set(activityThread, app)
            Logger.i("ActivityThread initialized")
        } catch (e: Exception) {
            Logger.w("ActivityThread setup failed", e)
        }
    }

    private fun initBootProperties() {
        try {
            AttestationBuilder.bootKey
            AttestationBuilder.bootHash
            Logger.i("Boot properties initialized")
        } catch (e: Exception) {
            Logger.w("Boot property init failed", e)
        }
    }

    private fun connectInterceptor(ksBinder: IBinder): Boolean {
        val backdoor = BinderInterceptor.getBackdoor(ksBinder)
        if (backdoor != null) {
            registerAll(ksBinder, backdoor)
            return true
        }

        if (!injectionAttempted) {
            Logger.w("Backdoor not found, attempting injection")
            injectionAttempted = true
            if (!performInjection()) {
                Logger.w("Injection failed, will retry")
                return false
            }
        }

        Thread.sleep(500)
        val backdoor2 = BinderInterceptor.getBackdoor(ksBinder)
        if (backdoor2 != null) {
            registerAll(ksBinder, backdoor2)
            return true
        }

        Logger.w("Injection succeeded but backdoor still not available")
        return false
    }

    private fun checkRetryLimit() {
        retryCount++
        if (retryCount >= MAX_RETRIES) {
            Logger.e("Failed after $MAX_RETRIES retries, exiting")
            kotlin.system.exitProcess(1)
        }
    }

    private fun performInjection(): Boolean {
        return try {
            val pid = Runtime.getRuntime()
                .exec(arrayOf("/system/bin/pidof", processName))
                .inputStream.bufferedReader().readText().trim()
            if (pid.isEmpty()) {
                Logger.w("$processName not running")
                return false
            }

            val cmd = arrayOf("$modDir/lib/libinject.so", pid, "$modDir/lib/libforgestore.so")
            Logger.d("Running: $modDir/lib/libinject.so $pid $modDir/lib/libforgestore.so")

            val process = Runtime.getRuntime().exec(cmd)
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                Logger.w("Injection exited with code $exitCode")
                return false
            }
            Logger.i("Injection succeeded")
            true
        } catch (e: Exception) {
            Logger.e("Injection failed", e)
            false
        }
    }

    private fun registerAll(ksBinder: IBinder, backdoor: IBinder) {
        if (isOldKeystore) {
            registerOld(ksBinder, backdoor)
        } else {
            registerKeystore2(ksBinder, backdoor)
        }
    }

    private fun registerOld(ksBinder: IBinder, backdoor: IBinder) {
        val interceptor = KeystoreInterceptor(ksBinder, backdoor)
        BinderInterceptor.register(backdoor, ksBinder, interceptor)
        Logger.i("Registered KeystoreInterceptor (legacy)")
    }

    private fun registerKeystore2(ksBinder: IBinder, backdoor: IBinder) {
        val ksService = IKeystoreService.Stub.asInterface(ksBinder)

        val teeBinder = try {
            ksService.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT).asBinder()
        } catch (e: Exception) {
            Logger.e("Failed to get TEE SecurityLevel", e)
            error(e)
        }
        Logger.d("Got IKeystoreSecurityLevel for TEE")
        teeBinder.linkToDeath({ onServiceDeath() }, 0)

        val teeKm = KeyMintInterceptor(teeBinder, SecurityLevel.TRUSTED_ENVIRONMENT)
        teeKm.loadPersistedKeys(ksService)

        var sbKm: KeyMintInterceptor? = null
        try {
            val sbBinder = ksService.getSecurityLevel(SecurityLevel.STRONGBOX).asBinder()
            sbKm = KeyMintInterceptor(sbBinder, SecurityLevel.STRONGBOX)
            sbKm.loadPersistedKeys(ksService)
        } catch (_: Exception) {
            Logger.w("StrongBox not available, skipping")
        }

        val ksInterceptor = Keystore2Interceptor(teeKm, sbKm)
        BinderInterceptor.register(backdoor, ksBinder, ksInterceptor)
        Logger.i("Registered Keystore2Interceptor")

        BinderInterceptor.register(backdoor, teeBinder, teeKm)
        Logger.i("Registered KeyMintInterceptor for TEE")

        if (sbKm != null) {
            try {
                val sbBinder = ksService.getSecurityLevel(SecurityLevel.STRONGBOX).asBinder()
                BinderInterceptor.register(backdoor, sbBinder, sbKm)
                Logger.i("Registered KeyMintInterceptor for StrongBox")
            } catch (_: Exception) {}
        }
    }

    private fun onServiceDeath() {
        Logger.w("Keystore service died, restarting daemon")
        kotlin.system.exitProcess(0)
    }

    private fun setupProviders() {
        try {
            Security.removeProvider("BC")
        } catch (_: Exception) {}
        Security.addProvider(BouncyCastleProvider())
        Logger.i("BouncyCastle provider installed")

        val providerClass = if (isOldKeystore)
            "android.security.keystore.AndroidKeyStoreProvider"
        else
            "android.security.keystore2.AndroidKeyStoreProvider"
        try {
            Class.forName(providerClass).getMethod("install").invoke(null)
            Logger.i("$providerClass installed")
        } catch (e: Exception) {
            Logger.w("$providerClass install skipped: ${e.message}")
        }
    }
}
