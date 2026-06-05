package com.dere3046.forgemint

import android.os.IBinder
import android.os.Looper
import android.os.ServiceManager
import android.system.keystore2.IKeystoreService
import android.hardware.security.keymint.SecurityLevel
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

object App {

    private const val KEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService/default"
    private const val RETRY_DELAY_MS = 1000L
    private const val MAX_RETRIES = 5

    private lateinit var modDir: String
    private var retryCount = 0
    private var injectionAttempted = false

    @JvmStatic
    fun main(args: Array<String>) {
        modDir = System.getProperty("moddir") ?: "/data/adb/modules/forgemint"
        Logger.i("ForgeMint daemon starting (moddir=$modDir)")

        prepareEnvironment()
        setupProviders()
        ConfigManager.initialize()
        BootStateManager.apply()
        cleanupDiagnosticFiles()
        initBootProperties()

        while (true) {
            try {
                val ksBinder = ServiceManager.getService(KEYSTORE_SERVICE)
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
                    Logger.i("TEE attestation cached=${DeviceAttestationService.cachedData != null}")
                    break
                }
            } catch (e: Exception) {
                Logger.e("Connection attempt failed", e)
            }
            checkRetryLimit()
            Thread.sleep(RETRY_DELAY_MS)
        }

        Logger.i("ForgeMint daemon ready")
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
        val ksService = IKeystoreService.Stub.asInterface(ksBinder)

        val backdoor = BinderInterceptor.getBackdoor(ksBinder)
        if (backdoor != null) {
            registerAll(ksService, ksBinder, backdoor)
            return true
        }

        if (!injectionAttempted) {
            Logger.i("Backdoor not found, attempting injection")
            injectionAttempted = true
            if (!performInjection()) {
                Logger.w("Injection failed, will retry")
                return false
            }
        }

        Thread.sleep(500)
        val backdoor2 = BinderInterceptor.getBackdoor(ksBinder)
        if (backdoor2 != null) {
            registerAll(ksService, ksBinder, backdoor2)
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
                .exec(arrayOf("/system/bin/pidof", "keystore2"))
                .inputStream.bufferedReader().readText().trim()
            if (pid.isEmpty()) {
                Logger.w("keystore2 not running")
                return false
            }

            val cmd = arrayOf("$modDir/lib/libinject.so", pid, "$modDir/lib/libforgemint.so")
            Logger.i("Running: $modDir/lib/libinject.so $pid $modDir/lib/libforgemint.so")

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

    private fun registerAll(ksService: IKeystoreService, ksBinder: IBinder, backdoor: IBinder) {
        val ksInterceptor = Keystore2Interceptor()
        BinderInterceptor.register(backdoor, ksBinder, ksInterceptor)
        Logger.i("Registered Keystore2Interceptor")

        val teeBinder = try {
            ksService.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT).asBinder()
        } catch (e: Exception) {
            Logger.e("Failed to get TEE SecurityLevel", e)
            error(e)
        }
        Logger.i("Got IKeystoreSecurityLevel for TEE")
        teeBinder.linkToDeath({ onServiceDeath() }, 0)

        val kmInterceptor = KeyMintInterceptor(teeBinder, SecurityLevel.TRUSTED_ENVIRONMENT)
        BinderInterceptor.register(backdoor, teeBinder, kmInterceptor)
        Logger.i("Registered KeyMintInterceptor for TEE")

        try {
            val sbBinder = ksService.getSecurityLevel(SecurityLevel.STRONGBOX).asBinder()
            val sbInterceptor = KeyMintInterceptor(sbBinder, SecurityLevel.STRONGBOX)
            BinderInterceptor.register(backdoor, sbBinder, sbInterceptor)
            Logger.i("Registered KeyMintInterceptor for StrongBox")
        } catch (_: Exception) {
            Logger.i("StrongBox not available, skipping")
        }
    }

    private fun onServiceDeath() {
        Logger.i("Keystore service died, restarting daemon")
        kotlin.system.exitProcess(0)
    }

    private fun setupProviders() {
        try {
            Security.removeProvider("BC")
        } catch (_: Exception) {}
        Security.addProvider(BouncyCastleProvider())
        Logger.i("BouncyCastle provider installed")

        try {
            Class.forName("android.security.keystore2.AndroidKeyStoreProvider")
                .getMethod("install")
                .invoke(null)
            Logger.i("AndroidKeyStoreProvider installed")
        } catch (e: Exception) {
            Logger.w("AndroidKeyStoreProvider install skipped: ${e.message}")
        }
    }

    private fun cleanupDiagnosticFiles() {
        try {
            val tmpDir = java.io.File("/data/local/tmp")
            tmpDir.listFiles()?.filter {
                it.name.startsWith("forge-") && it.extension == "bin"
            }?.forEach {
                it.delete()
                Logger.d("Cleaned up leftover: ${it.name}")
            }
        } catch (_: Exception) {}
    }
}
