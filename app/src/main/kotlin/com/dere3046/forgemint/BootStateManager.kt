package com.dere3046.forgemint

object BootStateManager {

    private val targets = linkedMapOf(
        "ro.boot.verifiedbootstate" to "green",
        "ro.boot.flash.locked" to "1",
        "ro.boot.veritymode" to "enforcing",
        "ro.boot.vbmeta.device_state" to "locked",
    )

    private val fillIfAbsent = linkedMapOf(
        "ro.boot.vbmeta.invalidate_on_error" to "yes",
        "ro.boot.vbmeta.avb_version" to "1.2",
        "ro.boot.vbmeta.hash_alg" to "sha256",
        "ro.boot.vbmeta.size" to "11904",
    )

    fun apply() {
        Logger.i("BootStateManager: applying boot state spoofing")
        for ((name, target) in targets) {
            val current = readProp(name)
            if (current.isEmpty()) {
                Logger.d("BootStateManager: $name absent, skip")
                continue
            }
            if (current == target) {
                Logger.d("BootStateManager: $name already $target, skip")
                continue
            }
            Logger.i("BootStateManager: setting $name=$target (was: '$current')")
            setProperty(name, target)
        }
        for ((name, value) in fillIfAbsent) {
            val current = readProp(name)
            if (current.isNotEmpty()) {
                Logger.d("BootStateManager: $name already '$current', skip")
                continue
            }
            Logger.i("BootStateManager: filling absent $name=$value")
            setProperty(name, value)
        }
    }

    private fun readProp(name: String): String {
        return try {
            val cls = Class.forName("android.os.SystemProperties")
            cls.getMethod("get", String::class.java, String::class.java)
                .invoke(null, name, "") as String
        } catch (_: Exception) { "" }
    }

    private fun setProperty(name: String, value: String) {
        try {
            Runtime.getRuntime().exec(arrayOf("resetprop", name, value)).waitFor()
        } catch (e: Exception) {
            Logger.w("BootStateManager: resetprop $name failed", e)
        }
    }
}
