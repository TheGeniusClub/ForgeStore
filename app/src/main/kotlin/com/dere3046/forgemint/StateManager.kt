package com.dere3046.forgemint

import android.os.IBinder
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyMetadata
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

object StateManager {

    data class KeyIdentifier(val uid: Int, val alias: String)

    data class KeyEntry(
        val uid: Int,
        val alias: String,
        val nspace: Long,
        val metadata: KeyMetadata,
        val keyPair: KeyPair,
        val securityLevel: Int,
        val securityLevelBinder: IKeystoreSecurityLevel,
        val certChain: List<X509Certificate>,
    )

    private val cache = ConcurrentHashMap<String, KeyEntry>()
    private val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()

    fun store(entry: KeyEntry) {
        cache[key(entry.uid, entry.alias)] = entry
    }

    fun lookup(uid: Int, alias: String): KeyEntry? = cache[key(uid, alias)]

    fun lookupByNspace(uid: Int, nspace: Long): KeyEntry? {
        return cache.values.find { it.uid == uid && it.nspace == nspace }
    }

    fun remove(uid: Int, alias: String) {
        cache.remove(key(uid, alias))
        patchedChains.remove(KeyIdentifier(uid, alias))
    }

    fun listForUid(uid: Int): List<KeyEntry> {
        return cache.values.filter { it.uid == uid }
    }

    fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

    fun cachePatchedChain(keyId: KeyIdentifier, chain: Array<Certificate>) {
        patchedChains[keyId] = chain
    }

    fun clearAll() {
        val count = cache.size
        cache.clear()
        patchedChains.clear()
        Logger.i("Cleared all state ($count entries)")
    }

    private fun key(uid: Int, alias: String) = "$uid:$alias"
}
