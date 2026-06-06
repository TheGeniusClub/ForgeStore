/*
 * Copyright (C) 2026  TheGeniusClub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <https://www.gnu.org/licenses/>.
 */

package com.dere3046.forgemint

import android.os.IBinder
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.security.KeyPair
import java.security.SecureRandom
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
        val keyPair: KeyPair? = null,
        val secretKey: javax.crypto.SecretKey? = null,
        val securityLevel: Int,
        val securityLevelBinder: IKeystoreSecurityLevel?,
        val certChain: List<X509Certificate>,
    )

    private val cache = ConcurrentHashMap<String, KeyEntry>()
    private val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
    private val metadataCache = ConcurrentHashMap<String, KeyMetadata>()
    private val nspaceToAlias = ConcurrentHashMap<String, String>()
    private val teeResponses = ConcurrentHashMap<KeyIdentifier, KeyEntryResponse>()
    private val activeOps = ConcurrentHashMap<Int, java.util.concurrent.ConcurrentLinkedDeque<SoftwareOperation>>()

    private const val MAX_OPS_PER_UID = 15

    data class SoftwareGrant(
        val granteeUid: Int,
        val accessVector: Int,
        val ownerKeyId: KeyIdentifier,
    )

    private val grantMap = ConcurrentHashMap<Long, SoftwareGrant>()

    fun issueGrant(ownerKeyId: KeyIdentifier, granteeUid: Int, accessVector: Int): Long {
        var nspace: Long
        do { nspace = java.security.SecureRandom().nextLong() } while (nspace == 0L || grantMap.containsKey(nspace))
        grantMap[nspace] = SoftwareGrant(granteeUid, accessVector, ownerKeyId)
        Logger.d("Grant issued owner=${ownerKeyId} grantee=$granteeUid nspace=$nspace")
        return nspace
    }

    fun resolveGrant(nspace: Long, callerUid: Int): KeyIdentifier? {
        val grant = grantMap[nspace] ?: return null
        if (grant.granteeUid != callerUid) return null
        if (cache.values.none { it.uid == grant.ownerKeyId.uid && it.alias == grant.ownerKeyId.alias }) return null
        return grant.ownerKeyId
    }

    fun isGrantNspaceKnown(nspace: Long): Boolean = grantMap.containsKey(nspace)

    fun getGrantAccessVector(nspace: Long): Int? = grantMap[nspace]?.accessVector

    fun revokeGrantForOwner(ownerKeyId: KeyIdentifier, granteeUid: Int) {
        val toRemove = grantMap.entries.filter {
            it.value.ownerKeyId == ownerKeyId && it.value.granteeUid == granteeUid
        }.map { it.key }
        toRemove.forEach { grantMap.remove(it) }
    }

    fun acquireOp(uid: Int, operation: SoftwareOperation) {
        val ops = activeOps.computeIfAbsent(uid) { java.util.concurrent.ConcurrentLinkedDeque() }
        ops.removeIf { it.finalized }
        while (ops.size >= MAX_OPS_PER_UID) {
            val oldest = ops.pollFirst() ?: break
            if (!oldest.finalized) {
                Logger.w("LRU: aborting oldest unfinished op for uid=$uid")
                oldest.abort()
            }
        }
        ops.addLast(operation)
    }

    fun releaseOp(uid: Int) {
        activeOps[uid]?.removeIf { it.finalized }
        activeOps[uid]?.takeIf { it.isEmpty() }?.let { activeOps.remove(uid) }
    }

    fun store(entry: KeyEntry) {
        cache[key(entry.uid, entry.alias)] = entry
        GeneratedKeyPersistence.store(entry)
    }

    fun lookup(uid: Int, alias: String): KeyEntry? = cache[key(uid, alias)]

    fun lookupByNspace(uid: Int, nspace: Long): KeyEntry? {
        return cache.values.find { it.uid == uid && it.nspace == nspace }
    }

    fun cacheMetadataSnapshot(keyId: KeyIdentifier, metadata: KeyMetadata) {
        val nspace = metadata.key?.nspace ?: return
        metadataCache[key(keyId.uid, keyId.alias)] = metadata
        nspaceToAlias[key(uid = keyId.uid, alias = nspace.toString())] = keyId.alias
        Logger.d("Cached metadata snapshot for ${keyId.alias} nspace=$nspace")
    }

    fun lookupMetadataByNspace(uid: Int, nspace: Long): KeyMetadata? {
        val entryKey = nspaceToAlias[key(uid, nspace.toString())]
            ?: return metadataCache.values.find {
                it.key?.nspace == nspace && it.key?.domain == android.system.keystore2.Domain.KEY_ID
            }
        return metadataCache[key(uid, entryKey)]
    }

    fun cacheTeeResponse(keyId: KeyIdentifier, metadata: KeyMetadata, levelBinder: IKeystoreSecurityLevel) {
        teeResponses[keyId] = KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = levelBinder
        }
        Logger.d("Cached teeResponse for ${keyId.alias}")
    }

    fun lookupTeeResponse(uid: Int, nspace: Long): KeyEntryResponse? {
        return teeResponses.entries.find {
            it.key.uid == uid && it.value.metadata?.key?.nspace == nspace
        }?.value
    }

    fun lookupByAliasOrDomain(uid: Int, descriptor: android.system.keystore2.KeyDescriptor): KeyEntry? {
        return when (descriptor.domain) {
            android.system.keystore2.Domain.KEY_ID -> lookupByNspace(uid, descriptor.nspace)
            android.system.keystore2.Domain.APP -> descriptor.alias?.let { lookup(uid, it) }
            else -> null
        }
    }

    fun remove(uid: Int, alias: String) {
        cache.remove(key(uid, alias))
        metadataCache.remove(key(uid, alias))
        teeResponses.remove(KeyIdentifier(uid, alias))
        patchedChains.remove(KeyIdentifier(uid, alias))
        purgeGrants(KeyIdentifier(uid, alias))
        GeneratedKeyPersistence.remove(uid, alias)
    }

    private fun purgeGrants(keyId: KeyIdentifier) {
        val toRemove = grantMap.entries.filter {
            it.value.ownerKeyId == keyId
        }.map { it.key }
        toRemove.forEach { grantMap.remove(it) }
    }

    private var keysLoaded = false

    fun loadPersistedKeys(ksService: android.system.keystore2.IKeystoreService) {
        if (keysLoaded) return
        keysLoaded = true
        var count = 0
        for (lk in GeneratedKeyPersistence.loadAll()) {
            if (lk.metadata == null) continue
            val binder = try {
                ksService.getSecurityLevel(lk.securityLevel)
            } catch (_: Exception) { null }
            store(KeyEntry(
                uid = lk.uid,
                alias = lk.alias,
                nspace = lk.nspace,
                metadata = lk.metadata,
                keyPair = lk.keyPair,
                secretKey = lk.secretKey,
                securityLevel = lk.securityLevel,
                securityLevelBinder = binder,
                certChain = lk.certChain,
            ))
            count++
        }
        if (count > 0) Logger.d("Loaded $count persisted keys")
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
        metadataCache.clear()
        nspaceToAlias.clear()
        teeResponses.clear()
        grantMap.clear()
        activeOps.clear()
        Logger.d("Cleared all state ($count entries)")
    }

    private fun key(uid: Int, alias: String) = "$uid:$alias"
}
