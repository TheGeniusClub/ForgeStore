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

import android.os.IBinder
import android.os.Parcel
import android.os.Build
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.security.cert.Certificate

class Keystore2Interceptor(
    private val teeInterceptor: KeyMintInterceptor,
    private val strongBoxInterceptor: KeyMintInterceptor?,
) : BinderInterceptor() {

    private val batchParams = java.util.concurrent.ConcurrentHashMap<Long, String?>()
    private val deletedSoftwareKeys = java.util.Collections.synchronizedSet(
        mutableSetOf<StateManager.KeyIdentifier>()
    )

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_KEY_ENTRY_TRANSACTION) {
            val grantResult = tryHandleGrantGetKeyEntry(data, callingUid)
            if (grantResult != null) return grantResult
        }

        if (shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }
        if (code == GET_KEY_ENTRY_TRANSACTION) {
            return handleGetKeyEntry(data, callingUid)
        }
        if (code == DELETE_KEY_TRANSACTION) {
            return handleDeleteKey(data, callingUid)
        }
        if (code == UPDATE_SUBCOMPONENT_TRANSACTION) {
            return handleUpdateSubcomponent(data, callingUid)
        }
        if (code == GRANT_TRANSACTION) {
            return handleGrant(data, callingUid)
        }
        if (code == UNGRANT_TRANSACTION) {
            return handleUngrant(data, callingUid)
        }
        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            if (isGms(callingUid)) return TransactionResult.ContinueAndSkipPost
            if (code == LIST_ENTRIES_BATCHED_TRANSACTION) {
                parseBatchParams(txId, data)
            }
        }
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            return TransactionResult.Continue
        }
        return TransactionResult.Continue
    }

    private fun handleUpdateSubcomponent(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val entry = findEntryByNspace(uid, descriptor.nspace)
                ?: run {
                    val nspace = descriptor.nspace
                    teeInterceptor.teeResponses.entries.find { it.key.uid == uid && it.value.metadata?.key?.nspace == nspace }?.let {
                        teeInterceptor.teeResponses.remove(it.key)
                        teeInterceptor.patchedChains.remove(it.key)
                    }
                    strongBoxInterceptor?.teeResponses?.entries?.find { it.key.uid == uid && it.value.metadata?.key?.nspace == nspace }?.let {
                        strongBoxInterceptor.teeResponses.remove(it.key)
                        strongBoxInterceptor.patchedChains.remove(it.key)
                    }
                    return TransactionResult.ContinueAndSkipPost
                }

            val publicCert = data.createByteArray()
            val certificateChain = data.createByteArray()

            entry.metadata.certificate = publicCert
            entry.metadata.certificateChain = certificateChain
            Logger.d("updateSubcomponent nspace=${entry.nspace} cert=${publicCert?.size} chain=${certificateChain?.size}")

            val reply = Parcel.obtain()
            reply.writeNoException()

            GeneratedKeyPersistence.rePersist(entry)

            return TransactionResult.OverrideReply(reply)
        } catch (_: Exception) {}
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (resultCode != 0 || reply == null) return TransactionResult.Skip
        if (shouldSkip(callingUid)) return TransactionResult.Skip

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            return injectGeneratedKeys(callingUid, reply, txId)
        }

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            return injectEntryCount(reply, callingUid)
        }

        if (code == GET_KEY_ENTRY_TRANSACTION) {
            return handlePostGetKeyEntry(callingUid, data, reply)
        }

        return TransactionResult.Skip
    }

    private fun handleGetKeyEntry(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue

            if (descriptor.domain == Domain.GRANT) {
                return handleGrantDomainGetKeyEntry(descriptor, uid)
            }

            if (descriptor.domain == Domain.KEY_ID) {
                val metadataResult = handleGetKeyEntryByMetadata(descriptor, uid)
                if (metadataResult != null) return metadataResult
                val teeResp = findTeeResponse(uid, descriptor.nspace)
                if (teeResp != null) {
                    val reply = Parcel.obtain()
                    reply.writeNoException()
                    reply.writeTypedObject(teeResp, 0)
                    return TransactionResult.OverrideReply(reply)
                }
            }

            val entry = descriptor.alias?.let { findEntry(uid, it) }
                ?: if (descriptor.domain == Domain.KEY_ID)
                    findEntryByNspace(uid, descriptor.nspace)
                else null

            if (entry == null) return TransactionResult.Continue
            return buildGetKeyEntryResponse(entry)
        } catch (e: Exception) {
            Logger.e("getKeyEntry failed", e)
            return TransactionResult.Continue
        }
    }

    private fun tryHandleGrantGetKeyEntry(data: Parcel, uid: Int): TransactionResult? {
        val savedPos = data.dataPosition()
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            if (descriptor != null && descriptor.domain == Domain.GRANT) {
                handleGrantDomainGetKeyEntry(descriptor, uid)
            } else null
        } catch (_: Exception) { null }
        finally { data.setDataPosition(savedPos) }
    }

    private fun handleGrantDomainGetKeyEntry(descriptor: KeyDescriptor, uid: Int): TransactionResult {
        val grantResult = StateManager.resolveGrant(descriptor.nspace, uid)
        if (grantResult == null) {
            if (StateManager.isGrantNspaceKnown(descriptor.nspace)) {
                return replyKeystoreError(7)
            }
            return TransactionResult.ContinueAndSkipPost
        }

        val entry = findEntry(grantResult.uid, grantResult.alias)
        if (entry != null) {
            val accessVector = StateManager.getGrantAccessVector(descriptor.nspace) ?: 0
            if ((accessVector and 0x4) == 0) {
                return replyKeystoreError(6)
            }
            return buildGetKeyEntryResponse(entry)
        }

        val teeResp = findTeeResponse(grantResult.uid, descriptor.nspace)
        if (teeResp != null) {
            val accessVector = StateManager.getGrantAccessVector(descriptor.nspace) ?: 0
            if ((accessVector and 0x4) == 0) {
                return replyKeystoreError(6)
            }
            val reply = Parcel.obtain()
            reply.writeNoException()
            reply.writeTypedObject(teeResp, 0)
            return TransactionResult.OverrideReply(reply)
        }

        return replyKeystoreError(7)
    }

    private fun handleGetKeyEntryByMetadata(descriptor: KeyDescriptor, uid: Int): TransactionResult? {
        val metadata = findMetadataByNspace(uid, descriptor.nspace) ?: return null
        val response = KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = null
        }
        val reply = Parcel.obtain()
        reply.writeNoException()
        reply.writeTypedObject(response, 0)
        return TransactionResult.OverrideReply(reply)
    }

    private fun handleGrant(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val granteeUid = data.readInt()
            val accessVector = data.readInt()

            val entry = keyDescriptor.alias?.let { findEntry(uid, it) }
                ?: if (keyDescriptor.domain == Domain.KEY_ID)
                    findEntryByNspace(uid, keyDescriptor.nspace)
                else null

            if (entry == null) {
                if (keyDescriptor.alias != null) {
                    val kid = StateManager.KeyIdentifier(uid, keyDescriptor.alias)
                    if (teeInterceptor.teeResponses.containsKey(kid) ||
                        (strongBoxInterceptor?.teeResponses?.containsKey(kid) == true)) {
                        if (Build.VERSION.SDK_INT < 36) return replyKeystoreError(6)
                        val gnsp = StateManager.issueGrant(kid, granteeUid, accessVector)
                        val reply = Parcel.obtain()
                        reply.writeNoException()
                        reply.writeTypedObject(KeyDescriptor().apply {
                            domain = Domain.GRANT; nspace = gnsp; alias = null; blob = null
                        }, 0)
                        return TransactionResult.OverrideReply(reply)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (Build.VERSION.SDK_INT < 36) {
                return replyKeystoreError(6)
            }

            val grantNspace = StateManager.issueGrant(
                StateManager.KeyIdentifier(uid, entry.alias),
                granteeUid, accessVector,
            )

            val reply = Parcel.obtain()
            reply.writeNoException()
            reply.writeTypedObject(KeyDescriptor().apply {
                domain = Domain.GRANT
                nspace = grantNspace
                alias = null
                blob = null
            }, 0)
            return TransactionResult.OverrideReply(reply)
        } catch (_: Exception) {}
        return TransactionResult.ContinueAndSkipPost
    }

    private fun handleUngrant(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val granteeUid = data.readInt()

            val entry = keyDescriptor.alias?.let { findEntry(uid, it) }
                ?: if (keyDescriptor.domain == Domain.KEY_ID)
                    findEntryByNspace(uid, keyDescriptor.nspace)
                else null

            if (entry == null) {
                if (keyDescriptor.alias != null) {
                    val kid = StateManager.KeyIdentifier(uid, keyDescriptor.alias)
                    if (teeInterceptor.teeResponses.containsKey(kid) ||
                        (strongBoxInterceptor?.teeResponses?.containsKey(kid) == true)) {
                        if (android.os.Build.VERSION.SDK_INT < 36) return replyKeystoreError(6)
                        StateManager.revokeGrantForOwner(kid, granteeUid)
                        val reply = Parcel.obtain()
                        reply.writeNoException()
                        return TransactionResult.OverrideReply(reply)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }
            if (android.os.Build.VERSION.SDK_INT < 36) return replyKeystoreError(6)

            StateManager.revokeGrantForOwner(StateManager.KeyIdentifier(uid, entry.alias), granteeUid)

            val reply = Parcel.obtain()
            reply.writeNoException()
            return TransactionResult.OverrideReply(reply)
        } catch (_: Exception) {}
        return TransactionResult.ContinueAndSkipPost
    }

    private fun replyKeystoreError(errorCode: Int): TransactionResult {
        val override = Parcel.obtain()
        override.writeInt(-8)
        override.writeString("Error::Rc($errorCode)")
        override.writeInt(0)
        override.writeInt(errorCode)
        return TransactionResult.OverrideReply(override)
    }

    private fun buildGetKeyEntryResponse(entry: StateManager.KeyEntry): TransactionResult {
        val binder = entry.securityLevelBinder ?: run {
            Logger.w("getKeyEntry alias=${entry.alias} UID=${entry.uid} → missing sec level binder")
            return TransactionResult.Continue
        }
        val pureCert = entry.metadata.certificate != null &&
            entry.metadata.keySecurityLevel >= 0 &&
            entry.metadata.authorizations?.isEmpty() != false
        val response = KeyEntryResponse().apply {
            metadata = entry.metadata
            iSecurityLevel = if (pureCert) null else binder
        }
        val reply = Parcel.obtain()
        reply.writeNoException()
        reply.writeTypedObject(response, 0)
        return TransactionResult.OverrideReply(reply)
    }

    private fun handleDeleteKey(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val alias = descriptor.alias
                ?: if (descriptor.domain == Domain.KEY_ID)
                    findEntryByNspace(uid, descriptor.nspace)?.alias
                else null
            if (alias == null) return TransactionResult.Continue

            val entry = findEntry(uid, alias)
            if (entry != null) {
                val keyId = StateManager.KeyIdentifier(uid, alias)
                Logger.d("deleteKey alias=$alias UID=$uid → cleaning up")
                val owningInterceptor = findOwningInterceptor(keyId)
                if (owningInterceptor != null) {
                    KeyMintInterceptor.cleanupKeyData(owningInterceptor, keyId)
                }
                deletedSoftwareKeys.add(keyId)
                val reply = Parcel.obtain()
                reply.writeNoException()
                return TransactionResult.OverrideReply(reply)
            }

            val keyId = StateManager.KeyIdentifier(uid, alias)
            if (teeInterceptor.teeResponses.containsKey(keyId) ||
                (strongBoxInterceptor?.teeResponses?.containsKey(keyId) == true)) {
                KeyMintInterceptor.cleanupKeyData(teeInterceptor, keyId)
                strongBoxInterceptor?.let { KeyMintInterceptor.cleanupKeyData(it, keyId) }
                deletedSoftwareKeys.add(keyId)
                val reply = Parcel.obtain()
                reply.writeNoException()
                return TransactionResult.OverrideReply(reply)
            }
        } catch (_: Exception) {}
        return TransactionResult.Continue
    }

    private fun handlePostGetKeyEntry(uid: Int, data: Parcel, reply: Parcel): TransactionResult {
        if (KeyMintInterceptor.hasException(reply)) return TransactionResult.Skip
        val savedReplyPos = reply.dataPosition()
        try {
            reply.setDataPosition(0)
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip

            val response = reply.readTypedObject(KeyEntryResponse.CREATOR) ?: return TransactionResult.Skip

            val metadata = response.metadata ?: return TransactionResult.Skip

            val authorizations = metadata.authorizations
            val parsedParams = KeyMintAttestation(
                authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
            )

            if (parsedParams.isImportKey) {
                Logger.d("getKeyEntry POST: skip patching for imported key alias=${keyDescriptor.alias}")
                return TransactionResult.Skip
            }

            if (!ConfigManager.shouldPatch(uid)) {
                Logger.d("getKeyEntry POST: not patching (shouldPatch=false) uid=$uid")
                return TransactionResult.Skip
            }

            if (parsedParams.isAttestKey) {
                return handleAttestKeyOverride(uid, keyDescriptor, response, parsedParams)
            }

            val originalChain = CertificateHelper.getCertificateChain(metadata) ?: return TransactionResult.Skip

            if (originalChain.size <= 1) {
                Logger.d("getKeyEntry POST: chain too short for alias=${keyDescriptor.alias}")
                return TransactionResult.Skip
            }

            val keyId = keyDescriptor.alias?.let { alias ->
                StateManager.KeyIdentifier(uid, alias)
            }

            val patchedChain: Array<Certificate>
            if (keyId != null) {
                val cached = strongBoxInterceptor?.let {
                    KeyMintInterceptor.getPatchedChain(it, keyId)
                } ?: KeyMintInterceptor.getPatchedChain(teeInterceptor, keyId)
                if (cached != null) {
                    Logger.d("getKeyEntry POST: using cached patched chain for alias=${keyDescriptor.alias}")
                    patchedChain = cached
                } else {
                    Logger.d("getKeyEntry POST: live patching chain for alias=${keyDescriptor.alias}")
                    patchedChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
                    val targetInterceptor = interceptorForSecurityLevel(response.metadata.keySecurityLevel)
                    targetInterceptor.patchedChains[keyId] = patchedChain
                }
            } else {
                Logger.d("getKeyEntry POST: live patching chain (anonymous descriptor)")
                patchedChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
            }

            CertificateHelper.updateCertificateChain(uid, metadata, patchedChain)
                .onFailure { e -> Logger.e("updateCertificateChain failed", e) }
            metadata.authorizations = AttestationPatcher.patchAuthorizations(metadata.authorizations, uid)

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(response, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("getKeyEntry POST patch failed", e)
        } finally {
            reply.setDataPosition(savedReplyPos)
        }
        return TransactionResult.Skip
    }

    private fun handleAttestKeyOverride(uid: Int, keyDescriptor: KeyDescriptor, response: KeyEntryResponse, params: KeyMintAttestation): TransactionResult {
        Logger.d("getKeyEntry POST: overriding hardware attest key alias=${keyDescriptor.alias}")

        val keybox = KeyboxReader.loadKeybox(params.algorithm) ?: return TransactionResult.Skip
        if (keybox.certificates.isEmpty()) return TransactionResult.Skip

        val keyPair = CertificateBuilder.generateKeyPair(params) ?: return TransactionResult.Skip

        val chain = CertificateBuilder.generateCertificateChain(
            keyPair, keybox, params, uid,
            response.metadata.keySecurityLevel,
        ) ?: return TransactionResult.Skip

        CertificateHelper.updateCertificateChain(uid, response.metadata, chain.toTypedArray())
            .onFailure { e -> Logger.e("updateCertificateChain failed for attest key", e) }

        val key = response.metadata.key ?: return TransactionResult.Skip
        key.nspace = java.security.SecureRandom().nextLong()

        val alias = keyDescriptor.alias ?: return TransactionResult.Skip
        val keyId = StateManager.KeyIdentifier(uid, alias)
        val entry = StateManager.KeyEntry(
            uid = uid,
            alias = alias,
            nspace = key.nspace,
            metadata = response.metadata,
            keyPair = keyPair,
            securityLevel = response.metadata.keySecurityLevel,
            securityLevelBinder = response.iSecurityLevel ?: return TransactionResult.Skip,
            certChain = chain.map { it as java.security.cert.X509Certificate },
        )
        val targetInterceptor = interceptorForSecurityLevel(response.metadata.keySecurityLevel)
        targetInterceptor.generatedKeys["${keyId.uid}:${keyId.alias}"] = entry
        GeneratedKeyPersistence.store(entry)
        Logger.d("Stored attest key override alias=$alias nspace=${key.nspace}")

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(response, 0)
        return TransactionResult.OverrideReply(override)
    }

    private fun parseBatchParams(txId: Long, data: Parcel) {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            data.readInt()
            data.readLong()
            val startPastAlias = data.readString()
            batchParams[txId] = startPastAlias
        } catch (_: Exception) {}
    }

    private fun injectGeneratedKeys(uid: Int, reply: Parcel, txId: Long): TransactionResult {
        try {
            reply.readException()
            val startPastAlias = batchParams.remove(txId)
            val existing = java.util.TreeMap<String, KeyDescriptor>()
            reply.createTypedArray(KeyDescriptor.CREATOR)?.forEach { kd ->
                kd.alias?.let { existing.putIfAbsent(it, kd) }
            }

            val generated = listEntriesForUid(uid)
                .filter { startPastAlias == null || it.alias > startPastAlias }
                .take(100)
            for (gk in generated) {
                existing[gk.alias] = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = gk.nspace
                    alias = gk.alias
                    blob = null
                }
            }

            val result = existing.values.toTypedArray()
            Logger.d("listEntries injected ${generated.size} keys for UID=$uid startPastAlias=$startPastAlias (total=${existing.size})")

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedArray(result, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("listEntries injection failed", e)
            return TransactionResult.Skip
        }
    }

    private fun injectEntryCount(reply: Parcel, uid: Int): TransactionResult {
        try {
            reply.readException()
            val halCount = reply.readInt()
            val generatedCount = countEntriesForUid(uid)
            val total = halCount + generatedCount
            Logger.d("getNumberOfEntries UID=$uid hal=$halCount generated=$generatedCount total=$total")

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeInt(total)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            return TransactionResult.Skip
        }
    }

    private fun shouldSkip(uid: Int): Boolean {
        return uid < 10000 || ConfigManager.shouldSkip(uid)
    }

    private fun isGms(uid: Int): Boolean {
        return try {
            val pmBinder = android.os.ServiceManager.getService("package") ?: return false
            val pm = android.content.pm.IPackageManager.Stub.asInterface(pmBinder)
            val packages = pm.getPackagesForUid(uid)?.toList() ?: emptyList()
            packages.any { it == "com.google.android.gms" }
        } catch (_: Exception) { false }
    }

    private fun findEntry(uid: Int, alias: String): StateManager.KeyEntry? {
        return teeInterceptor.generatedKeys.values.find { it.uid == uid && it.alias == alias }
            ?: strongBoxInterceptor?.generatedKeys?.values?.find { it.uid == uid && it.alias == alias }
    }

    private fun findEntryByNspace(uid: Int, nspace: Long): StateManager.KeyEntry? {
        val entry = KeyMintInterceptor.findGeneratedKeyByKeyId(teeInterceptor, uid, nspace)
        if (entry != null) return entry
        if (strongBoxInterceptor != null) {
            return KeyMintInterceptor.findGeneratedKeyByKeyId(strongBoxInterceptor, uid, nspace)
        }
        return null
    }

    private fun findTeeResponse(uid: Int, nspace: Long?): KeyEntryResponse? {
        val resp = KeyMintInterceptor.findTeeResponseByKeyId(teeInterceptor, uid, nspace)
        if (resp != null) return resp
        if (strongBoxInterceptor != null) {
            return KeyMintInterceptor.findTeeResponseByKeyId(strongBoxInterceptor, uid, nspace)
        }
        return null
    }

    private fun findMetadataByNspace(uid: Int, nspace: Long): KeyMetadata? {
        fun tryFind(interceptor: KeyMintInterceptor): KeyMetadata? {
            val entryKey = interceptor.nspaceToAlias["$uid:$nspace"]
            if (entryKey != null) return interceptor.metadataCache["$uid:$entryKey"]
            return interceptor.metadataCache.values.find {
                it.key?.nspace == nspace && it.key?.domain == Domain.KEY_ID
            }
        }
        return tryFind(teeInterceptor)
            ?: strongBoxInterceptor?.let { tryFind(it) }
    }

    private fun listEntriesForUid(uid: Int): List<StateManager.KeyEntry> {
        val entries = teeInterceptor.generatedKeys.values.filter { it.uid == uid }.toMutableList()
        strongBoxInterceptor?.generatedKeys?.values?.filter { it.uid == uid }?.let { entries.addAll(it) }
        return entries
    }

    private fun countEntriesForUid(uid: Int): Int {
        return teeInterceptor.generatedKeys.values.count { it.uid == uid } +
            (strongBoxInterceptor?.generatedKeys?.values?.count { it.uid == uid } ?: 0)
    }

    private fun findOwningInterceptor(keyId: StateManager.KeyIdentifier): KeyMintInterceptor? {
        if (KeyMintInterceptor.ownsKeyResponse(teeInterceptor, keyId)) return teeInterceptor
        if (strongBoxInterceptor != null && KeyMintInterceptor.ownsKeyResponse(strongBoxInterceptor, keyId)) return strongBoxInterceptor
        return null
    }

    private fun interceptorForSecurityLevel(securityLevel: Int): KeyMintInterceptor {
        return if (strongBoxInterceptor != null &&
            securityLevel == android.hardware.security.keymint.SecurityLevel.STRONGBOX)
            strongBoxInterceptor
        else
            teeInterceptor
    }

    companion object {
        val LIST_ENTRIES_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_listEntries") }
        val LIST_ENTRIES_BATCHED_TRANSACTION: Int? by lazy {
            if (android.os.Build.VERSION.SDK_INT >= 34) resolveCode("TRANSACTION_listEntriesBatched") else null
        }
        val GET_KEY_ENTRY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_getKeyEntry") }
        val DELETE_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_deleteKey") }
        val UPDATE_SUBCOMPONENT_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_updateSubcomponent") }
        val GRANT_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_grant") }
        val UNGRANT_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_ungrant") }
        val GET_NUMBER_OF_ENTRIES_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_getNumberOfEntries") }

        private fun resolveCode(name: String): Int {
            return try {
                IKeystoreService.Stub::class.java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .getInt(null)
            } catch (e: Exception) {
                Logger.e("Failed to resolve $name", e)
                -1
            }
        }
    }
}
