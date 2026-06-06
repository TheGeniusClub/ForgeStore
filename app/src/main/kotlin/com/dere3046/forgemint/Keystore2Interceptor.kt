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
import android.os.Parcel
import android.os.Build
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata

class Keystore2Interceptor : BinderInterceptor() {

    private val batchParams = java.util.concurrent.ConcurrentHashMap<Long, String?>()

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
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
            val entry = StateManager.lookupByNspace(uid, descriptor.nspace)
                ?: return TransactionResult.ContinueAndSkipPost

            val publicCert = data.createByteArray()
            val certificateChain = data.createByteArray()

            entry.metadata.certificate = publicCert
            entry.metadata.certificateChain = certificateChain
            Logger.i("updateSubcomponent nspace=${entry.nspace} cert=${publicCert?.size} chain=${certificateChain?.size}")

            val reply = Parcel.obtain()
            reply.writeNoException()
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
                val teeResp = StateManager.lookupTeeResponse(uid, descriptor.nspace)
                if (teeResp != null) {
                    val reply = Parcel.obtain()
                    reply.writeNoException()
                    reply.writeTypedObject(teeResp, 0)
                    return TransactionResult.OverrideReply(reply)
                }
            }

            val entry = descriptor.alias?.let { StateManager.lookup(uid, it) }
                ?: if (descriptor.domain == Domain.KEY_ID)
                    StateManager.lookupByNspace(uid, descriptor.nspace)
                else null

            if (entry == null) return TransactionResult.Continue
            return buildGetKeyEntryResponse(entry)
        } catch (e: Exception) {
            Logger.e("getKeyEntry failed", e)
            return TransactionResult.Continue
        }
    }

    private fun handleGrantDomainGetKeyEntry(descriptor: KeyDescriptor, uid: Int): TransactionResult {
        val grantResult = StateManager.resolveGrant(descriptor.nspace, uid)
        if (grantResult == null) {
            if (StateManager.isGrantNspaceKnown(descriptor.nspace)) {
                return replyKeystoreError(7)
            }
            return TransactionResult.ContinueAndSkipPost
        }

        val entry = StateManager.lookup(grantResult.uid, grantResult.alias)
            ?: return replyKeystoreError(7)

        val accessVector = StateManager.getGrantAccessVector(descriptor.nspace) ?: 0
        if ((accessVector and 0x4) == 0) {
            return replyKeystoreError(6)
        }

        return buildGetKeyEntryResponse(entry)
    }

    private fun handleGetKeyEntryByMetadata(descriptor: KeyDescriptor, uid: Int): TransactionResult? {
        val metadata = StateManager.lookupMetadataByNspace(uid, descriptor.nspace) ?: return null
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

            val entry = keyDescriptor.alias?.let { StateManager.lookup(uid, it) }
                ?: if (keyDescriptor.domain == Domain.KEY_ID)
                    StateManager.lookupByNspace(uid, keyDescriptor.nspace)
                else null

            if (entry == null) return TransactionResult.ContinueAndSkipPost

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

            val entry = keyDescriptor.alias?.let { StateManager.lookup(uid, it) }
                ?: if (keyDescriptor.domain == Domain.KEY_ID)
                    StateManager.lookupByNspace(uid, keyDescriptor.nspace)
                else null

            if (entry == null) return TransactionResult.ContinueAndSkipPost

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
                    StateManager.lookupByNspace(uid, descriptor.nspace)?.alias
                else null
            if (alias == null) return TransactionResult.Continue

            if (StateManager.lookup(uid, alias) != null) {
                Logger.i("deleteKey alias=$alias UID=$uid → cleaning up")
                StateManager.remove(uid, alias)
                val reply = Parcel.obtain()
                reply.writeNoException()
                return TransactionResult.OverrideReply(reply)
            }
        } catch (_: Exception) {}
        return TransactionResult.Continue
    }

    private fun handlePostGetKeyEntry(uid: Int, data: Parcel, reply: Parcel): TransactionResult {
        try {
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

            val patchedChain: Array<java.security.cert.Certificate>
            if (keyId != null) {
                val cached = StateManager.getPatchedChain(keyId)
                if (cached != null) {
                    Logger.d("getKeyEntry POST: using cached patched chain for alias=${keyDescriptor.alias}")
                    patchedChain = cached
                } else {
                    Logger.i("getKeyEntry POST: live patching chain for alias=${keyDescriptor.alias}")
                    patchedChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
                    StateManager.cachePatchedChain(keyId, patchedChain)
                }
            } else {
                Logger.i("getKeyEntry POST: live patching chain (anonymous descriptor)")
                patchedChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
            }

            CertificateHelper.updateCertificateChain(uid, metadata, patchedChain)
                .onFailure { e -> Logger.e("updateCertificateChain failed", e) }

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(response, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("getKeyEntry POST patch failed", e)
            return TransactionResult.Skip
        }
    }

    private fun handleAttestKeyOverride(uid: Int, keyDescriptor: KeyDescriptor, response: KeyEntryResponse, params: KeyMintAttestation): TransactionResult {
        Logger.i("getKeyEntry POST: overriding hardware attest key alias=${keyDescriptor.alias}")

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
        StateManager.store(entry)
        Logger.i("Stored attest key override alias=$alias nspace=${key.nspace}")

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

            val generated = StateManager.listForUid(uid)
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
            Logger.i("listEntries injected ${generated.size} keys for UID=$uid startPastAlias=$startPastAlias (total=${existing.size})")

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
            val generatedCount = StateManager.listForUid(uid).size
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
