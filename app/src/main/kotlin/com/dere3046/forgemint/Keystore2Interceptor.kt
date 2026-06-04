package com.dere3046.forgemint

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata

class Keystore2Interceptor : BinderInterceptor() {

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
            return handleGetKeyEntry(data, callingUid)
        }
        if (code == DELETE_KEY_TRANSACTION) {
            return handleDeleteKey(data, callingUid)
        }
        if (shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }
        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            if (isGms(callingUid)) return TransactionResult.ContinueAndSkipPost
        }
        return TransactionResult.Continue
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
            return injectGeneratedKeys(reply, callingUid)
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
            val alias = descriptor.alias ?: return TransactionResult.Continue

            val entry = StateManager.lookup(uid, alias) ?: return TransactionResult.Continue

            Logger.i("getKeyEntry alias=$alias UID=$uid → returning generated key")

            val response = KeyEntryResponse().apply {
                metadata = entry.metadata
                iSecurityLevel = entry.securityLevelBinder
            }
            val reply = Parcel.obtain()
            reply.writeNoException()
            reply.writeTypedObject(response, 0)
            return TransactionResult.OverrideReply(reply)
        } catch (e: Exception) {
            Logger.e("getKeyEntry failed", e)
            return TransactionResult.Continue
        }
    }

    private fun handleDeleteKey(data: Parcel, uid: Int): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val alias = descriptor.alias ?: return TransactionResult.Continue

            if (StateManager.lookup(uid, alias) != null) {
                Logger.i("deleteKey alias=$alias UID=$uid → cleaning up")
                StateManager.remove(uid, alias)
            }
        } catch (_: Exception) {}
        return TransactionResult.Continue
    }

    private fun handlePostGetKeyEntry(uid: Int, data: Parcel, reply: Parcel): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip

            val response = reply.readTypedObject(KeyEntryResponse.CREATOR) ?: return TransactionResult.Skip

            val authorizations = response.metadata.authorizations
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

            val originalChain = CertificateHelper.getCertificateChain(response.metadata) ?: return TransactionResult.Skip

            if (originalChain.size <= 1) {
                Logger.d("getKeyEntry POST: chain too short for alias=${keyDescriptor.alias}")
                return TransactionResult.Skip
            }

            val keyId = StateManager.KeyIdentifier(uid, keyDescriptor.alias ?: return TransactionResult.Skip)

            val cachedChain = StateManager.getPatchedChain(keyId)
            val patchedChain: Array<java.security.cert.Certificate>
            if (cachedChain != null) {
                Logger.d("getKeyEntry POST: using cached patched chain for alias=${keyDescriptor.alias}")
                patchedChain = cachedChain
            } else {
                Logger.i("getKeyEntry POST: live patching chain for alias=${keyDescriptor.alias}")
                patchedChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
                StateManager.cachePatchedChain(keyId, patchedChain)
            }

            CertificateHelper.updateCertificateChain(uid, response.metadata, patchedChain)
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

    private fun injectGeneratedKeys(reply: Parcel, uid: Int): TransactionResult {
        try {
            reply.readException()
            val existing = mutableMapOf<String, KeyDescriptor>()
            reply.createTypedArray(KeyDescriptor.CREATOR)?.forEach { kd ->
                kd.alias?.let { existing.putIfAbsent(it, kd) }
            }

            val generated = StateManager.listForUid(uid)
            for (gk in generated) {
                existing[gk.alias] = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = gk.nspace
                    alias = gk.alias
                    blob = null
                }
            }

            Logger.i("listEntries injected ${generated.size} keys for UID=$uid (total=${existing.size})")

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedArray(existing.values.toTypedArray(), 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("listEntries injection failed", e)
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
        val LIST_ENTRIES_BATCHED_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_listEntriesBatched") }
        val GET_KEY_ENTRY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_getKeyEntry") }
        val DELETE_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_deleteKey") }

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
