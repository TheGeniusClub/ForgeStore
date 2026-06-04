package com.dere3046.forgemint

import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyMetadata
import java.security.SecureRandom
import java.security.cert.X509Certificate

class KeyMintInterceptor(
    private val originalBinder: IBinder,
    private val securityLevel: Int,
) : BinderInterceptor() {

    data class GenerateKeyParams(
        val attestation: KeyMintAttestation,
        val descriptor: KeyDescriptor,
        val attestationKeyDescriptor: KeyDescriptor?,
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
        if (code == CREATE_OPERATION_TRANSACTION) {
            return handleCreateOperation(txId, callingUid, data)
        }

        if (code == IMPORT_KEY_TRANSACTION) {
            return handleImportKey(callingUid, data)
        }

        if (code != GENERATE_KEY_TRANSACTION) {
            return TransactionResult.ContinueAndSkipPost
        }

        Logger.i("generateKey UID=$callingUid")

        if (ConfigManager.shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }

        val genParams = parseParams(data) ?: return TransactionResult.Continue
        val params = genParams.attestation

        val needsSoftwareGen = ConfigManager.shouldGenerate(callingUid) ||
            (ConfigManager.shouldPatch(callingUid) && params.isAttestKey) ||
            (genParams.attestationKeyDescriptor != null && isKnownAttestationKey(callingUid, genParams.attestationKeyDescriptor))

        if (needsSoftwareGen) {
            val result = tryGenerateSoftwareKey(params, genParams.descriptor, genParams.attestationKeyDescriptor, callingUid)
            if (result != null) {
                Logger.i("Software key generated for UID=$callingUid")
                return result
            }
            Logger.w("Software generation failed, falling back to HAL")
        }

        if (ConfigManager.shouldPatch(callingUid) && params.attestationChallenge != null) {
            Logger.i("Forwarding to HAL for PATCH mode")
            return TransactionResult.Continue
        }

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

        if (code == GENERATE_KEY_TRANSACTION) {
            return handlePostGenerateKey(callingUid, data, reply)
        }

        if (code == CREATE_OPERATION_TRANSACTION) {
            return handlePostCreateOperation(callingUid, data, reply, target)
        }

        if (code == IMPORT_KEY_TRANSACTION) {
            return handlePostImportKey(callingUid, data)
        }

        return TransactionResult.Skip
    }

    private fun handlePostGenerateKey(callingUid: Int, data: Parcel, reply: Parcel): TransactionResult {
        if (!ConfigManager.shouldPatch(callingUid)) return TransactionResult.Skip

        Logger.i("PATCH mode post-generateKey for UID=$callingUid")

        try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return TransactionResult.Skip

            val originalChain = CertificateHelper.getCertificateChain(metadata) ?: return TransactionResult.Skip

            if (originalChain.size <= 1) {
                Logger.d("PATCH mode: chain too short (size=${originalChain.size})")
                return TransactionResult.Skip
            }

            val patchedChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip

            val keyId = StateManager.KeyIdentifier(callingUid, keyDescriptor.alias ?: "")
            StateManager.cachePatchedChain(keyId, patchedChain)
            Logger.d("Cached patched chain for alias=${keyDescriptor.alias}")

            CertificateHelper.updateCertificateChain(callingUid, metadata, patchedChain)
                .onFailure { e -> Logger.e("updateCertificateChain failed", e) }

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(metadata, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("PATCH mode post-generateKey failed", e)
            return TransactionResult.Skip
        }
    }

    private fun handlePostCreateOperation(uid: Int, data: Parcel, reply: Parcel, target: IBinder): TransactionResult {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            data.readTypedObject(KeyDescriptor.CREATOR)
            data.createTypedArray(KeyParameter.CREATOR)
            data.readBoolean()

            reply.readException()
            val response = reply.readTypedObject(CreateOperationResponse.CREATOR) ?: return TransactionResult.Skip

            response.iOperation?.let { op ->
                val opBinder = op.asBinder()
                val opBackdoor = BinderInterceptor.getBackdoor(target) ?: return@let
                val interceptor = OperationInterceptor(op, opBackdoor)
                BinderInterceptor.register(opBackdoor, opBinder, interceptor)
                Logger.i("Registered OperationInterceptor for UID=$uid")
            }
        } catch (e: Exception) {
            Logger.e("Post createOperation failed", e)
        }
        return TransactionResult.Skip
    }

    private fun handlePostImportKey(uid: Int, data: Parcel): TransactionResult {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip
            val alias = keyDescriptor.alias
            if (alias != null && StateManager.lookup(uid, alias) != null) {
                Logger.i("importKey alias=$alias UID=$uid → cleaning up generated key")
                StateManager.remove(uid, alias)
            }
        } catch (_: Exception) {}
        return TransactionResult.Skip
    }

    private fun handleCreateOperation(
        txId: Long,
        uid: Int,
        data: Parcel,
    ): TransactionResult {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue

            if (keyDescriptor.domain != Domain.KEY_ID) {
                return TransactionResult.ContinueAndSkipPost
            }

            val entry = StateManager.lookupByNspace(uid, keyDescriptor.nspace)
                ?: return TransactionResult.Continue

            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return TransactionResult.Continue
            val parsedParams = KeyMintAttestation(params)
            data.readBoolean()

            Logger.i("createOperation for generated key alias=${entry.alias} nspace=${keyDescriptor.nspace}")

            val operation = SoftwareOperation(txId, entry.keyPair, parsedParams)
            val binder = SoftwareOperationBinder(operation)
            val override = Parcel.obtain()
            override.writeNoException()
            override.writeStrongBinder(binder)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("createOperation failed", e)
            return TransactionResult.Continue
        }
    }

    private fun parseParams(data: Parcel): GenerateKeyParams? {
        return try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return null
            val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return null
            data.readInt()
            GenerateKeyParams(KeyMintAttestation(params), descriptor, attestationKeyDescriptor)
        } catch (e: Exception) {
            Logger.e("Failed to parse generateKey params", e)
            null
        }
    }

    private fun buildAuthorizations(params: KeyMintAttestation, callingUid: Int): Array<Authorization> {
        val list = mutableListOf<Authorization>()

        fun addAuth(tag: Int, level: Int, value: KeyParameterValue.() -> Unit) {
            val kp = KeyParameter()
            kp.tag = tag
            kp.value = KeyParameterValue().apply(value)
            list.add(Authorization().apply {
                keyParameter = kp
                this.securityLevel = level
            })
        }

        addAuth(Tag.ALGORITHM, securityLevel) { algorithm = params.algorithm }
        for (p in params.purpose) {
            addAuth(Tag.PURPOSE, securityLevel) { keyPurpose = p }
        }
        if (params.keySize > 0) {
            addAuth(Tag.KEY_SIZE, securityLevel) { integer = params.keySize }
        }
        if (params.ecCurve != null) {
            addAuth(Tag.EC_CURVE, securityLevel) { ecCurve = params.ecCurve }
        }
        if (params.rsaPublicExponent != null) {
            addAuth(Tag.RSA_PUBLIC_EXPONENT, securityLevel) { longInteger = params.rsaPublicExponent.toLong() }
        }
        for (d in params.digest) {
            addAuth(Tag.DIGEST, securityLevel) { digest = d }
        }
        for (m in params.blockMode) {
            addAuth(Tag.BLOCK_MODE, securityLevel) { blockMode = m }
        }
        for (p in params.padding) {
            addAuth(Tag.PADDING, securityLevel) { paddingMode = p }
        }
        if (params.noAuthRequired != null) {
            addAuth(Tag.NO_AUTH_REQUIRED, securityLevel) { boolValue = params.noAuthRequired }
        }
        addAuth(Tag.ORIGIN, securityLevel) { origin = params.origin ?: KeyOrigin.GENERATED }
        addAuth(Tag.OS_VERSION, securityLevel) { integer = AttestationBuilder.osVersion }
        addAuth(Tag.OS_PATCHLEVEL, securityLevel) { integer = AttestationBuilder.getPatchLevel(callingUid) }
        addAuth(Tag.VENDOR_PATCHLEVEL, securityLevel) { integer = AttestationBuilder.getPatchLevelLong(callingUid) }
        addAuth(Tag.BOOT_PATCHLEVEL, securityLevel) { integer = AttestationBuilder.getPatchLevelLong(callingUid) }
        addAuth(Tag.CREATION_DATETIME, securityLevel) { dateTime = System.currentTimeMillis() }
        addAuth(Tag.USER_ID, SecurityLevel.SOFTWARE) { integer = callingUid / 100000 }

        return list.toTypedArray()
    }

    companion object {
        val GENERATE_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_generateKey") }
        val CREATE_OPERATION_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_createOperation") }
        val IMPORT_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_importKey") }

        private fun resolveCode(name: String): Int {
            return try {
                IKeystoreSecurityLevel.Stub::class.java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .getInt(null)
            } catch (e: Exception) {
                Logger.e("Failed to resolve $name", e)
                -1
            }
        }
    }

    private fun isKnownAttestationKey(uid: Int, descriptor: KeyDescriptor): Boolean {
        val entry = StateManager.lookup(uid, descriptor.alias ?: return false)
            ?: StateManager.lookupByNspace(uid, descriptor.nspace)
        return entry != null
    }

    private fun handleImportKey(uid: Int, data: Parcel): TransactionResult {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val alias = keyDescriptor?.alias
            if (alias != null) {
                Logger.i("importKey alias=$alias UID=$uid → forwarding to HAL, will cleanup on success")
            }
        } catch (_: Exception) {}
        return TransactionResult.Continue
    }

    private fun tryGenerateSoftwareKey(
        params: KeyMintAttestation,
        originalDescriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        uid: Int,
    ): TransactionResult? {
        Logger.i("tryGenerateSoftwareKey algo=${params.algorithm} keySize=${params.keySize} ecCurve=${params.ecCurve} uid=$uid")

        val keybox = KeyboxReader.loadKeybox(params.algorithm)
        if (keybox == null) {
            Logger.w("GenKeyFailed: keybox not found for algo=${params.algorithm}")
            return null
        }
        if (keybox.certificates.isEmpty()) {
            Logger.w("GenKeyFailed: keybox certificates empty")
            return null
        }

        val signerKeyPair = if (attestKeyDescriptor != null) {
            val alias = attestKeyDescriptor.alias
            if (alias == null) {
                Logger.w("GenKeyFailed: attestKeyDescriptor alias is null")
                return null
            }
            val attestEntry = StateManager.lookup(uid, alias)
                ?: StateManager.lookupByNspace(uid, attestKeyDescriptor.nspace)
            if (attestEntry == null) {
                Logger.w("GenKeyFailed: attest key not found alias=$alias")
                return null
            }
            attestEntry.keyPair
        } else null

        val keyPair = CertificateBuilder.generateKeyPair(params)
        if (keyPair == null) {
            Logger.w("GenKeyFailed: KeyPair generation failed algo=${params.algorithm} keySize=${params.keySize}")
            return null
        }

        val chain = CertificateBuilder.generateCertificateChain(
            keyPair, keybox, params, uid, securityLevel,
            signerKeyPair,
        )
        if (chain == null) {
            Logger.w("GenKeyFailed: cert chain generation failed")
            return null
        }

        val nspace = SecureRandom().nextLong()
        val descriptor = KeyDescriptor().apply {
            domain = Domain.KEY_ID
            this.nspace = nspace
            alias = null
            blob = null
        }
        val metadata = KeyMetadata().apply {
            keySecurityLevel = securityLevel
            key = descriptor
            modificationTimeMs = System.currentTimeMillis()
            authorizations = buildAuthorizations(params, uid)
            certificate = chain[0].encoded
            certificateChain = if (chain.size > 1) {
                chain.drop(1).flatMap { it.encoded.toList() }.toByteArray()
            } else null
        }

        StateManager.store(StateManager.KeyEntry(
            uid = uid,
            alias = originalDescriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = keyPair,
            securityLevel = securityLevel,
            securityLevelBinder = originalBinder,
            certChain = chain.map { it as X509Certificate },
        ))

        val response = android.system.keystore2.KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = originalBinder
        }
        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(response, 0)
        return TransactionResult.OverrideReply(override)
    }
}
