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

        if (ConfigManager.shouldSkip(callingUid) && !params.isAttestKey) {
            return TransactionResult.ContinueAndSkipPost
        }

        val needsSoftwareGen = params.isAttestKey ||
            ConfigManager.shouldGenerate(callingUid) ||
            (ConfigManager.shouldPatch(callingUid) && params.isAttestKey) ||
            (genParams.attestationKeyDescriptor != null && isKnownAttestationKey(callingUid, genParams.attestationKeyDescriptor))

        if (needsSoftwareGen) {
            val result = tryGenerateSoftwareKey(params, genParams.descriptor, genParams.attestationKeyDescriptor, callingUid)
            if (result != null) {
                Logger.i("Software key generated for UID=$callingUid")
                return result
            }
            Logger.w("Software generation failed (isAttestKey=${params.isAttestKey} challenge=${params.attestationChallenge != null}), falling back to HAL")
        }

        if (ConfigManager.shouldPatch(callingUid) && params.attestationChallenge != null) {
            Logger.i("Forwarding to HAL for PATCH mode")
            return TransactionResult.Continue
        }

        Logger.i("generateKey: no handler matched (shouldGenerate=${ConfigManager.shouldGenerate(callingUid)} shouldPatch=${ConfigManager.shouldPatch(callingUid)} isAttestKey=${params.isAttestKey} hasChallenge=${params.attestationChallenge != null}), forwarding to HAL for post-transact cache")
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
        try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return TransactionResult.Skip

            val originalChain = CertificateHelper.getCertificateChain(metadata) ?: return TransactionResult.Skip

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip
            val keyId = StateManager.KeyIdentifier(callingUid, keyDescriptor.alias ?: "")

            if (originalChain.size <= 1) {
                StateManager.cacheMetadataSnapshot(keyId, metadata)
                val levelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
                StateManager.cacheTeeResponse(keyId, metadata, levelBinder)
                Logger.d("Cached teeResponse for non-attested key alias=${keyDescriptor.alias}")
                return TransactionResult.Skip
            }

            if (!ConfigManager.shouldPatch(callingUid)) {
                val levelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
                StateManager.cacheTeeResponse(keyId, metadata, levelBinder)
                return TransactionResult.Skip
            }

            Logger.i("PATCH mode post-generateKey for UID=$callingUid")
            val patchedChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

            StateManager.cachePatchedChain(keyId, patchedChain)
            val levelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
            StateManager.cacheTeeResponse(keyId, metadata, levelBinder)
            StateManager.cacheMetadataSnapshot(keyId, metadata)
            Logger.d("Cached patched chain + teeResponse for alias=${keyDescriptor.alias}")

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
            val keyDesc = data.readTypedObject(KeyDescriptor.CREATOR)
            val paramsArray = data.createTypedArray(KeyParameter.CREATOR)
            data.readBoolean()

            val isAead = paramsArray?.let { params ->
                KeyMintAttestation(params).blockMode.any { it == android.hardware.security.keymint.BlockMode.GCM }
            } ?: false

            reply.readException()
            val response = reply.readTypedObject(CreateOperationResponse.CREATOR)
            if (response == null) {
                Logger.w("Post createOperation: response is null for UID=$uid keyDesc.alias=${keyDesc?.alias} keyDesc.nspace=${keyDesc?.nspace}")
                return TransactionResult.Skip
            }
            Logger.i("Post createOperation: UID=$uid operationChallenge=${response.operationChallenge != null} iOperation=${response.iOperation != null}")

            response.iOperation?.let { op ->
                val opBinder = op.asBinder()
                val opBackdoor = BinderInterceptor.getBackdoor(target) ?: return@let
                val interceptor = OperationInterceptor(op, opBackdoor, isAead)
                BinderInterceptor.register(opBackdoor, opBinder, interceptor)
                Logger.i("Registered OperationInterceptor for UID=$uid isAead=$isAead")
            }
        } catch (e: Exception) {
            Logger.e("Post createOperation failed UID=$uid", e)
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

            val entry = StateManager.lookupByAliasOrDomain(uid, keyDescriptor)
                ?: return TransactionResult.Continue

            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return TransactionResult.Continue
            var parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()

            if (parsedParams.algorithm == 0 && entry.keyPair != null) {
                parsedParams = parsedParams.copy(algorithm = when (entry.keyPair.private.algorithm) {
                    "EC", "ECDSA" -> android.hardware.security.keymint.Algorithm.EC
                    "RSA" -> android.hardware.security.keymint.Algorithm.RSA
                    else -> parsedParams.algorithm
                })
            }

            val keyParams = KeyMintAttestation(
                entry.metadata.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
            )

            val authResult = AuthorizeCreate.validate(parsedParams, keyParams, forced)
            if (!authResult.allowed) {
                Logger.w("createOperation authorized failed for UID=$uid error=${authResult.errorCode}")
                return replyKeymintError(authResult.errorCode ?: -1000) ?: TransactionResult.Skip
            }

            Logger.i("createOperation for generated key alias=${entry.alias} nspace=${keyDescriptor.nspace} algo=${parsedParams.algorithm} purpose=${parsedParams.purpose.firstOrNull()}")

            val operation = SoftwareOperation(txId, entry.keyPair, entry.secretKey, parsedParams, securityLevel, uid)
            StateManager.acquireOp(uid, operation)
            val binder = SoftwareOperationBinder(operation)
            val response = android.system.keystore2.CreateOperationResponse().apply {
                iOperation = binder
                operationChallenge = null
                parameters = operation.beginParameters
            }
            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(response, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("createOperation failed UID=$uid", e)
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

        for (p in params.purpose) {
            addAuth(Tag.PURPOSE, securityLevel) { keyPurpose = p }
        }
        addAuth(Tag.ALGORITHM, securityLevel) { algorithm = params.algorithm }
        if (params.keySize > 0) {
            addAuth(Tag.KEY_SIZE, securityLevel) { integer = params.keySize }
        }
        if (params.ecCurve != null) {
            addAuth(Tag.EC_CURVE, securityLevel) { ecCurve = params.ecCurve }
        }
        for (m in params.blockMode) {
            addAuth(Tag.BLOCK_MODE, securityLevel) { blockMode = m }
        }
        for (d in params.digest) {
            addAuth(Tag.DIGEST, securityLevel) { digest = d }
        }
        for (p in params.padding) {
            addAuth(Tag.PADDING, securityLevel) { paddingMode = p }
        }
        if (params.rsaPublicExponent != null) {
            addAuth(Tag.RSA_PUBLIC_EXPONENT, securityLevel) { longInteger = params.rsaPublicExponent.toLong() }
        }
        for (d in params.rsaOaepMgfDigest) {
            addAuth(Tag.RSA_OAEP_MGF_DIGEST, securityLevel) { digest = d }
        }

        if (params.callerNonce == true) {
            addAuth(Tag.CALLER_NONCE, securityLevel) { boolValue = true }
        }
        if (params.minMacLength != null) {
            addAuth(Tag.MIN_MAC_LENGTH, securityLevel) { integer = params.minMacLength }
        }
        if (params.rollbackResistance == true) {
            addAuth(Tag.ROLLBACK_RESISTANCE, securityLevel) { boolValue = true }
        }
        if (params.earlyBootOnly == true) {
            addAuth(Tag.EARLY_BOOT_ONLY, securityLevel) { boolValue = true }
        }
        if (params.allowWhileOnBody == true) {
            addAuth(Tag.ALLOW_WHILE_ON_BODY, securityLevel) { boolValue = true }
        }
        if (params.trustedUserPresenceRequired == true) {
            addAuth(Tag.TRUSTED_USER_PRESENCE_REQUIRED, securityLevel) { boolValue = true }
        }
        if (params.trustedConfirmationRequired == true) {
            addAuth(Tag.TRUSTED_CONFIRMATION_REQUIRED, securityLevel) { boolValue = true }
        }
        if (params.maxUsesPerBoot != null) {
            addAuth(Tag.MAX_USES_PER_BOOT, securityLevel) { integer = params.maxUsesPerBoot }
        }
        if (params.maxBootLevel != null) {
            addAuth(Tag.MAX_BOOT_LEVEL, securityLevel) { integer = params.maxBootLevel }
        }

        if (params.noAuthRequired != null) {
            addAuth(Tag.NO_AUTH_REQUIRED, securityLevel) { boolValue = params.noAuthRequired }
        }
        addAuth(Tag.ORIGIN, securityLevel) { origin = params.origin ?: KeyOrigin.GENERATED }
        addAuth(Tag.OS_VERSION, securityLevel) { integer = AttestationBuilder.osVersion }
        addAuth(Tag.OS_PATCHLEVEL, securityLevel) { integer = AttestationBuilder.getPatchLevel(callingUid) }

        addAuth(Tag.CREATION_DATETIME, SecurityLevel.KEYSTORE) { dateTime = System.currentTimeMillis() }
        if (params.activeDateTime != null) {
            addAuth(Tag.ACTIVE_DATETIME, SecurityLevel.KEYSTORE) { dateTime = params.activeDateTime.time }
        }
        if (params.originationExpireDateTime != null) {
            addAuth(Tag.ORIGINATION_EXPIRE_DATETIME, SecurityLevel.KEYSTORE) { dateTime = params.originationExpireDateTime.time }
        }
        if (params.usageExpireDateTime != null) {
            addAuth(Tag.USAGE_EXPIRE_DATETIME, SecurityLevel.KEYSTORE) { dateTime = params.usageExpireDateTime.time }
        }
        if (params.unlockedDeviceRequired == true) {
            addAuth(Tag.UNLOCKED_DEVICE_REQUIRED, SecurityLevel.KEYSTORE) { boolValue = true }
        }
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

    private fun replyKeymintError(errorCode: Int): TransactionResult? {
        val override = Parcel.obtain()
        override.writeInt(-8)
        override.writeString("Error::Km($errorCode)")
        override.writeInt(0)
        override.writeInt(errorCode)
        return TransactionResult.OverrideReply(override)
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

        val startNanos = System.nanoTime()

        if (params.hasTag(AttestationConstants.TAG_CREATION_DATETIME)) {
            Logger.w("generateKey rejected: CREATION_DATETIME in params.uid=$uid")
            return replyKeymintError(20)
        }

        if (params.isAttestKey) {
            return tryGenerateAttestKey(params, originalDescriptor, uid, startNanos)
        }

        if (params.isSymmetric) {
            return tryGenerateSymmetricKey(params, originalDescriptor, uid, startNanos)
        }

        if (params.attestationChallenge != null && params.attestationChallenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT) {
            Logger.w("Challenge exceeds length limit (${params.attestationChallenge.size})")
            return replyKeymintError(-21)
        }

        val keybox = KeyboxReader.loadKeybox(params.algorithm)
        val attestEntry: StateManager.KeyEntry? = if (attestKeyDescriptor != null) {
            val alias = attestKeyDescriptor.alias
            if (alias == null) {
                Logger.w("GenKeyFailed: attestKeyDescriptor alias is null")
                return null
            }
            val entry = StateManager.lookup(uid, alias)
                ?: StateManager.lookupByNspace(uid, attestKeyDescriptor.nspace)
            if (entry == null) {
                Logger.w("GenKeyFailed: attest key not found alias=$alias")
                return null
            }
            entry
        } else null
        val signerKeyPair = attestEntry?.keyPair
        val attestKeyCert = attestEntry?.certChain?.firstOrNull()

        val keyPair = CertificateBuilder.generateKeyPair(params)
        if (keyPair == null) {
            Logger.w("GenKeyFailed: KeyPair generation failed algo=${params.algorithm} keySize=${params.keySize}")
            return null
        }

        val chain = when {
            keybox != null && keybox.certificates.isNotEmpty() ->
                CertificateBuilder.generateCertificateChain(
                    keyPair, keybox, params, uid, securityLevel,
                    signerKeyPair, attestKeyCert,
                )
            keybox != null -> {
                Logger.w("keybox configured but certificates empty, using self-signed fallback for UID=$uid")
                CertificateBuilder.generateFallbackChain(keyPair, params, uid, securityLevel)
            }
            else -> {
                Logger.w("no keybox configured, falling back to HAL for UID=$uid")
                null
            }
        }
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
        val metadata = Parcel.obtain().let { p ->
            val m = KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = descriptor
                modificationTimeMs = System.currentTimeMillis()
                authorizations = buildAuthorizations(params, uid)
                certificate = chain[0].encoded
                certificateChain = if (chain.size > 1) {
                    chain.drop(1).flatMap { it.encoded.toList() }.toByteArray()
                } else null
            }
            p.writeTypedObject(m, 0)
            p.setDataPosition(0)
            val normalized = p.readTypedObject(KeyMetadata.CREATOR) ?: m
            p.recycle()
            normalized
        }

        StateManager.store(StateManager.KeyEntry(
            uid = uid,
            alias = originalDescriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = keyPair,
            securityLevel = securityLevel,
            securityLevelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = chain.map { it as X509Certificate },
        ))

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(metadata, 0)

        TeeLatencySimulator.simulateGenerateKeyDelay(params.algorithm, securityLevel, System.nanoTime() - startNanos)

        return TransactionResult.OverrideReply(override)
    }

    private fun tryGenerateAttestKey(
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
        uid: Int,
        startNanos: Long,
    ): TransactionResult? {
        Logger.i("tryGenerateAttestKey algo=${params.algorithm} uid=$uid")

        val keyPair = CertificateBuilder.generateKeyPair(params)
        if (keyPair == null) {
            Logger.w("AttestKeyFailed: key pair generation failed")
            return null
        }

        val nspace = SecureRandom().nextLong()
        val keyDescriptor = KeyDescriptor().apply {
            domain = Domain.KEY_ID
            this.nspace = nspace
            alias = null
            blob = null
        }
        val metadata = Parcel.obtain().let { p ->
            val m = KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = keyDescriptor
                modificationTimeMs = System.currentTimeMillis()
                authorizations = buildAuthorizations(params, uid)
                certificate = null
                certificateChain = null
            }
            p.writeTypedObject(m, 0)
            p.setDataPosition(0)
            val normalized = p.readTypedObject(KeyMetadata.CREATOR) ?: m
            p.recycle()
            normalized
        }

        StateManager.store(StateManager.KeyEntry(
            uid = uid,
            alias = descriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = keyPair,
            securityLevel = securityLevel,
            securityLevelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = emptyList(),
        ))

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(metadata, 0)

        TeeLatencySimulator.simulateGenerateKeyDelay(params.algorithm, securityLevel, System.nanoTime() - startNanos)

        return TransactionResult.OverrideReply(override)
    }

    private fun tryGenerateSymmetricKey(
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
        uid: Int,
        startNanos: Long,
    ): TransactionResult? {
        Logger.i("tryGenerateSymmetricKey algo=${params.algorithm} keySize=${params.keySize} uid=$uid")

        val algoName = when (params.algorithm) {
            android.hardware.security.keymint.Algorithm.AES -> "AES"
            android.hardware.security.keymint.Algorithm.HMAC -> "HmacSHA256"
            else -> {
                Logger.w("SymmetricKeyGen: unsupported algorithm ${params.algorithm}")
                return null
            }
        }
        val keyGen = javax.crypto.KeyGenerator.getInstance(algoName)
        val keySize = if (params.keySize > 0) params.keySize else 128
        keyGen.init(keySize)
        val secretKey = keyGen.generateKey()

        val nspace = SecureRandom().nextLong()
        val keyDescriptor = KeyDescriptor().apply {
            domain = Domain.KEY_ID
            this.nspace = nspace
            alias = null
            blob = null
        }
        val metadata = Parcel.obtain().let { p ->
            val m = KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = keyDescriptor
                modificationTimeMs = System.currentTimeMillis()
                authorizations = buildAuthorizations(params, uid)
                certificate = null
                certificateChain = null
            }
            p.writeTypedObject(m, 0)
            p.setDataPosition(0)
            val normalized = p.readTypedObject(KeyMetadata.CREATOR) ?: m
            p.recycle()
            normalized
        }

        StateManager.store(StateManager.KeyEntry(
            uid = uid,
            alias = descriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = null,
            secretKey = secretKey,
            securityLevel = securityLevel,
            securityLevelBinder = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = emptyList(),
        ))

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(metadata, 0)

        TeeLatencySimulator.simulateGenerateKeyDelay(params.algorithm, securityLevel, System.nanoTime() - startNanos)

        return TransactionResult.OverrideReply(override)
    }
}
