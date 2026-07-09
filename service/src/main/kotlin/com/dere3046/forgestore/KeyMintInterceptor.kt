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

import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque

class KeyMintInterceptor(
    internal val originalBinder: IBinder,
    val securityLevel: Int,
) : BinderInterceptor() {

    val generatedKeys = ConcurrentHashMap<String, StateManager.KeyEntry>()
    val teeResponses = ConcurrentHashMap<StateManager.KeyIdentifier, KeyEntryResponse>()
    val patchedChains = ConcurrentHashMap<StateManager.KeyIdentifier, Array<Certificate>>()
    val attestationKeys = ConcurrentHashMap.newKeySet<StateManager.KeyIdentifier>()
    val importedKeys = ConcurrentHashMap.newKeySet<StateManager.KeyIdentifier>()
    val usageCounters = ConcurrentHashMap<StateManager.KeyIdentifier, java.util.concurrent.atomic.AtomicInteger>()
    val activeOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<SoftwareOperation>>()
    val recentOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<Long>>()
    val nspaceToAlias = ConcurrentHashMap<String, String>()
    val metadataCache = ConcurrentHashMap<String, KeyMetadata>()

    fun loadPersistedKeys(ksService: android.system.keystore2.IKeystoreService) {
        var count = 0
        for (lk in GeneratedKeyPersistence.loadAll(securityLevel)) {
            if (lk.metadata == null) continue
            val binder = try {
                ksService.getSecurityLevel(lk.securityLevel)
            } catch (_: Exception) { null }
            generatedKeys[key(lk.uid, lk.alias)] = StateManager.KeyEntry(
                uid = lk.uid,
                alias = lk.alias,
                nspace = lk.nspace,
                metadata = lk.metadata,
                keyPair = lk.keyPair,
                secretKey = lk.secretKey,
                securityLevel = lk.securityLevel,
                securityLevelBinder = binder,
                certChain = lk.certChain,
            )
            count++
        }
        if (count > 0) Logger.d("Loaded $count persisted keys (secLevel=$securityLevel)")
    }

    private fun enforceStrongBoxLimitThenContinue(uid: Int): TransactionResult {
        val isSb = securityLevel == android.hardware.security.keymint.SecurityLevel.STRONGBOX
        Logger.w("StrongBox: enforceSB uid=$uid secLev=$securityLevel isSB=$isSb keyNotInCache")
        if (!isSb) {
            return TransactionResult.Continue
        }
        val timestamps = recentOps.computeIfAbsent(uid) { ConcurrentLinkedDeque() }
        val cutoff = System.nanoTime() - 10_000_000_000L
        timestamps.removeIf { it < cutoff }
        if (timestamps.size >= 4) {
            Logger.w("StrongBox op limit reached for uid=$uid (${timestamps.size} ops in 10s window)")
            return replyKeymintError(-29) ?: TransactionResult.Skip
        }
        timestamps.addLast(System.nanoTime())
        Logger.w("StrongBox: op allowed for uid=$uid windowOps=${timestamps.size}")
        return TransactionResult.Continue
    }

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

        Logger.d("generateKey UID=$callingUid")

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
            Logger.w("Software generation failed (isAttestKey=${params.isAttestKey} challenge=${params.attestationChallenge != null}), falling back to HAL uid=$callingUid")
        }

        if (ConfigManager.shouldPatch(callingUid) && params.attestationChallenge != null) {
            Logger.d("Forwarding to HAL for PATCH mode")
            return TransactionResult.Continue
        }

        Logger.w("generateKey: no handler matched (shouldGenerate=${ConfigManager.shouldGenerate(callingUid)} shouldPatch=${ConfigManager.shouldPatch(callingUid)} isAttestKey=${params.isAttestKey} hasChallenge=${params.attestationChallenge != null}), forwarding to HAL for post-transact cache")
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
        if (resultCode != 0 || reply == null) {
            if (code == GENERATE_KEY_TRANSACTION) {
                Logger.w("PostGen: skipped resultCode=$resultCode reply=${reply != null} uid=$callingUid")
            }
            return TransactionResult.Skip
        }

        if (code == GENERATE_KEY_TRANSACTION) {
            Logger.w("PostGen: entering handlePostGenerateKey uid=$callingUid")
            return handlePostGenerateKey(callingUid, data, reply)
        }

        if (code == CREATE_OPERATION_TRANSACTION) {
            return handlePostCreateOperation(callingUid, data, reply, target)
        }

        if (code == IMPORT_KEY_TRANSACTION) {
            return handlePostImportKey(callingUid, data, reply)
        }

        return TransactionResult.Skip
    }

    private fun handlePostGenerateKey(callingUid: Int, data: Parcel, reply: Parcel): TransactionResult {
        try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return TransactionResult.Skip

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip
            val keyId = StateManager.KeyIdentifier(callingUid, keyDescriptor.alias ?: "")

            val originalChain = CertificateHelper.getCertificateChain(metadata)
            if (originalChain == null || originalChain.size <= 1) {
                cacheMetadataSnapshot(keyId, metadata)
                val levelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
                teeResponses[keyId] = KeyEntryResponse().apply {
                    this.metadata = metadata
                    iSecurityLevel = levelBinder
                }
                Logger.d("Cached teeResponse for non-attested/null-chain key alias=${keyDescriptor.alias}")
                return TransactionResult.Skip
            }

            if (!ConfigManager.shouldPatch(callingUid)) {
                val levelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
                teeResponses[keyId] = KeyEntryResponse().apply {
                    this.metadata = metadata
                    iSecurityLevel = levelBinder
                }
                Logger.d("Cached teeResponse for HAL key (non-patch) alias=${keyDescriptor.alias} uid=$callingUid chainSize=${originalChain.size}")
                return TransactionResult.Skip
            }

            Logger.d("PATCH mode post-generateKey for UID=$callingUid")
            cleanupKeyData(this, keyId)
            val patchedChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

            patchedChains[keyId] = patchedChain
            val levelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
            teeResponses[keyId] = KeyEntryResponse().apply {
                this.metadata = metadata
                iSecurityLevel = levelBinder
            }
            cacheMetadataSnapshot(keyId, metadata)
            Logger.d("Cached patched chain + teeResponse for alias=${keyDescriptor.alias}")

            CertificateHelper.updateCertificateChain(callingUid, metadata, patchedChain)
                .onFailure { e -> Logger.e("updateCertificateChain failed", e) }
            metadata.authorizations = AttestationPatcher.patchAuthorizations(metadata.authorizations, callingUid)

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(metadata, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            val alias = runCatching {
                val savedPos = data.dataPosition()
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val desc = data.readTypedObject(KeyDescriptor.CREATOR)
                data.setDataPosition(savedPos)
                desc?.alias
            }.getOrNull() ?: "<unknown>"
            Logger.w("PostGen failed uid=$callingUid alias=$alias msg=${e.message?.take(60)}")
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
            Logger.d("Post createOperation: UID=$uid operationChallenge=${response.operationChallenge != null} iOperation=${response.iOperation != null}")

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

    private fun handlePostImportKey(uid: Int, data: Parcel, reply: Parcel): TransactionResult {
        if (hasException(reply)) return TransactionResult.Skip
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Skip
            val alias = keyDescriptor.alias ?: return TransactionResult.Skip
            val keyId = StateManager.KeyIdentifier(uid, alias)
            if (generatedKeys.containsKey(key(keyId.uid, keyId.alias))) {
                Logger.d("importKey alias=$alias UID=$uid → cleaning up generated key")
                cleanupKeyData(this, keyId)
            }
            importedKeys.add(keyId)

            if (!ConfigManager.shouldPatch(uid)) return TransactionResult.Skip

            val savedReplyPos = reply.dataPosition()
            try {
                reply.setDataPosition(0)
                val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return TransactionResult.Skip
                val originalChain = CertificateHelper.getCertificateChain(metadata)
                if (originalChain != null && originalChain.size > 1) {
                    val newChain = AttestationPatcher.patchCertificateChain(originalChain, uid)
                    CertificateHelper.updateCertificateChain(uid, metadata, newChain).getOrThrow()
                    metadata.authorizations = AttestationPatcher.patchAuthorizations(metadata.authorizations, uid)
                    patchedChains[keyId] = newChain
                    val levelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder)
                    teeResponses[keyId] = KeyEntryResponse().apply {
                        this.metadata = metadata
                        iSecurityLevel = levelBinder
                    }
                    Logger.d("Cached patched chain + teeResponse for imported key alias=$alias")

                    val override = Parcel.obtain()
                    override.writeNoException()
                    override.writeTypedObject(metadata, 0)
                    return TransactionResult.OverrideReply(override)
                }
            } finally {
                reply.setDataPosition(savedReplyPos)
            }
        } catch (_: Exception) {}
        return TransactionResult.Skip
    }

    private fun handleCreateOperation(
        txId: Long,
        uid: Int,
        data: Parcel,
    ): TransactionResult {
        if (securityLevel == android.hardware.security.keymint.SecurityLevel.STRONGBOX) {
            Logger.w("StrongBox: handleCreateOp uid=$uid txId=$txId")
        }
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue

            val entry = lookupByAliasOrDomain(uid, keyDescriptor)
                ?: return enforceStrongBoxLimitThenContinue(uid)

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

            Logger.d("createOperation for generated key alias=${entry.alias} nspace=${keyDescriptor.nspace} algo=${parsedParams.algorithm} purpose=${parsedParams.purpose.firstOrNull()} secLevel=$securityLevel")

            val maxUsage = keyParams.maxUsesPerBoot
            val keyId = StateManager.KeyIdentifier(uid, entry.alias)
            if (maxUsage != null && maxUsage > 0) {
                val counter = usageCounters.computeIfAbsent(keyId) {
                    java.util.concurrent.atomic.AtomicInteger(maxUsage)
                }
                if (counter.get() <= 0) {
                    Logger.d("createOperation: usage count exhausted for alias=${entry.alias}")
                    return replyKeymintError(7) ?: TransactionResult.Skip
                }
            }

            val operation = SoftwareOperation(txId, entry.keyPair, entry.secretKey, parsedParams, securityLevel, uid)
            if (maxUsage != null && maxUsage > 0) {
                val counter = usageCounters[keyId] ?: usageCounters.computeIfAbsent(keyId) {
                    java.util.concurrent.atomic.AtomicInteger(maxUsage)
                }
                operation.onFinishCallback = {
                    if (counter.decrementAndGet() <= 0) {
                        Logger.d("createOperation: usage count exhausted alias=${entry.alias}")
                    }
                }
            }
            if (securityLevel == android.hardware.security.keymint.SecurityLevel.STRONGBOX &&
                countActiveOps(uid) >= getOpLimit(securityLevel)) {
                Logger.w("createOperation: StrongBox op limit reached uid=$uid active=${countActiveOps(uid)}")
                return replyKeymintError(-29) ?: TransactionResult.Skip
            }
            acquireOp(uid, operation, securityLevel)
            val binder = SoftwareOperationBinder(operation)
            val response = CreateOperationResponse().apply {
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

        fun hasException(reply: Parcel): Boolean {
            val savedPos = reply.dataPosition()
            reply.setDataPosition(0)
            val hasEx = runCatching { reply.readException() }.isFailure
            reply.setDataPosition(savedPos)
            return hasEx
        }

        fun findGeneratedKeyByKeyId(interceptor: KeyMintInterceptor, uid: Int, nspace: Long?): StateManager.KeyEntry? {
            if (nspace == null || nspace == 0L) return null
            return interceptor.generatedKeys.values.find { it.uid == uid && it.nspace == nspace }
        }

        fun findTeeResponseByKeyId(interceptor: KeyMintInterceptor, uid: Int, nspace: Long?): KeyEntryResponse? {
            if (nspace == null || nspace == 0L) return null
            return interceptor.teeResponses.entries.find { it.key.uid == uid && it.value.metadata?.key?.nspace == nspace }?.value
        }

        fun getGeneratedKeyResponse(interceptor: KeyMintInterceptor, keyId: StateManager.KeyIdentifier): KeyEntryResponse? {
            val entry = interceptor.generatedKeys["${keyId.uid}:${keyId.alias}"]
            if (entry != null) {
                val binder = entry.securityLevelBinder ?: return null
                return KeyEntryResponse().apply {
                    metadata = entry.metadata
                    iSecurityLevel = binder
                }
            }
            return interceptor.teeResponses[keyId]
        }

        fun ownsKeyResponse(interceptor: KeyMintInterceptor, keyId: StateManager.KeyIdentifier): Boolean {
            return interceptor.generatedKeys.containsKey("${keyId.uid}:${keyId.alias}") || interceptor.teeResponses.containsKey(keyId)
        }

        fun cleanupKeyData(interceptor: KeyMintInterceptor, keyId: StateManager.KeyIdentifier) {
            purgeGrantsForKey(interceptor, keyId)
            if (interceptor.generatedKeys.remove("${keyId.uid}:${keyId.alias}") != null) GeneratedKeyPersistence.remove(keyId.uid, keyId.alias)
            interceptor.teeResponses.remove(keyId)
            interceptor.patchedChains.remove(keyId)
            interceptor.attestationKeys.remove(keyId)
            interceptor.importedKeys.remove(keyId)
            interceptor.usageCounters.remove(keyId)
        }

        fun purgeGrantsForKey(interceptor: KeyMintInterceptor, keyId: StateManager.KeyIdentifier) {
            StateManager.purgeGrants(keyId)
        }

        fun getPatchedChain(interceptor: KeyMintInterceptor, keyId: StateManager.KeyIdentifier): Array<Certificate>? {
            return interceptor.patchedChains[keyId]
        }
    }

    private fun key(uid: Int, alias: String) = "$uid:$alias"

    private fun isKnownAttestationKey(uid: Int, descriptor: KeyDescriptor): Boolean {
        return generatedKeys.values.find { it.uid == uid && it.nspace == descriptor.nspace } != null ||
            (descriptor.alias != null && generatedKeys[key(uid, descriptor.alias)] != null)
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
                Logger.d("importKey alias=$alias UID=$uid → forwarding to HAL, will cleanup on success")
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
        Logger.d("tryGenerateSoftwareKey algo=${params.algorithm} keySize=${params.keySize} ecCurve=${params.ecCurve} uid=$uid")

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
            val entry = attestKeyDescriptor.alias?.let { generatedKeys[key(uid, it)] }
                ?: generatedKeys.values.find { it.uid == uid && it.nspace == attestKeyDescriptor.nspace }
            if (entry == null) {
                Logger.w("GenKeyFailed: attest key not found " +
                    "alias=${attestKeyDescriptor.alias} nspace=${attestKeyDescriptor.nspace}")
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
            keybox != null && keybox.certificates.isNotEmpty() -> {
                val sameAlgo = keybox.keyPair.private.algorithm == keyPair.private.algorithm
                if (!ConfigManager.isFallbackEnabled || sameAlgo) {
                    CertificateBuilder.generateCertificateChain(
                        keyPair, keybox, params, uid, securityLevel,
                        signerKeyPair, attestKeyCert,
                    ).also { Logger.d("Software gen: using keybox chain for UID=$uid") }
                } else {
                    Logger.w("keybox algorithm mismatch, using self-signed for UID=$uid")
                    CertificateBuilder.generateFallbackChain(keyPair, params, uid, securityLevel)
                }
            }
            ConfigManager.isFallbackEnabled -> {
                Logger.w("keybox empty, using self-signed for UID=$uid")
                CertificateBuilder.generateFallbackChain(keyPair, params, uid, securityLevel)
            }
            else -> {
                Logger.w("no keybox configured or fallback disabled, falling back to HAL for UID=$uid")
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

        val kId = key(uid, originalDescriptor.alias ?: "")
        generatedKeys[kId] = StateManager.KeyEntry(
            uid = uid,
            alias = originalDescriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = keyPair,
            securityLevel = securityLevel,
            securityLevelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = chain.map { it as X509Certificate },
        )
        GeneratedKeyPersistence.store(generatedKeys[kId]!!)

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
        Logger.d("tryGenerateAttestKey algo=${params.algorithm} uid=$uid")

        val keyPair = CertificateBuilder.generateKeyPair(params)
        if (keyPair == null) {
            Logger.w("AttestKeyFailed: key pair generation failed")
            return null
        }

        val keybox = KeyboxReader.loadKeybox(params.algorithm)
        val chain = when {
            keybox != null && keybox.certificates.isNotEmpty() -> {
                val sameAlgo = keybox.keyPair.private.algorithm == keyPair.private.algorithm
                if (!ConfigManager.isFallbackEnabled || sameAlgo) {
                    CertificateBuilder.generateCertificateChain(keyPair, keybox, params, uid, securityLevel)
                } else {
                    CertificateBuilder.generateFallbackChain(keyPair, params, uid, securityLevel)
                }
            }
            ConfigManager.isFallbackEnabled ->
                CertificateBuilder.generateFallbackChain(keyPair, params, uid, securityLevel)
            else -> {
                Logger.w("no keybox configured for attest key, falling back to HAL")
                null
            }
        }
        if (chain == null) return null

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

        val kId = key(uid, descriptor.alias ?: "")
        generatedKeys[kId] = StateManager.KeyEntry(
            uid = uid,
            alias = descriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = keyPair,
            securityLevel = securityLevel,
            securityLevelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = chain.map { it as X509Certificate },
        )
        GeneratedKeyPersistence.store(generatedKeys[kId]!!)

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
        Logger.d("tryGenerateSymmetricKey algo=${params.algorithm} keySize=${params.keySize} uid=$uid")

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

        val kId = key(uid, descriptor.alias ?: "")
        generatedKeys[kId] = StateManager.KeyEntry(
            uid = uid,
            alias = descriptor.alias ?: "",
            nspace = nspace,
            metadata = metadata,
            keyPair = null,
            secretKey = secretKey,
            securityLevel = securityLevel,
            securityLevelBinder = IKeystoreSecurityLevel.Stub.asInterface(originalBinder),
            certChain = emptyList(),
        )
        GeneratedKeyPersistence.store(generatedKeys[kId]!!)

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(metadata, 0)

        TeeLatencySimulator.simulateGenerateKeyDelay(params.algorithm, securityLevel, System.nanoTime() - startNanos)

        return TransactionResult.OverrideReply(override)
    }

    private fun countActiveOps(uid: Int): Int = activeOps[uid]?.count { !it.finalized } ?: 0

    private fun getOpLimit(secLevel: Int): Int =
        if (secLevel == android.hardware.security.keymint.SecurityLevel.STRONGBOX) 4 else 15

    private fun acquireOp(uid: Int, operation: SoftwareOperation, secLevel: Int) {
        val maxOps = getOpLimit(secLevel)
        val ops = activeOps.computeIfAbsent(uid) { ConcurrentLinkedDeque() }
        ops.removeIf { it.finalized }
        while (ops.size >= maxOps) {
            val oldest = ops.pollFirst() ?: break
            if (!oldest.finalized) {
                Logger.w("LRU: aborting oldest unfinished op for uid=$uid (active=${ops.size}/$maxOps)")
                oldest.abort()
            }
        }
        ops.addLast(operation)
    }

    private fun lookupByAliasOrDomain(uid: Int, descriptor: KeyDescriptor): StateManager.KeyEntry? {
        return when (descriptor.domain) {
            Domain.KEY_ID -> generatedKeys.values.find { it.uid == uid && it.nspace == descriptor.nspace }
            Domain.APP -> descriptor.alias?.let { generatedKeys[key(uid, it)] }
            else -> null
        }
    }

    private fun cacheMetadataSnapshot(keyId: StateManager.KeyIdentifier, metadata: KeyMetadata) {
        val nspace = metadata.key?.nspace ?: return
        metadataCache[key(keyId.uid, keyId.alias)] = metadata
        nspaceToAlias[key(uid = keyId.uid, alias = nspace.toString())] = keyId.alias
        Logger.d("Cached metadata snapshot for ${keyId.alias} nspace=$nspace")
    }

    private fun lookupMetadataByNspace(uid: Int, nspace: Long): KeyMetadata? {
        val entryKey = nspaceToAlias[key(uid, nspace.toString())]
            ?: return metadataCache.values.find {
                it.key?.nspace == nspace && it.key?.domain == Domain.KEY_ID
            }
        return metadataCache[key(uid, entryKey)]
    }
}
