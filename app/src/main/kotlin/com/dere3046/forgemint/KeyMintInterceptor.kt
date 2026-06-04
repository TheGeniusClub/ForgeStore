package com.dere3046.forgemint

import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
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

        if (code != GENERATE_KEY_TRANSACTION) {
            return TransactionResult.ContinueAndSkipPost
        }

        Logger.i("generateKey UID=$callingUid")

        if (ConfigManager.shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }

        val genParams = parseParams(data) ?: return TransactionResult.Continue
        val params = genParams.attestation
        if (!params.isAttestKey) {
            Logger.d("Not attestation key, forwarding to HAL")
            return TransactionResult.ContinueAndSkipPost
        }

        if (ConfigManager.shouldGenerate(callingUid)) {
            val result = tryGenerateSoftwareKey(params, genParams.descriptor, genParams.attestationKeyDescriptor, callingUid)
            if (result != null) {
                Logger.i("Software key generated for UID=$callingUid")
                return result
            }
            Logger.w("Software generation failed, falling back to HAL")
        }

        Logger.i("Forwarding to HAL for PATCH mode")
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
            return handlePostGenerateKey(callingUid, reply)
        }

        if (code == CREATE_OPERATION_TRANSACTION) {
            return handlePostCreateOperation(callingUid, data, reply, target)
        }

        return TransactionResult.Skip
    }

    private fun handlePostGenerateKey(callingUid: Int, reply: Parcel): TransactionResult {
        if (!ConfigManager.shouldPatch(callingUid)) return TransactionResult.Skip

        Logger.i("Post-transact patching cert chain for UID=$callingUid")

        val keybox = KeyboxReader.loadKeybox() ?: return TransactionResult.Skip
        if (keybox.certificates.isEmpty()) return TransactionResult.Skip

        try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return TransactionResult.Skip

            metadata.certificate = keybox.certificates[0].encoded
            if (keybox.certificates.size > 1) {
                metadata.certificateChain = keybox.certificates.drop(1)
                    .flatMap { it.encoded.toList() }
                    .toByteArray()
            }

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedObject(metadata, 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("Post-transact patch failed", e)
            return TransactionResult.Skip
        }
    }

    private fun handlePostCreateOperation(uid: Int, data: Parcel, reply: Parcel, target: IBinder): TransactionResult {
        try {
            data.readInt()
            data.readString()
            data.readTypedObject(KeyDescriptor.CREATOR)
            data.createTypedArray(KeyParameter.CREATOR)
            data.readBoolean()

            reply.readException()
            val response = reply.readTypedObject(CreateOperationResponse.CREATOR) ?: return TransactionResult.Skip

            response.iOperation?.let { op ->
                val opBinder = op.asBinder()
                val backdoor = BinderInterceptor.getBackdoor(target) ?: return@let
                OperationInterceptor.gBackdoorBinder = backdoor
                val interceptor = OperationInterceptor()
                BinderInterceptor.register(backdoor, opBinder, interceptor)
                Logger.i("Registered OperationInterceptor for UID=$uid")
            }
        } catch (e: Exception) {
            Logger.e("Post createOperation failed", e)
        }
        return TransactionResult.Skip
    }

    private fun handleCreateOperation(
        txId: Long,
        uid: Int,
        data: Parcel,
    ): TransactionResult {
        try {
            data.readInt()
            data.readString()
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            data.createTypedArray(KeyParameter.CREATOR) // skip params
            data.readBoolean() // skip forced

            val entry = StateManager.lookup(uid, keyDescriptor.alias ?: return TransactionResult.Continue)
                ?: StateManager.lookupByNspace(uid, keyDescriptor.nspace)
                ?: return TransactionResult.Continue

            Logger.i("createOperation for generated key alias=${entry.alias}")

            val operation = SoftwareOperation(entry.keyPair, entry.nspace, entry.alias, uid)
            val override = Parcel.obtain()
            override.writeNoException()
            override.writeStrongBinder(operation)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("createOperation failed", e)
            return TransactionResult.Continue
        }
    }

    private fun parseParams(data: Parcel): GenerateKeyParams? {
        return try {
            data.readInt()
            data.readString()
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return null
            val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return null
            data.readInt() // flags
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
        addAuth(Tag.OS_VERSION, securityLevel) { integer = osVersion() }
        addAuth(Tag.OS_PATCHLEVEL, securityLevel) { integer = parsePatchLevel(Build.VERSION.SECURITY_PATCH) }
        addAuth(Tag.VENDOR_PATCHLEVEL, securityLevel) { integer = parsePatchLevel(Build.VERSION.SECURITY_PATCH) }
        addAuth(Tag.BOOT_PATCHLEVEL, securityLevel) { integer = parsePatchLevel(Build.VERSION.SECURITY_PATCH) }
        addAuth(Tag.CREATION_DATETIME, securityLevel) { dateTime = System.currentTimeMillis() }

        return list.toTypedArray()
    }

    companion object {
        private fun osVersion(): Int = when (Build.VERSION.SDK_INT) {
            29 -> 100000
            30 -> 110000
            31 -> 120000
            32 -> 120100
            33 -> 130000
            34 -> 140000
            35 -> 150000
            36 -> 160000
            else -> 150000
        }

        private fun parsePatchLevel(patch: String?): Int {
            if (patch == null) return 20250605
            val digits = patch.replace("-", "")
            return digits.take(8).toIntOrNull() ?: 20250605
        }

        val GENERATE_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_generateKey") }
        val CREATE_OPERATION_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_createOperation") }

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

    private fun tryGenerateSoftwareKey(
        params: KeyMintAttestation,
        originalDescriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        uid: Int,
    ): TransactionResult? {
        val keybox = KeyboxReader.loadKeybox(params.algorithm) ?: return null
        if (keybox.certificates.isEmpty()) return null

        val signerKeyPair = if (attestKeyDescriptor != null) {
            val attestEntry = StateManager.lookup(uid, attestKeyDescriptor.alias ?: return null)
                ?: StateManager.lookupByNspace(uid, attestKeyDescriptor.nspace)
            attestEntry?.keyPair
        } else null

        val keyPair = CertificateBuilder.generateKeyPair(params) ?: return null

        val chain = CertificateBuilder.generateCertificateChain(
            keyPair, keybox, params, uid, securityLevel,
            signerKeyPair,
        ) ?: return null

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
            securityLevelBinder = this as IBinder,
            certChain = chain.map { it as X509Certificate },
        ))

        val override = Parcel.obtain()
        override.writeNoException()
        override.writeTypedObject(metadata, 0)
        return TransactionResult.OverrideReply(override)
    }
}
