package com.dere3046.forgemint

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
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
            val result = tryGenerateSoftwareKey(params, genParams.descriptor, callingUid)
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
        if (code != GENERATE_KEY_TRANSACTION || resultCode != 0 || reply == null) {
            return TransactionResult.Skip
        }
        if (!ConfigManager.shouldPatch(callingUid)) {
            return TransactionResult.Skip
        }

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
            data.readTypedObject(KeyDescriptor.CREATOR) // attestationKey (optional)
            val params = data.createTypedArray(KeyParameter.CREATOR) ?: return null
            data.readInt() // flags
            GenerateKeyParams(KeyMintAttestation(params), descriptor)
        } catch (e: Exception) {
            Logger.e("Failed to parse generateKey params", e)
            null
        }
    }

    private fun buildAuthorizations(params: KeyMintAttestation): Array<Authorization> {
        val list = mutableListOf<Authorization>()

        fun addAuth(tag: Int, value: KeyParameterValue.() -> Unit) {
            val kp = KeyParameter()
            kp.tag = tag
            kp.value = KeyParameterValue().apply(value)
            list.add(Authorization().apply { keyParameter = kp })
        }

        for (p in params.purpose) {
            addAuth(Tag.PURPOSE) { keyPurpose = p }
        }
        if (params.algorithm != 0) {
            addAuth(Tag.ALGORITHM) { algorithm = params.algorithm }
        }
        if (params.keySize > 0) {
            addAuth(Tag.KEY_SIZE) { integer = params.keySize }
        }
        for (d in params.digest) {
            addAuth(Tag.DIGEST) { digest = d }
        }
        if (params.ecCurve != null) {
            addAuth(Tag.EC_CURVE) { ecCurve = params.ecCurve }
        }
        if (params.rsaPublicExponent != null) {
            addAuth(Tag.RSA_PUBLIC_EXPONENT) { longInteger = params.rsaPublicExponent.toLong() }
        }

        return list.toTypedArray()
    }

    private fun tryGenerateSoftwareKey(
        params: KeyMintAttestation,
        originalDescriptor: KeyDescriptor,
        uid: Int,
    ): TransactionResult? {
        val keybox = KeyboxReader.loadKeybox() ?: return null
        if (keybox.certificates.isEmpty()) return null

        val keyPair = CertificateBuilder.generateKeyPair(params) ?: return null

        val chain = CertificateBuilder.generateCertificateChain(
            keyPair, keybox, params, uid, securityLevel,
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
            authorizations = buildAuthorizations(params)
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

    companion object {
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
}
