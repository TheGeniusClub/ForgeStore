package com.dere3046.forgemint

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher

private sealed interface CryptoPrimitive {
    fun update(data: ByteArray?): ByteArray?
    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
    fun abort()
}

private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest = when (params.digest.firstOrNull()) {
            Digest.SHA_2_256 -> "SHA256"
            Digest.SHA_2_384 -> "SHA384"
            Digest.SHA_2_512 -> "SHA512"
            else -> "NONE"
        }
        val keyAlgo = when (params.algorithm) {
            Algorithm.EC -> "ECDSA"
            Algorithm.RSA -> "RSA"
            else -> throw IllegalArgumentException("Unsupported signature algorithm: ${params.algorithm}")
        }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo = when (params.algorithm) {
            Algorithm.RSA -> "RSA"
            Algorithm.AES -> "AES"
            else -> throw IllegalArgumentException("Unsupported cipher algorithm: ${params.algorithm}")
        }
        val blockMode = when (params.blockMode.firstOrNull()) {
            BlockMode.ECB -> "ECB"
            BlockMode.CBC -> "CBC"
            BlockMode.GCM -> "GCM"
            else -> "ECB"
        }
        val padding = when (params.padding.firstOrNull()) {
            PaddingMode.NONE -> "NoPadding"
            PaddingMode.PKCS7 -> "PKCS7Padding"
            PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
            PaddingMode.RSA_OAEP -> "OAEPPadding"
            else -> "NoPadding"
        }
        return "$keyAlgo/$blockMode/$padding"
    }
}

private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) throw SignatureException("Signature to verify is null")
        if (!this.signature.verify(signature)) {
            throw SignatureException("Signature verification failed")
        }
        return null
    }

    override fun abort() {}
}

private class CipherPrimitive(
    keyPair: KeyPair,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair.public else keyPair.private
            init(opMode, key)
        }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}
}

class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair,
    params: KeyMintAttestation,
    private val securityLevel: Int,
) {
    private val primitive: CryptoPrimitive

    private val latencyFloorMs: Long = when (params.algorithm) {
        android.hardware.security.keymint.Algorithm.EC -> 20L
        android.hardware.security.keymint.Algorithm.RSA -> 70L
        android.hardware.security.keymint.Algorithm.AES -> 35L
        else -> 20L
    }

    init {
        val purpose = params.purpose.firstOrNull() ?: throw UnsupportedOperationException("No purpose specified")
        Logger.d("SoftwareOperation txId=$txId purpose=$purpose")
        primitive = when (purpose) {
            KeyPurpose.SIGN -> Signer(keyPair, params)
            KeyPurpose.VERIFY -> Verifier(keyPair, params)
            KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
            KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
            else -> throw UnsupportedOperationException("Unsupported operation purpose: $purpose")
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        try {
            return primitive.update(data)
        } catch (e: Exception) {
            Logger.e("SoftwareOperation update error txId=$txId", e)
            throw e
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        val start = System.nanoTime()
        try {
            val result = primitive.finish(data, signature)
            Logger.i("SoftwareOperation finish txId=$txId OK")
            return result
        } catch (e: Exception) {
            Logger.e("SoftwareOperation finish error txId=$txId", e)
            throw e
        } finally {
            applyLatency(start)
        }
    }

    fun abort() {
        primitive.abort()
        Logger.d("SoftwareOperation abort txId=$txId")
    }

    private fun applyLatency(startNanos: Long) {
        val elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L
        val remainingMs = latencyFloorMs - elapsedMs
        if (remainingMs > 1) {
            Thread.sleep(remainingMs)
        }
    }
}

class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Throws(RemoteException::class)
    override fun updateAad(input: ByteArray?): Int {
        return 0
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Throws(RemoteException::class)
    override fun abort() {
        operation.abort()
    }
}
