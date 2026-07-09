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

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.RemoteException
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

internal object KeystoreErrorCodes {
    val invalidTag: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INVALID_TAG", -76) }
    val invalidOperationHandle: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INVALID_OPERATION_HANDLE", -28) }
    val verificationFailed: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "VERIFICATION_FAILED", -30) }
    val invalidArgument: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INVALID_ARGUMENT", -38) }
    val invalidInputLength: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INVALID_INPUT_LENGTH", -21) }
    val incompatibleKey: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_KEY", -31) }
    val incompatiblePurpose: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_PURPOSE", -13) }
    val unsupportedPurpose: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "UNSUPPORTED_PURPOSE", -14) }
    val incompatibleAlgorithm: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_ALGORITHM", -18) }
    val keyNotYetValid: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "KEY_NOT_YET_VALID", -39) }
    val keyExpired: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "KEY_EXPIRED", -40) }
    val callerNonceProhibited: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "CALLER_NONCE_PROHIBITED", -55) }
    val tooMuchData: Int by lazy { resolve("android.system.keystore2.ResponseCode", "TOO_MUCH_DATA", 21) }
    val unknownError: Int by lazy { resolve("android.hardware.security.keymint.ErrorCode", "UNKNOWN_ERROR", -1000) }

    private fun resolve(className: String, fieldName: String, fallback: Int): Int {
        return try {
            Class.forName(className).getField(fieldName).getInt(null)
        } catch (_: Exception) { fallback }
    }
}

private sealed interface CryptoPrimitive {
    fun updateAad(aadInput: ByteArray?) {
        throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
    }
    fun update(data: ByteArray?): ByteArray?
    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
    fun abort()
    fun getBeginParameters(): Array<KeyParameter>? = null
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
            Algorithm.RSA -> {
                if (params.padding.firstOrNull() == PaddingMode.RSA_PSS) "RSA/PSS"
                else "RSA"
            }
            else -> throw ServiceSpecificException(
                KeystoreErrorCodes.incompatibleAlgorithm,
                "Unsupported signature algorithm: ${params.algorithm}",
            )
        }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo = when (params.algorithm) {
            Algorithm.RSA -> "RSA"
            Algorithm.AES -> "AES"
            else -> throw ServiceSpecificException(
                KeystoreErrorCodes.incompatibleAlgorithm,
                "Unsupported cipher algorithm: ${params.algorithm}",
            )
        }
        val blockMode = when (params.blockMode.firstOrNull()) {
            BlockMode.ECB -> "ECB"
            BlockMode.CBC -> "CBC"
            BlockMode.GCM -> "GCM"
            BlockMode.CTR -> "CTR"
            else -> "ECB"
        }
        val padding = when (params.padding.firstOrNull()) {
            PaddingMode.NONE -> "NoPadding"
            PaddingMode.PKCS7 -> "PKCS7Padding"
            PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
            PaddingMode.RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
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
        if (signature == null) throw ServiceSpecificException(
            KeystoreErrorCodes.verificationFailed, "Signature to verify is null",
        )
        if (!this.signature.verify(signature)) {
            throw ServiceSpecificException(KeystoreErrorCodes.verificationFailed, "Signature verification failed")
        }
        return null
    }

    override fun abort() {}
}

private class CipherPrimitive(
    cryptoKey: Key,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val isAead = params.blockMode.firstOrNull() == BlockMode.GCM
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val nonce = params.nonce
            if (nonce != null && isAead) {
                init(opMode, cryptoKey, GCMParameterSpec(128, nonce))
            } else if (nonce != null) {
                init(opMode, cryptoKey, IvParameterSpec(nonce))
            } else {
                init(opMode, cryptoKey)
            }
        }

    override fun updateAad(aadInput: ByteArray?) {
        if (!isAead) throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
        if (aadInput != null) cipher.updateAAD(aadInput)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}

    override fun getBeginParameters(): Array<KeyParameter>? {
        val iv = cipher.iv ?: return null
        return arrayOf(KeyParameter().apply {
            tag = Tag.NONCE
            value = KeyParameterValue().apply { blob = iv }
        })
    }
}

private class KeyAgreementPrimitive(keyPair: KeyPair) : CryptoPrimitive {
    private val agreement: javax.crypto.KeyAgreement =
        javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(keyPair.private) }

    override fun update(data: ByteArray?): ByteArray? = null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data == null) throw ServiceSpecificException(
            KeystoreErrorCodes.invalidArgument, "Peer public key required for key agreement",
        )
        val peerKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(data))
        agreement.doPhase(peerKey, true)
        return agreement.generateSecret()
    }

    override fun abort() {}
}

private class MacPrimitive(private val mac: javax.crypto.Mac) : CryptoPrimitive {
    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) mac.update(data)
        return mac.doFinal()
    }

    override fun abort() {}
}

private class MacVerifier(private val mac: javax.crypto.Mac) : CryptoPrimitive {
    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        if (signature == null) throw ServiceSpecificException(
            KeystoreErrorCodes.verificationFailed, "Signature to verify is null",
        )
        if (!mac.doFinal().contentEquals(signature)) {
            throw ServiceSpecificException(KeystoreErrorCodes.verificationFailed, "MAC verification failed")
        }
        return null
    }

    override fun abort() {}
}

class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair?,
    private val secretKey: javax.crypto.SecretKey? = null,
    params: KeyMintAttestation,
    private val securityLevel: Int,
    private val uid: Int,
) {
    private val primitive: CryptoPrimitive

    @Volatile var finalized = false
        private set

    @Volatile var onFinishCallback: (() -> Unit)? = null

    private val latencyFloorMs: Long = when (params.algorithm) {
        Algorithm.EC -> 20L
        Algorithm.RSA -> 70L
        Algorithm.AES -> 35L
        else -> 20L
    }

    init {
        val purpose = params.purpose.firstOrNull()
            ?: throw ServiceSpecificException(KeystoreErrorCodes.unsupportedPurpose, "No purpose specified")
        Logger.d("SoftwareOperation txId=$txId purpose=$purpose")
        primitive = when (purpose) {
            KeyPurpose.SIGN -> {
                if (secretKey != null) {
                    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                    mac.init(secretKey)
                    MacPrimitive(mac)
                } else {
                    val kp = keyPair ?: throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument, "No key pair for SIGN")
                    Signer(kp, params)
                }
            }
            KeyPurpose.VERIFY -> {
                if (secretKey != null) {
                    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                    mac.init(secretKey)
                    MacVerifier(mac)
                } else {
                    val kp = keyPair ?: throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument, "No key pair for VERIFY")
                    Verifier(kp, params)
                }
            }
            KeyPurpose.ENCRYPT -> {
                val key: java.security.Key = secretKey ?: keyPair?.public
                    ?: throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument, "No key for ENCRYPT")
                CipherPrimitive(key, params, Cipher.ENCRYPT_MODE)
            }
            KeyPurpose.DECRYPT -> {
                val key: java.security.Key = secretKey ?: keyPair?.private
                    ?: throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument, "No key for DECRYPT")
                CipherPrimitive(key, params, Cipher.DECRYPT_MODE)
            }
            KeyPurpose.AGREE_KEY -> {
                val kp = keyPair ?: throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument, "No key pair for AGREE_KEY")
                KeyAgreementPrimitive(kp)
            }
            else -> throw ServiceSpecificException(
                KeystoreErrorCodes.unsupportedPurpose, "Unsupported operation purpose: $purpose",
            )
        }
    }

    val beginParameters: KeyParameters?
        get() {
            val params = primitive.getBeginParameters() ?: return null
            if (params.isEmpty()) return null
            return KeyParameters().apply { keyParameter = params }
        }

    fun update(data: ByteArray?): ByteArray? {
        checkActive()
        checkInputLength(data)
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            Logger.e("SoftwareOperation update error txId=$txId", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        checkInputLength(data)
        val start = System.nanoTime()
        try {
            val result = primitive.finish(data, signature)
            finalized = true
            Logger.d("SoftwareOperation finish txId=$txId OK")
            return result
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            Logger.e("SoftwareOperation finish error txId=$txId", e)
            throw mapToServiceSpecificException(e)
        } finally {
            if (finalized) {
                onFinishCallback?.invoke()
                applyLatency(start)
            }
        }
    }

    fun abort() {
        if (finalized) return
        finalized = true
        primitive.abort()
        Logger.d("SoftwareOperation abort txId=$txId")
    }

    fun updateAad(input: ByteArray?) {
        checkActive()
        checkInputLength(input)
        try {
            primitive.updateAad(input)
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            Logger.e("SoftwareOperation updateAad error txId=$txId", e)
            throw mapToServiceSpecificException(e)
        }
    }

    private fun checkActive() {
        if (finalized) throw ServiceSpecificException(KeystoreErrorCodes.invalidOperationHandle)
    }

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > 0x8000) throw ServiceSpecificException(KeystoreErrorCodes.tooMuchData)
    }

    private fun applyLatency(startNanos: Long) {
        val elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L
        val remainingMs = latencyFloorMs - elapsedMs
        if (remainingMs > 1) {
            java.util.concurrent.locks.LockSupport.parkNanos(remainingMs * 1_000_000)
        }
    }

    companion object {
        private fun mapToServiceSpecificException(e: Exception): ServiceSpecificException = when (e) {
            is SignatureException -> ServiceSpecificException(KeystoreErrorCodes.verificationFailed, e.message)
            is javax.crypto.BadPaddingException -> ServiceSpecificException(KeystoreErrorCodes.invalidArgument, e.message)
            is javax.crypto.IllegalBlockSizeException -> ServiceSpecificException(KeystoreErrorCodes.invalidInputLength, e.message)
            is java.security.InvalidKeyException -> ServiceSpecificException(KeystoreErrorCodes.incompatibleKey, e.message)
            else -> ServiceSpecificException(KeystoreErrorCodes.unknownError, e.message)
        }
    }
}

class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Synchronized
    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? = operation.update(input)

    @Synchronized
    @Throws(RemoteException::class)
    override fun updateAad(input: ByteArray?) {
        operation.updateAad(input)
    }

    @Synchronized
    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? = operation.finish(input, signature)

    @Synchronized
    @Throws(RemoteException::class)
    override fun abort() = operation.abort()
}
