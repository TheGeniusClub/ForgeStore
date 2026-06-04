package com.dere3046.forgemint

import android.os.Binder
import android.os.Parcel
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey

class SoftwareOperation(
    private val keyPair: KeyPair,
    private val nspace: Long,
    private val alias: String,
    private val uid: Int,
    private val params: KeyMintAttestation? = null,
) : Binder() {

    private var canceled = false
    private var signer: Signature? = null
    private var finished = false

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        if (canceled) return false
        return try {
            when (code) {
                UPDATE_OPERATION_CODE -> handleUpdate(data, reply)
                FINISH_OPERATION_CODE -> handleFinish(data, reply)
                ABORT_OPERATION_CODE -> handleAbort(reply)
                UPDATE_AAD_CODE -> handleUpdateAad(data, reply)
                else -> super.onTransact(code, data, reply, flags)
            }
        } catch (e: Exception) {
            Logger.e("SoftwareOperation error alias=$alias", e)
            reply?.let { it.writeInt(-38); it.writeString(e.message) }
            true
        }
    }

    private fun handleUpdate(data: Parcel, reply: Parcel?): Boolean {
        val input = readByteArray(data)
        if (input != null) {
            val sig = getOrCreateSigner()
            sig.update(input)
        }
        reply?.writeInt(0)
        return true
    }

    private fun handleFinish(data: Parcel, reply: Parcel?): Boolean {
        val input = readByteArray(data)
        readByteArray(data) // signature (for verify operations, ignored for sign)

        if (finished) {
            reply?.writeInt(0)
            reply?.writeByteArray(ByteArray(0))
            return true
        }
        finished = true

        val sig = getOrCreateSigner()
        if (input != null) sig.update(input)
        val result = sig.sign()

        reply?.writeInt(0)
        reply?.writeInt(result.size)
        reply?.writeByteArray(result)
        return true
    }

    private fun handleAbort(reply: Parcel?): Boolean {
        canceled = true
        reply?.writeInt(0)
        return true
    }

    private fun handleUpdateAad(data: Parcel, reply: Parcel?): Boolean {
        readByteArray(data)
        reply?.writeInt(0)
        return true
    }

    private fun getOrCreateSigner(): Signature {
        if (signer != null) return signer!!
        val algorithm = getSignatureAlgorithm()
        val sig = Signature.getInstance(algorithm)
        sig.initSign(keyPair.private)
        signer = sig
        return sig
    }

    private fun getSignatureAlgorithm(): String {
        val p = params
        val digest = if (p != null && p.digest.isNotEmpty()) {
            when (p.digest.first()) {
                2 -> "SHA224"
                3 -> "SHA256"
                4 -> "SHA384"
                5 -> "SHA512"
                else -> "SHA256"
            }
        } else "SHA256"
        val keyAlgo = when (keyPair.private) {
            is ECKey -> "ECDSA"
            is RSAKey -> "RSA"
            else -> "ECDSA"
        }
        return "$digest${if (keyAlgo == "ECDSA") "withECDSA" else "withRSA"}"
    }

    private fun readByteArray(data: Parcel): ByteArray? {
        val len = data.readInt()
        if (len < 0) return null
        val arr = ByteArray(len)
        data.readByteArray(arr)
        return arr
    }

    companion object {
        val UPDATE_OPERATION_CODE: Int by lazy { resolveCode("TRANSACTION_update") }
        val FINISH_OPERATION_CODE: Int by lazy { resolveCode("TRANSACTION_finish") }
        val ABORT_OPERATION_CODE: Int by lazy { resolveCode("TRANSACTION_abort") }
        val UPDATE_AAD_CODE: Int by lazy { resolveCode("TRANSACTION_updateAad") }

        private fun resolveCode(name: String): Int {
            return try {
                android.system.keystore2.IKeystoreOperation.Stub::class.java
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
