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

import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.security.Credentials
import android.security.KeyStore
import android.security.keymaster.ExportResult
import android.security.keymaster.KeyCharacteristics
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import android.security.keystore.IKeystoreCertificateChainCallback
import android.security.keystore.IKeystoreExportKeyCallback
import android.security.keystore.IKeystoreKeyCharacteristicsCallback
import android.security.keystore.IKeystoreService
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

class KeystoreInterceptor(
    private val ksBinder: IBinder,
    private val backdoor: IBinder,
) : BinderInterceptor() {

    private val transactionCodes: Map<Int, String> by lazy {
        mutableMapOf<Int, String>().apply {
            IKeystoreService.Stub::class.java.declaredFields.filter {
                it.type == Int::class.javaPrimitiveType && it.name.startsWith("TRANSACTION_")
            }.forEach { f ->
                f.isAccessible = true
                put(f.getInt(null), f.name.removePrefix("TRANSACTION_"))
            }
        }
    }

    private val generateKeyCode: Int by lazy { resolveCode("generateKey") }
    private val getKeyCharacteristicsCode: Int by lazy { resolveCode("getKeyCharacteristics") }
    private val exportKeyCode: Int by lazy { resolveCode("exportKey") }
    private val attestKeyCode: Int by lazy { resolveCode("attestKey") }
    private val getCode: Int by lazy { resolveCode("get") }

    private val keygenParams = ConcurrentHashMap<String, KeystoreOneKeygenParams>()
    private val generatedKeyPairs = ConcurrentHashMap<String, KeyPair>()
    private val patchedChainCache = ConcurrentHashMap<String, Array<Certificate>>()

    override fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
    ): TransactionResult {
        if (ConfigManager.shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }

        val txnName = transactionCodes[code] ?: return TransactionResult.Continue

        if (ConfigManager.shouldGenerate(callingUid)) {
            return when (code) {
                generateKeyCode -> handleGenerateKey(callingUid, data)
                getKeyCharacteristicsCode -> handleGetKeyCharacteristics(callingUid, data)
                exportKeyCode -> handleExportKey(callingUid, data)
                attestKeyCode -> handleAttestKey(callingUid, data)
                else -> TransactionResult.ContinueAndSkipPost
            }
        }

        if (ConfigManager.shouldPatch(callingUid) && code == getCode) {
            Logger.d("K1 preTr: get uid=$callingUid")
            return TransactionResult.Continue
        }

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
        reply: Parcel?, resultCode: Int,
    ): TransactionResult {
        if (resultCode != 0 || reply == null) return TransactionResult.Skip
        if (!ConfigManager.shouldPatch(callingUid)) return TransactionResult.Skip
        if (code != getCode) return TransactionResult.Skip

        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val alias = data.readString() ?: return TransactionResult.Skip
            val extractedAlias = extractAlias(alias)

            when {
                alias.startsWith(Credentials.USER_CERTIFICATE) -> {
                    Logger.d("K1 postTr: patch leaf cert alias=$extractedAlias")
                    val leafBytes = reply.createByteArray() ?: return TransactionResult.Skip
                    val leafCert = CertificateHelper.toCertificate(leafBytes)
                        ?: return TransactionResult.Skip
                    val newChain = AttestationPatcher.patchCertificateChain(
                        arrayOf(leafCert), callingUid
                    )
                    if (newChain.isNotEmpty() && newChain[0] !== leafCert) {
                        patchedChainCache[extractedAlias] = newChain.toList().toTypedArray()
                        val override = Parcel.obtain()
                        override.writeByteArray(newChain[0].encoded)
                        TransactionResult.OverrideReply(override)
                    } else {
                        TransactionResult.Skip
                    }
                }

                alias.startsWith(Credentials.CA_CERTIFICATE) -> {
                    Logger.d("K1 postTr: return cached CA chain alias=$extractedAlias")
                    val cachedChain = patchedChainCache.remove(extractedAlias)
                    if (cachedChain != null && cachedChain.size > 1) {
                        val caBytes = CertificateHelper.certificatesToByteArray(
                            cachedChain.drop(1)
                        )
                        val override = Parcel.obtain()
                        override.writeByteArray(caBytes)
                        TransactionResult.OverrideReply(override)
                    } else {
                        TransactionResult.Skip
                    }
                }

                else -> TransactionResult.Skip
            }
        } catch (e: Exception) {
            Logger.e("K1 postTr failed", e)
            TransactionResult.Skip
        }
    }

    private fun handleGenerateKey(uid: Int, data: Parcel): TransactionResult {
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val callbackBinder = data.readStrongBinder()
            val alias = extractAlias(data.readString() ?: return TransactionResult.Skip)
            val keymasterArgs = KeymasterArguments()
            if (data.readInt() == 1) {
                keymasterArgs.readFromParcel(data)
            }

            val params = KeystoreOneKeygenParams.fromKeymasterArguments(keymasterArgs)
            keygenParams[alias] = params

            val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(callbackBinder)
            val characteristics = KeyCharacteristics().apply {
                swEnforced = KeymasterArguments()
                hwEnforced = KeymasterArguments().apply {
                    addEnum(KeymasterDefs.KM_TAG_ALGORITHM, params.algorithm)
                }
            }
            callback.onFinished(successResponse(), characteristics)
            Logger.d("K1 generateKey alias=$alias algo=${params.algorithm}")

            replySuccess()
        } catch (e: Exception) {
            Logger.e("K1 generateKey failed", e)
            TransactionResult.ContinueAndSkipPost
        }
    }

    private fun handleGetKeyCharacteristics(uid: Int, data: Parcel): TransactionResult {
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val callbackBinder = data.readStrongBinder()
            val alias = extractAlias(data.readString() ?: return TransactionResult.Skip)
            val params = keygenParams[alias]
                ?: return TransactionResult.ContinueAndSkipPost

            val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(callbackBinder)
            val characteristics = KeyCharacteristics().apply {
                swEnforced = KeymasterArguments()
                hwEnforced = KeymasterArguments().apply {
                    addEnum(KeymasterDefs.KM_TAG_ALGORITHM, params.algorithm)
                }
            }
            callback.onFinished(successResponse(), characteristics)
            Logger.d("K1 getKeyChar alias=$alias")

            replySuccess()
        } catch (e: Exception) {
            Logger.e("K1 getKeyChar failed", e)
            TransactionResult.ContinueAndSkipPost
        }
    }

    private fun handleExportKey(uid: Int, data: Parcel): TransactionResult {
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val callbackBinder = data.readStrongBinder()
            val alias = extractAlias(data.readString() ?: return TransactionResult.Skip)
            val params = keygenParams[alias]
                ?: return TransactionResult.ContinueAndSkipPost

            val keyPair = generatedKeyPairs.getOrPut(alias) {
                CertificateBuilder.generateKeyPair(params.toKeyMintAttestation())
                    ?: throw IllegalStateException("Failed to generate software key pair for $alias")
            }

            val exportParcel = Parcel.obtain().apply {
                writeInt(KeyStore.NO_ERROR)
                writeByteArray(keyPair.public.encoded)
                setDataPosition(0)
            }
            val exportResult = ExportResult.CREATOR.createFromParcel(exportParcel)
            exportParcel.recycle()

            val callback = IKeystoreExportKeyCallback.Stub.asInterface(callbackBinder)
            callback.onFinished(exportResult)
            Logger.d("K1 exportKey alias=$alias")

            replySuccess()
        } catch (e: Exception) {
            Logger.e("K1 exportKey failed", e)
            TransactionResult.ContinueAndSkipPost
        }
    }

    private fun handleAttestKey(uid: Int, data: Parcel): TransactionResult {
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val callbackBinder = data.readStrongBinder()
            val alias = extractAlias(data.readString() ?: return TransactionResult.Skip)
            val params = keygenParams[alias]
                ?: return TransactionResult.ContinueAndSkipPost
            val keyPair = generatedKeyPairs[alias]
                ?: return TransactionResult.ContinueAndSkipPost

            val attestationArgs = KeymasterArguments()
            if (data.readInt() == 1) {
                attestationArgs.readFromParcel(data)
                params.attestationChallenge = attestationArgs.getBytes(
                    KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, ByteArray(0)
                )
            }

            val attestation = params.toKeyMintAttestation()
            val keybox = KeyboxReader.loadKeybox(params.algorithm)
            if (keybox == null) {
                Logger.w("K1 attestKey alias=$alias no keybox for algo=${params.algorithm}")
                return TransactionResult.ContinueAndSkipPost
            }
            val chain = CertificateBuilder.generateCertificateChain(
                keyPair, keybox, attestation, uid,
                android.hardware.security.keymint.SecurityLevel.TRUSTED_ENVIRONMENT
            ) ?: return TransactionResult.ContinueAndSkipPost

            val chainBytes = chain.map { it.encoded }
            val certChain = KeymasterCertificateChain(chainBytes.toMutableList())

            val callback = IKeystoreCertificateChainCallback.Stub.asInterface(callbackBinder)
            callback.onFinished(successResponse(), certChain)
            Logger.d("K1 attestKey alias=$alias chainLen=${chainBytes.size}")

            replySuccess()
        } catch (e: Exception) {
            Logger.e("K1 attestKey failed", e)
            TransactionResult.ContinueAndSkipPost
        }
    }

    private fun resolveCode(name: String): Int {
        return try {
            IKeystoreService.Stub::class.java
                .getDeclaredField("TRANSACTION_$name")
                .apply { isAccessible = true }
                .getInt(null)
        } catch (_: Exception) { -1 }
    }

    private fun successResponse(): android.security.keystore.KeystoreResponse {
        val p = Parcel.obtain()
        p.writeInt(KeyStore.NO_ERROR)
        p.writeString(null)
        p.setDataPosition(0)
        val r = android.security.keystore.KeystoreResponse.CREATOR.createFromParcel(p)
        p.recycle()
        return r
    }

    private fun replySuccess(): TransactionResult {
        val reply = Parcel.obtain()
        reply.writeNoException()
        return TransactionResult.OverrideReply(reply)
    }

    private fun extractAlias(alias: String): String {
        val prefixes = listOf("USRCERT_", "CACERT_", "USRPKEY_")
        for (p in prefixes) {
            if (alias.startsWith(p)) return alias.substring(p.length)
        }
        return alias
    }

    companion object {
        fun isCompatible(): Boolean =
            Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R
    }
}

private class KeystoreOneKeygenParams(
    val algorithm: Int,
    val keySize: Int,
    val purpose: List<Int>,
    val digest: List<Int>,
    val certificateNotBefore: java.util.Date?,
    val ecCurveName: String?,
) {
    var attestationChallenge: ByteArray? = null

    fun toKeyMintAttestation(): KeyMintAttestation {
        return KeyMintAttestation(
            keySize = this.keySize,
            algorithm = this.algorithm,
            ecCurve = 0,
            ecCurveName = this.ecCurveName ?: "",
            purpose = this.purpose,
            digest = this.digest,
            blockMode = emptyList(),
            padding = emptyList(),
            rsaPublicExponent = null,
            certificateSerial = null,
            certificateSubject = null,
            certificateNotBefore = this.certificateNotBefore,
            certificateNotAfter = null,
            attestationChallenge = this.attestationChallenge,
            origin = null,
            noAuthRequired = null,
            brand = null,
            device = null,
            product = null,
            serial = null,
            imei = null,
            meid = null,
            manufacturer = null,
            model = null,
            secondImei = null,
            includeUniqueId = null,
            callerNonce = null,
            minMacLength = null,
            rollbackResistance = null,
            earlyBootOnly = null,
            allowWhileOnBody = null,
            trustedUserPresenceRequired = null,
            trustedConfirmationRequired = null,
            maxUsesPerBoot = null,
            unlockedDeviceRequired = null,
            rsaOaepMgfDigest = emptyList(),
            activeDateTime = null,
            originationExpireDateTime = null,
            usageExpireDateTime = null,
            maxBootLevel = null,
        )
    }

    companion object {
        fun fromKeymasterArguments(args: KeymasterArguments): KeystoreOneKeygenParams {
            val algorithm = args.getEnum(KeymasterDefs.KM_TAG_ALGORITHM, 0)
            val keySize = args.getUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 0L).toInt()
            return KeystoreOneKeygenParams(
                algorithm = algorithm,
                keySize = keySize,
                purpose = args.getEnums(KeymasterDefs.KM_TAG_PURPOSE),
                digest = args.getEnums(KeymasterDefs.KM_TAG_DIGEST),
                certificateNotBefore = args.getDate(
                    KeymasterDefs.KM_TAG_ACTIVE_DATETIME, java.util.Date()
                ),
                ecCurveName = if (algorithm == KeymasterDefs.KM_ALGORITHM_EC)
                    when (keySize) {
                        224 -> "secp224r1"
                        256 -> "secp256r1"
                        384 -> "secp384r1"
                        521 -> "secp521r1"
                        else -> "secp256r1"
                    } else null,
            )
        }
    }
}
