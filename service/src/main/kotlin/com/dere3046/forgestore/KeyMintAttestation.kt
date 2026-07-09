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

import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name

data class KeyMintAttestation(
    val algorithm: Int,
    val ecCurve: Int?,
    val ecCurveName: String,
    val keySize: Int,
    val origin: Int?,
    val noAuthRequired: Boolean?,
    val blockMode: List<Int>,
    val padding: List<Int>,
    val purpose: List<Int>,
    val digest: List<Int>,
    val rsaPublicExponent: BigInteger?,
    val certificateSerial: BigInteger?,
    val certificateSubject: X500Name?,
    val certificateNotBefore: Date?,
    val certificateNotAfter: Date?,
    val attestationChallenge: ByteArray?,
    val brand: ByteArray?,
    val device: ByteArray?,
    val product: ByteArray?,
    val serial: ByteArray?,
    val imei: ByteArray?,
    val meid: ByteArray?,
    val manufacturer: ByteArray?,
    val model: ByteArray?,
    val secondImei: ByteArray?,
    val nonce: ByteArray? = null,
    val includeUniqueId: Boolean?,
    val callerNonce: Boolean?,
    val minMacLength: Int?,
    val rollbackResistance: Boolean?,
    val earlyBootOnly: Boolean?,
    val allowWhileOnBody: Boolean?,
    val trustedUserPresenceRequired: Boolean?,
    val trustedConfirmationRequired: Boolean?,
    val maxUsesPerBoot: Int?,
    val unlockedDeviceRequired: Boolean?,
    val rsaOaepMgfDigest: List<Int>,
    val activeDateTime: Date?,
    val originationExpireDateTime: Date?,
    val usageExpireDateTime: Date?,
    val maxBootLevel: Int?,
    val rawParams: Array<KeyParameter> = emptyArray(),
) {
    constructor(params: Array<KeyParameter>) : this(
        algorithm = params.findAlgorithm(Tag.ALGORITHM) ?: 0,
        keySize = params.findInteger(Tag.KEY_SIZE) ?: params.deriveKeySizeFromCurve(),
        ecCurve = params.findEcCurve(Tag.EC_CURVE),
        ecCurveName = params.deriveEcCurveName(),
        origin = params.findOrigin(Tag.ORIGIN),
        noAuthRequired = params.findBoolean(Tag.NO_AUTH_REQUIRED),
        blockMode = params.findAllBlockMode(Tag.BLOCK_MODE),
        padding = params.findAllPaddingMode(Tag.PADDING),
        purpose = params.findAllKeyPurpose(Tag.PURPOSE),
        digest = params.findAllDigests(Tag.DIGEST),
        rsaPublicExponent = params.findLongInteger(Tag.RSA_PUBLIC_EXPONENT),
        certificateSerial = params.findBlob(Tag.CERTIFICATE_SERIAL)?.let { BigInteger(it) },
        certificateSubject = params.findBlob(Tag.CERTIFICATE_SUBJECT)?.let { X500Name(X500Principal(it).name) },
        certificateNotBefore = params.findDate(Tag.CERTIFICATE_NOT_BEFORE),
        certificateNotAfter = params.findDate(Tag.CERTIFICATE_NOT_AFTER),
        attestationChallenge = params.findBlob(Tag.ATTESTATION_CHALLENGE),
        brand = params.findBlob(Tag.ATTESTATION_ID_BRAND),
        device = params.findBlob(Tag.ATTESTATION_ID_DEVICE),
        product = params.findBlob(Tag.ATTESTATION_ID_PRODUCT),
        serial = params.findBlob(Tag.ATTESTATION_ID_SERIAL),
        imei = params.findBlob(Tag.ATTESTATION_ID_IMEI),
        meid = params.findBlob(Tag.ATTESTATION_ID_MEID),
        manufacturer = params.findBlob(Tag.ATTESTATION_ID_MANUFACTURER),
        model = params.findBlob(Tag.ATTESTATION_ID_MODEL),
        secondImei = params.findBlob(Tag.ATTESTATION_ID_SECOND_IMEI),
        nonce = params.findBlob(Tag.NONCE),
        includeUniqueId = params.findBoolean(Tag.INCLUDE_UNIQUE_ID),
        callerNonce = params.findBoolean(Tag.CALLER_NONCE),
        minMacLength = params.findInteger(Tag.MIN_MAC_LENGTH),
        rollbackResistance = params.findBoolean(Tag.ROLLBACK_RESISTANCE),
        earlyBootOnly = params.findBoolean(Tag.EARLY_BOOT_ONLY),
        allowWhileOnBody = params.findBoolean(Tag.ALLOW_WHILE_ON_BODY),
        trustedUserPresenceRequired = params.findBoolean(Tag.TRUSTED_USER_PRESENCE_REQUIRED),
        trustedConfirmationRequired = params.findBoolean(Tag.TRUSTED_CONFIRMATION_REQUIRED),
        maxUsesPerBoot = params.findInteger(Tag.MAX_USES_PER_BOOT),
        unlockedDeviceRequired = params.findBoolean(Tag.UNLOCKED_DEVICE_REQUIRED),
        rsaOaepMgfDigest = params.findAllDigests(Tag.RSA_OAEP_MGF_DIGEST),
        activeDateTime = params.findDate(Tag.ACTIVE_DATETIME),
        originationExpireDateTime = params.findDate(Tag.ORIGINATION_EXPIRE_DATETIME),
        usageExpireDateTime = params.findDate(Tag.USAGE_EXPIRE_DATETIME),
        maxBootLevel = params.findInteger(Tag.MAX_BOOT_LEVEL),
        rawParams = params,
    )

    val isAttestKey: Boolean
        get() = purpose.size == 1 && purpose.contains(KeyPurpose.ATTEST_KEY)

    val isImportKey: Boolean
        get() = origin == KeyOrigin.IMPORTED || origin == KeyOrigin.SECURELY_IMPORTED

    val isSymmetric: Boolean
        get() = algorithm == android.hardware.security.keymint.Algorithm.AES ||
            algorithm == android.hardware.security.keymint.Algorithm.HMAC ||
            algorithm == android.hardware.security.keymint.Algorithm.TRIPLE_DES

    fun hasTag(tag: Int): Boolean {
        return rawParams.any { it.tag == tag }
    }
}



private fun Array<KeyParameter>.findBoolean(tag: Int): Boolean? =
    find { it.tag == tag }?.value?.boolValue

private fun Array<KeyParameter>.findInteger(tag: Int): Int? =
    find { it.tag == tag }?.value?.integer

private fun Array<KeyParameter>.findAlgorithm(tag: Int): Int? =
    find { it.tag == tag }?.value?.algorithm

private fun Array<KeyParameter>.findEcCurve(tag: Int): Int? =
    find { it.tag == tag }?.value?.ecCurve

private fun Array<KeyParameter>.findOrigin(tag: Int): Int? =
    find { it.tag == tag }?.value?.origin

private fun Array<KeyParameter>.findLongInteger(tag: Int): BigInteger? =
    find { it.tag == tag }?.value?.longInteger?.toBigInteger()

private fun Array<KeyParameter>.findDate(tag: Int): Date? =
    find { it.tag == tag }?.value?.dateTime?.let { Date(it) }

private fun Array<KeyParameter>.findBlob(tag: Int): ByteArray? =
    find { it.tag == tag }?.value?.blob

private fun Array<KeyParameter>.findAllBlockMode(tag: Int): List<Int> =
    filter { it.tag == tag }.map { it.value.blockMode }

private fun Array<KeyParameter>.findAllPaddingMode(tag: Int): List<Int> =
    filter { it.tag == tag }.map { it.value.paddingMode }

private fun Array<KeyParameter>.findAllKeyPurpose(tag: Int): List<Int> =
    filter { it.tag == tag }.map { it.value.keyPurpose }

private fun Array<KeyParameter>.findAllDigests(tag: Int): List<Int> =
    filter { it.tag == tag }.map { it.value.digest }

private fun Array<KeyParameter>.deriveKeySizeFromCurve(): Int {
    val curveId = find { it.tag == Tag.EC_CURVE }?.value?.ecCurve ?: return 0
    return when (curveId) {
        EcCurve.P_224 -> 224
        EcCurve.P_256, EcCurve.CURVE_25519 -> 256
        EcCurve.P_384 -> 384
        EcCurve.P_521 -> 521
        else -> 0
    }
}

private fun Array<KeyParameter>.deriveEcCurveName(): String {
    val curveParam = find { it.tag == Tag.EC_CURVE }
    if (curveParam != null) {
        return when (curveParam.value.ecCurve) {
            EcCurve.CURVE_25519 -> "CURVE_25519"
            EcCurve.P_224 -> "secp224r1"
            EcCurve.P_256 -> "secp256r1"
            EcCurve.P_384 -> "secp384r1"
            EcCurve.P_521 -> "secp521r1"
            else -> "secp256r1"
        }
    }
    val keySize = findInteger(Tag.KEY_SIZE) ?: 0
    return when (keySize) {
        224 -> "secp224r1"
        384 -> "secp384r1"
        521 -> "secp521r1"
        else -> "secp256r1"
    }
}
