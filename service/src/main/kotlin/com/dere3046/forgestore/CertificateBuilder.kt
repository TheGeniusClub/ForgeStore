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

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import javax.security.auth.x500.X500Principal

object CertificateBuilder {

    data class KeyboxData(
        val keyPair: KeyPair,
        val certificates: List<X509Certificate>,
    )

    private const val UNDEFINED_NOT_AFTER = 253402300799000L

    fun generateKeyPair(params: KeyMintAttestation): KeyPair? {
        if (params.attestationChallenge != null &&
            params.attestationChallenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT
        ) {
            Logger.w("Challenge exceeds length limit (${params.attestationChallenge.size})")
            return null
        }

        return runCatching {
            val (algorithm, spec) = when (params.algorithm) {
                android.hardware.security.keymint.Algorithm.RSA -> "RSA" to RSAKeyGenParameterSpec(
                    params.keySize.takeIf { it > 0 } ?: 2048,
                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                )
                else -> "EC" to ECGenParameterSpec(
                    when (params.ecCurve) {
                        android.hardware.security.keymint.EcCurve.P_224 -> "secp224r1"
                        android.hardware.security.keymint.EcCurve.P_256 -> "secp256r1"
                        android.hardware.security.keymint.EcCurve.P_384 -> "secp384r1"
                        android.hardware.security.keymint.EcCurve.P_521 -> "secp521r1"
                        else -> params.ecCurveName
                    }
                )
            }
            KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                .apply { initialize(spec) }
                .generateKeyPair()
        }.onFailure { Logger.w("generateKeyPair: ecCurveName=${params.ecCurveName} ecCurve=${params.ecCurve} err=${it.message}", it) }
        .getOrNull()
    }

    fun generateCertificateChain(
        subjectKeyPair: KeyPair,
        keybox: KeyboxData,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
        signerKeyPair: KeyPair? = null,
        attestKeyCert: X509Certificate? = null,
    ): List<Certificate>? {
        return runCatching {
            val signingKey = signerKeyPair ?: keybox.keyPair
            val issuerName = when {
                attestKeyCert != null -> X509CertificateHolder(attestKeyCert.encoded).subject
                signerKeyPair != null -> X500Name("CN=Android Keystore Key")
                else -> X509CertificateHolder(keybox.certificates[0].encoded).subject
            }
            val leafCert = buildLeafCertificate(
                subjectKeyPair, signingKey, issuerName,
                params, uid, securityLevel,
            )
            listOf(leafCert) + keybox.certificates
        }.getOrNull()
    }

    fun generateFallbackChain(
        subjectKeyPair: KeyPair,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): List<Certificate>? {
        return runCatching {
            val issuer = X500Name("CN=Android Keystore Key")
            val leafCert = buildLeafCertificate(
                subjectKeyPair, subjectKeyPair, issuer,
                params, uid, securityLevel,
            )
            listOf(leafCert)
        }.getOrNull()
    }

    private fun buildLeafCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject
            ?: X500Name("CN=Android Keystore Key")
        val serial = params.certificateSerial ?: BigInteger.ONE
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter,
            subject, subjectKeyPair.public,
        )

        val keyUsageBits = buildKeyUsage(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }

        val attestationExt = AttestationBuilder.buildAttestationExtension(
            params, uid, securityLevel,
        )
        builder.addExtension(attestationExt)

        val signerAlgorithm = when (signingKeyPair.private) {
            is ECKey -> "SHA256withECDSA"
            is RSAKey -> "SHA256withRSA"
            else -> "SHA256withECDSA"
        }
        val signer = JcaContentSignerBuilder(signerAlgorithm)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(signingKeyPair.private)

        return JcaX509CertificateConverter()
            .getCertificate(builder.build(signer))
    }

    private fun buildKeyUsage(purposes: List<Int>): Int {
        var bits = 0
        for (p in purposes) {
            bits = bits or when (p) {
                android.hardware.security.keymint.KeyPurpose.SIGN -> KeyUsage.digitalSignature
                android.hardware.security.keymint.KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                android.hardware.security.keymint.KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                android.hardware.security.keymint.KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                android.hardware.security.keymint.KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                else -> 0
            }
        }
        return bits
    }
}
