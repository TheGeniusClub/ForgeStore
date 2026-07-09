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

import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization

object AttestationPatcher {

    fun patchCertificateChain(originalChain: Array<Certificate>?, uid: Int): Array<Certificate> {
        if (originalChain.isNullOrEmpty()) {
            Logger.w("patchCertificateChain: null or empty chain for UID $uid")
            return originalChain ?: emptyArray()
        }

        return runCatching {
            val originalLeaf = originalChain[0] as X509Certificate
            val originalLeafHolder = X509CertificateHolder(originalLeaf.encoded)

            val parsed = parseAttestationExtension(originalLeafHolder) ?: return originalChain

            val keybox = getKeyboxForAlgorithm(originalLeaf.sigAlgName)

            val patchedLeaf = createPatchedLeafCertificate(
                originalLeafHolder, parsed, keybox,
                originalLeaf.sigAlgName, uid,
            )

            val newChain = listOf(patchedLeaf) + keybox.certificates
            Logger.d("Patched cert chain for UID $uid, chain size=${newChain.size}")
            newChain.toTypedArray()
        }.getOrElse {
            Logger.e("Failed to patch certificate chain for UID $uid", it)
            originalChain
        }
    }

    fun formatAsn1Primitive(obj: ASN1Encodable?): String {
        val primitive = obj?.toASN1Primitive()
        return when (primitive) {
            null -> "NULL"
            is ASN1Integer -> primitive.value.toString()
            is ASN1Enumerated -> primitive.value.toString()
            is ASN1Boolean -> primitive.isTrue.toString()
            is ASN1Null -> "NULL"
            is ASN1OctetString -> {
                val bytes = primitive.octets
                if (bytes.all { it >= 32 && it < 127 }) {
                    "\"${String(bytes, StandardCharsets.UTF_8)}\""
                } else if (bytes.isEmpty()) {
                    "\"\""
                } else {
                    "#${bytes.toHex()}"
                }
            }
            is ASN1TaggedObject ->
                "[TAG ${primitive.tagNo}]${formatAsn1Primitive(primitive.baseObject)}"
            is ASN1Sequence ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "[", postfix = "]", separator = ", ")
            is ASN1Set ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "{", postfix = "}", separator = ", ")
            else -> primitive.toString()
        }
    }

    private fun normalizeSignatureAlgorithm(algoName: String): String {
        return algoName.uppercase().replace("WITH", "with")
    }

    private fun getKeyboxForAlgorithm(algorithm: String): CertificateBuilder.KeyboxData {
        val keyType = when {
            algorithm.contains("RSA", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_RSA
            algorithm.contains("EC", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_EC
            else -> algorithm
        }

        val keybox = KeyboxReader.loadKeybox(
            when (keyType) {
                KeyProperties.KEY_ALGORITHM_RSA -> android.hardware.security.keymint.Algorithm.RSA
                else -> android.hardware.security.keymint.Algorithm.EC
            }
        ) ?: throw IllegalArgumentException("No keybox found for algorithm '$keyType'")

        return keybox
    }

    private fun createPatchedLeafCertificate(
        originalLeafHolder: X509CertificateHolder,
        parsed: ParsedAttestation,
        keybox: CertificateBuilder.KeyboxData,
        sigAlgName: String,
        uid: Int,
    ): Certificate {
        val newIssuer = X509CertificateHolder(keybox.certificates[0].encoded).subject

        val builder = X509v3CertificateBuilder(
            newIssuer,
            originalLeafHolder.serialNumber,
            originalLeafHolder.notBefore,
            originalLeafHolder.notAfter,
            originalLeafHolder.subject,
            originalLeafHolder.subjectPublicKeyInfo,
        )

        val patchedExtension = createPatchedAttestationExtension(parsed, uid)

        originalLeafHolder.extensions.extensionOIDs.forEach {
            builder.addExtension(
                if (it.id == AttestationConstants.ATTESTATION_OID) patchedExtension
                else originalLeafHolder.getExtension(it)
            )
        }

        val signer = JcaContentSignerBuilder(normalizeSignatureAlgorithm(sigAlgName))
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keybox.keyPair.private)
        val newCert = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val sigBytes = (newCert as X509Certificate).signature
        Logger.d("Patched leaf cert signature: ${sigBytes.toHex()}")

        return newCert
    }

    private fun parseAttestationExtension(certHolder: X509CertificateHolder): ParsedAttestation? {
        val extension = certHolder.getExtension(AttestationConstants.ATTESTATION_OID_OBJ) ?: return null
        val sequence = ASN1Sequence.getInstance(extension.extnValue.octets)
        val allFields = sequence.toArray()

        val softwareCandidate = allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX]
        val teeCandidate = allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX]
        if (sequenceContainsRootOfTrust(softwareCandidate) &&
            !sequenceContainsRootOfTrust(teeCandidate)
        ) {
            allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX] = teeCandidate
            allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] = softwareCandidate
        }

        val teeEnforced = allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] as ASN1Sequence

        var originalRootOfTrust: ASN1Encodable? = null
        val teeEnforcedMap = mutableMapOf<Int, ASN1TaggedObject>()

        for (element in teeEnforced) {
            val tagged = element as ASN1TaggedObject
            if (tagged.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST) {
                originalRootOfTrust = tagged.baseObject.toASN1Primitive()
            } else {
                teeEnforcedMap[tagged.tagNo] = tagged
            }
        }
        return ParsedAttestation(allFields, teeEnforcedMap, originalRootOfTrust)
    }

    private fun sequenceContainsRootOfTrust(seq: ASN1Encodable): Boolean {
        if (seq !is ASN1Sequence) return false
        return seq.any { element ->
            (element as? ASN1TaggedObject)?.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST
        }
    }

    private fun createPatchedAttestationExtension(parsed: ParsedAttestation, uid: Int): Extension {
        val (allFields, teeEnforcedMap, originalRootOfTrust) = parsed

        val newRootOfTrust = AttestationBuilder.buildRootOfTrust(originalRootOfTrust)
        teeEnforcedMap[AttestationConstants.TAG_ROOT_OF_TRUST] =
            DERTaggedObject(true, AttestationConstants.TAG_ROOT_OF_TRUST, newRootOfTrust)

        val simulatedProperties = AttestationBuilder.getSimulatedHardwareProperties(uid)
        for ((tag, value) in simulatedProperties) {
            if (value != null) {
                teeEnforcedMap[tag] = value
            } else {
                teeEnforcedMap.remove(tag)
            }
        }

        val sortedElements = teeEnforcedMap.values.sortedBy { it.tagNo }
        val sortedTeeEnforced = DERSequence(sortedElements.toTypedArray())

        allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] = sortedTeeEnforced
        val patchedSequence = DERSequence(allFields)
        val patchedOctets = DEROctetString(patchedSequence)

        return Extension(
            AttestationConstants.ATTESTATION_OID_OBJ,
            false, patchedOctets,
        )
    }

    private data class ParsedAttestation(
        val allFields: Array<ASN1Encodable>,
        val teeEnforcedMap: MutableMap<Int, ASN1TaggedObject>,
        val rootOfTrust: ASN1Encodable?,
    )

    fun patchAuthorizations(
        authorizations: Array<Authorization>?,
        callingUid: Int,
    ): Array<Authorization>? {
        if (authorizations == null) return null

        val osPatch = AttestationBuilder.getPatchLevel(callingUid)
        val vendorBootPatch = AttestationBuilder.getPatchLevelLong(callingUid)

        return authorizations.map { auth ->
            val replacement = when (auth.keyParameter.tag) {
                Tag.OS_PATCHLEVEL -> osPatch
                Tag.VENDOR_PATCHLEVEL -> vendorBootPatch
                Tag.BOOT_PATCHLEVEL -> vendorBootPatch
                else -> null
            }
            if (replacement != null) {
                Authorization().apply {
                    keyParameter = KeyParameter().apply {
                        tag = auth.keyParameter.tag
                        value = KeyParameterValue.integer(replacement)
                    }
                    securityLevel = auth.securityLevel
                }
            } else {
                auth
            }
        }.toTypedArray()
    }
}
