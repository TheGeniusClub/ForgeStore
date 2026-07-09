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

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object CertificateHelper {

    val certificateFactory by lazy { CertificateFactory.getInstance("X.509") }

    fun toCertificate(bytes: ByteArray): X509Certificate? {
        return try {
            certificateFactory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
        } catch (_: CertificateException) { null }
    }

    fun toCertificates(bytes: ByteArray?): List<X509Certificate> {
        return bytes?.let {
            try {
                @Suppress("UNCHECKED_CAST")
                certificateFactory.generateCertificates(ByteArrayInputStream(it)) as Collection<X509Certificate>
            } catch (_: CertificateException) { emptyList() }
        }?.toList() ?: emptyList()
    }

    fun certificatesToByteArray(certificates: Collection<java.security.cert.Certificate>): ByteArray? {
        return runCatching {
            ByteArrayOutputStream().use { stream ->
                certificates.forEach { cert -> stream.write(cert.encoded) }
                stream.toByteArray()
            }
        }.getOrNull()
    }

    fun getCertificateChain(metadata: KeyMetadata?): Array<java.security.cert.Certificate>? {
        metadata ?: return null
        val leafBytes = metadata.certificate ?: return null
        val leafCert = toCertificate(leafBytes) ?: return null

        val chainBytes = metadata.certificateChain
        return if (chainBytes == null) {
            arrayOf(leafCert)
        } else {
            val additional = toCertificates(chainBytes)
            (listOf(leafCert) + additional).toTypedArray()
        }
    }

    fun updateCertificateChain(
        uid: Int,
        metadata: KeyMetadata,
        chain: Array<java.security.cert.Certificate>,
    ): Result<Unit> {
        return runCatching {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty" }

            metadata.certificate = chain[0].encoded
            metadata.certificateChain = if (chain.size > 1) {
                certificatesToByteArray(chain.drop(1))
            } else null

            metadata.authorizations = metadata.authorizations?.mapNotNull { auth ->
                val replacement = when (auth.keyParameter.tag) {
                    Tag.OS_PATCHLEVEL -> AttestationBuilder.getPatchLevel(uid)
                    Tag.VENDOR_PATCHLEVEL -> AttestationBuilder.getPatchLevelLong(uid)
                    Tag.BOOT_PATCHLEVEL -> AttestationBuilder.getPatchLevelLong(uid)
                    else -> return@mapNotNull auth
                }
                Authorization().apply {
                    securityLevel = auth.securityLevel
                    keyParameter = KeyParameter().apply {
                        tag = auth.keyParameter.tag
                        value = KeyParameterValue().apply { integer = replacement }
                    }
                }
            }?.toTypedArray()
        }
    }
}
