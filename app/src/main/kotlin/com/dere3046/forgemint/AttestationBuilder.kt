package com.dere3046.forgemint

import android.os.Build
import android.os.ServiceManager
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import java.security.MessageDigest

object AttestationBuilder {

    fun buildAttestationExtension(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): org.bouncycastle.asn1.x509.Extension {
        val keyDescription = buildKeyDescription(params, uid, securityLevel)
        return org.bouncycastle.asn1.x509.Extension(
            ASN1ObjectIdentifier(AttestationConstants.ATTESTATION_OID),
            false,
            DEROctetString(keyDescription.encoded),
        )
    }

    private fun attestVersion(): Long = when {
        Build.VERSION.SDK_INT >= 35 -> 400
        Build.VERSION.SDK_INT >= 34 -> 300
        else -> 200
    }

    private fun buildKeyDescription(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): DERSequence {
        val ver = attestVersion()
        val kmVer = if (ver >= 100) ver else 41
        Logger.d("Building KeyDescription ver=$ver kmVer=$kmVer securityLevel=$securityLevel algo=${params.algorithm}")
        val teeEnforced = buildTeeEnforcedList(params, uid, securityLevel, ver)
        val softwareEnforced = buildSoftwareEnforcedList(params, uid, securityLevel, ver)

        val fields = arrayOf(
            ASN1Integer(ver), // attestationVersion
            ASN1Enumerated(securityLevel), // attestationSecurityLevel
            ASN1Integer(kmVer), // keyMintVersion
            ASN1Enumerated(securityLevel), // keymintSecurityLevel
            DEROctetString(params.attestationChallenge ?: ByteArray(0)),
            DEROctetString(ByteArray(0)), // uniqueId
            softwareEnforced,
            teeEnforced,
        )
        return DERSequence(fields)
    }

    private fun buildTeeEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
        ver: Long,
    ): DERSequence {
        val list = mutableListOf<ASN1Encodable>(
            DERTaggedObject(true, AttestationConstants.TAG_PURPOSE,
                DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray())),
            DERTaggedObject(true, AttestationConstants.TAG_ALGORITHM,
                ASN1Integer(params.algorithm.toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_KEY_SIZE,
                ASN1Integer(params.keySize.toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_DIGEST,
                DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray())),
        )

        if (params.blockMode.isNotEmpty()) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_BLOCK_MODE,
                DERSet(params.blockMode.map { ASN1Integer(it.toLong()) }.toTypedArray())))
        }
        if (params.padding.isNotEmpty()) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_PADDING,
                DERSet(params.padding.map { ASN1Integer(it.toLong()) }.toTypedArray())))
        }
        if (params.ecCurve != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_EC_CURVE,
                ASN1Integer(params.ecCurve.toLong())))
        }
        if (params.rsaPublicExponent != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_RSA_PUBLIC_EXPONENT,
                ASN1Integer(params.rsaPublicExponent.toLong())))
        }

        list.addAll(listOf(
            DERTaggedObject(true, AttestationConstants.TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE),
            DERTaggedObject(true, AttestationConstants.TAG_ORIGIN, ASN1Integer(0L)),
            DERTaggedObject(true, AttestationConstants.TAG_ROOT_OF_TRUST, buildRootOfTrust()),
            DERTaggedObject(true, AttestationConstants.TAG_OS_VERSION,
                ASN1Integer(getOsVersion().toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_OS_PATCHLEVEL,
                ASN1Integer(getOsPatchLevel().toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                ASN1Integer(getVendorPatchLevel().toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_BOOT_PATCHLEVEL,
                ASN1Integer(getBootPatchLevel().toLong())),
        )        )
        params.brand?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_BRAND, DEROctetString(it)))
        }
        params.device?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_DEVICE, DEROctetString(it)))
        }
        params.product?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_PRODUCT, DEROctetString(it)))
        }
        params.serial?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_SERIAL, DEROctetString(it)))
        }
        params.imei?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_IMEI, DEROctetString(it)))
        }
        params.meid?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MEID, DEROctetString(it)))
        }
        params.manufacturer?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER, DEROctetString(it)))
        }
        params.model?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MODEL, DEROctetString(it)))
        }
        if (ver >= 400) {
            params.secondImei?.let {
                list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI, DEROctetString(it)))
            }
        }

        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    private fun buildSoftwareEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
        ver: Long,
    ): DERSequence {
        val list = mutableListOf<ASN1Encodable>(
            DERTaggedObject(true, AttestationConstants.TAG_CREATION_DATETIME,
                ASN1Integer(System.currentTimeMillis())),
        )
        if (params.attestationChallenge != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_APPLICATION_ID,
                DEROctetString(getApplicationId(uid))))
        }
        if (ver >= 400) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_MODULE_HASH,
                DEROctetString(readModuleHash())))
        }
        return DERSequence(list.toTypedArray())
    }

    private fun buildRootOfTrust(): DERSequence {
        val bootKey = readHexProperty("ro.boot.vbmeta.public_key_digest")
        val bootHash = readHexProperty("ro.boot.vbmeta.digest")
        return DERSequence(arrayOf(
            DEROctetString(bootKey),
            ASN1Boolean.TRUE,
            ASN1Enumerated(0),
            DEROctetString(bootHash),
        ))
    }

    private fun readModuleHash(): ByteArray {
        val value = try {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            m.invoke(null, "ro.boot.avb_modules_hash", "") as String
        } catch (_: Exception) { "" }
        if (value.isNotEmpty()) return hexStringToByteArray(value)
        return ByteArray(32) { (it * 5 + 1).toByte() }
    }

    private fun getApplicationId(uid: Int): ByteArray {
        val packages = try {
            val pmBinder = ServiceManager.getService("package")
            val pm = android.content.pm.IPackageManager.Stub.asInterface(pmBinder)
            pm.getPackagesForUid(uid)?.toList() ?: emptyList()
        } catch (_: Exception) { emptyList<String>() }

        val sha256 = MessageDigest.getInstance("SHA-256")
        val packageSeq = packages.map { pkg ->
            DERSequence(arrayOf(
                DEROctetString(pkg.toByteArray(Charsets.UTF_8)),
                ASN1Integer(0L),
            ))
        }

        return DERSequence(arrayOf(
            DERSet(packageSeq.toTypedArray()),
            DERSet(packageSeq.map {
                DEROctetString(sha256.digest(it.encoded))
            }.toTypedArray()),
        )).encoded
    }

    private fun readHexProperty(key: String): ByteArray {
        val value = try {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            m.invoke(null, key, "") as String
        } catch (_: Exception) { "" }
        if (value.isEmpty()) return ByteArray(32) { (it * 7 + 3).toByte() }
        return hexStringToByteArray(value)
    }

    private fun getOsVersion(): Int {
        val release = Build.VERSION.RELEASE ?: "15"
        val parts = release.split(".").map { it.toIntOrNull() ?: 0 }
        return when (parts.size) {
            1 -> parts[0] * 10000
            2 -> parts[0] * 10000 + parts[1] * 100
            3 -> parts[0] * 10000 + parts[1] * 100 + parts[2]
            else -> 150000
        }
    }

    private fun getOsPatchLevel(): Int {
        val patch = Build.VERSION.SECURITY_PATCH ?: "2026-06"
        val parts = patch.split("-")
        if (parts.size == 2) {
            val y = parts[0].toIntOrNull() ?: 2026
            val m = parts[1].toIntOrNull() ?: 6
            return (y - 2000) * 12 + m
        }
        return 26206
    }

    private fun getVendorPatchLevel(): Int = getOsPatchLevel()
    private fun getBootPatchLevel(): Int = getOsPatchLevel()

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
        }
        return data
    }
}
