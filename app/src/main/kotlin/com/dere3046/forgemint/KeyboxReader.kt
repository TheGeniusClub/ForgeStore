package com.dere3046.forgemint

import android.hardware.security.keymint.Algorithm
import android.security.keystore.KeyProperties
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory

object KeyboxReader {

    private const val KEYBOX_FILE = "/data/adb/forgemint/keybox.xml"

    private var keyboxCache: Map<String, CertificateBuilder.KeyboxData>? = null

    fun loadKeybox(algorithm: Int? = null): CertificateBuilder.KeyboxData? {
        val algoKey = algorithm?.let { algoToKey(it) } ?: return singleKey()
        val cache = keyboxCache ?: reload()
        return cache[algoKey]
    }
    private fun algoToKey(algo: Int): String = when (algo) {
        Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
        Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC
        else -> ""
    }

    private fun singleKey(): CertificateBuilder.KeyboxData? {
        val cache = keyboxCache ?: reload()
        return cache.values.firstOrNull()
    }

    private fun reload(): Map<String, CertificateBuilder.KeyboxData> {
        val file = File(KEYBOX_FILE)
        if (!file.exists()) {
            Logger.w("Keybox file not found: $KEYBOX_FILE")
            return emptyMap()
        }
        return try {
            val xmlContent = file.readText().trimStart('\uFEFF', '\uFFFE', ' ')
            val map = parseXml(xmlContent)
            keyboxCache = map
            map
        } catch (e: Exception) {
            Logger.e("Failed to load keybox", e)
            emptyMap()
        }
    }

    fun clearCache() { keyboxCache = null }

    private fun parseXml(xmlContent: String): Map<String, CertificateBuilder.KeyboxData> {
        val found = mutableMapOf<String, CertificateBuilder.KeyboxData>()
        val parser = XmlPullParserFactory.newInstance().newPullParser().apply {
            setInput(StringReader(xmlContent))
        }

        var currentAlgorithm: String? = null
        var currentPrivateKeyPem: String? = null
        val currentCerts = mutableListOf<String>()
        var insideKeyPem = false
        var insideCert = false

        var event = parser.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            when (event) {
                XmlPullParser.START_TAG -> when (parser.name) {
                    "Key" -> {
                        currentAlgorithm = parser.getAttributeValue(null, "algorithm")
                        currentPrivateKeyPem = null
                        currentCerts.clear()
                    }
                    "PrivateKey" -> insideKeyPem = true
                    "Certificate" -> insideCert = true
                }
                XmlPullParser.TEXT -> {
                    if (parser.isWhitespace) { event = parser.next(); continue }
                    if (insideKeyPem) currentPrivateKeyPem = parser.text
                    if (insideCert) currentCerts.add(parser.text)
                }
                XmlPullParser.END_TAG -> when (parser.name) {
                    "PrivateKey" -> insideKeyPem = false
                    "Certificate" -> insideCert = false
                    "Key" -> runCatching {
                        val algo = currentAlgorithm ?: return@runCatching
                        val pem = currentPrivateKeyPem ?: return@runCatching
                        if (currentCerts.isEmpty()) return@runCatching

                        val keyPair = parsePemKeyPair(pem) ?: return@runCatching
                        val certs = currentCerts.mapNotNull { parsePemCert(it) }

                        val derivedAlgo = when (keyPair.private) {
                            is RSAPrivateKey -> KeyProperties.KEY_ALGORITHM_RSA
                            is ECPrivateKey -> KeyProperties.KEY_ALGORITHM_EC
                            else -> return@runCatching
                        }

                        found[derivedAlgo] = CertificateBuilder.KeyboxData(keyPair, certs)
                    }
                }
            }
            event = parser.next()
        }

        Logger.i("Parsed ${found.size} keys from keybox.xml")
        return found
    }

    private fun parsePemKeyPair(pem: String): KeyPair? {
        return try {
            PEMParser(StringReader(pem.trimIndent())).use { parser ->
                val obj = parser.readObject()
                if (obj is org.bouncycastle.openssl.PEMKeyPair) {
                    JcaPEMKeyConverter().getKeyPair(obj)
                } else null
            }
        } catch (e: Exception) {
            Logger.e("Failed to parse PEM key pair", e)
            null
        }
    }

    private fun parsePemCert(pem: String): X509Certificate? {
        return try {
            PemReader(StringReader(pem.trimIndent())).use { reader ->
                val obj = reader.readPemObject()
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(obj.content)) as X509Certificate
            }
        } catch (_: Exception) { null }
    }
}
