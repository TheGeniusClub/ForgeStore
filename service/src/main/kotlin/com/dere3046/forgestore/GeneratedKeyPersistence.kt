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

import android.os.Parcel
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

object GeneratedKeyPersistence {

    private const val DIR = "/data/adb/forge_store/keys"
    private const val FORMAT_VERSION = 2
    private val locks = ConcurrentHashMap<String, ReentrantLock>()
    private val certFactory by lazy { CertificateFactory.getInstance("X.509") }

    fun store(entry: StateManager.KeyEntry) {
        val key = filename(entry.uid, entry.alias)
        val dir = File(DIR)
        if (!dir.exists()) dir.mkdirs()
        val file = File(dir, key)
        val tmp = File(dir, "$key.tmp")

        locks.getOrPut(key) { ReentrantLock() }.withLock {
            try {
                DataOutputStream(FileOutputStream(tmp)).use { out ->
                    out.writeInt(FORMAT_VERSION)
                    out.writeInt(entry.uid)
                    out.writeUTF(entry.alias)
                    out.writeLong(entry.nspace)
                    out.writeInt(entry.securityLevel)

                    if (entry.keyPair != null) {
                        out.writeByte(0)
                        val algo = entry.keyPair.private.algorithm
                        out.writeUTF(algo)
                        val pk = entry.keyPair.private.encoded
                        out.writeInt(pk.size)
                        out.write(pk)
                        val pub = entry.keyPair.public.encoded
                        out.writeInt(pub.size)
                        out.write(pub)
                    } else if (entry.secretKey != null) {
                        out.writeByte(1)
                        val algo = entry.secretKey.algorithm
                        out.writeUTF(algo)
                        val encoded = entry.secretKey.encoded
                        out.writeInt(encoded.size)
                        out.write(encoded)
                    } else {
                        Logger.w("Persisting key with no key material: ${entry.alias}")
                        return
                    }

                    val mp = Parcel.obtain()
                    mp.writeTypedObject(entry.metadata, 0)
                    val md = mp.marshall()
                    mp.recycle()
                    out.writeInt(md.size)
                    out.write(md)

                    out.writeInt(entry.certChain.size)
                    for (cert in entry.certChain) {
                        val cb = cert.encoded
                        out.writeInt(cb.size)
                        out.write(cb)
                    }

                    out.flush()
                }
                if (!tmp.exists() || tmp.length() < 20) {
                    Logger.w("persist: write verification failed for $key")
                    return@withLock
                }
                tmp.renameTo(file)
                Logger.d("persist: stored key $key (uid=${entry.uid} alias=${entry.alias})")
            } catch (e: Exception) {
                Logger.e("persist: store failed", e)
                tmp.delete()
            }
        }
    }

    fun loadAll(securityLevel: Int): List<LoadedKey> {
        val dir = File(DIR)
        if (!dir.exists() || !dir.isDirectory) return emptyList()
        val result = mutableListOf<LoadedKey>()
        for (file in dir.listFiles() ?: emptyArray()) {
            if (file.extension != "tmp") {
                load(file)?.let {
                    if (it.securityLevel == securityLevel) result.add(it)
                }
            }
        }
        return result
    }

    private fun load(file: File): LoadedKey? {
        val key = file.name
        locks.getOrPut(key) { ReentrantLock() }.withLock {
            try {
                DataInputStream(FileInputStream(file)).use { input ->
                    val version = input.readInt()
                    if (version != 1 && version != FORMAT_VERSION) {
                        Logger.w("persist: skipping $key (version=$version)")
                        return null
                    }
                    val uid = input.readInt()
                    val alias = input.readUTF()
                    val nspace = input.readLong()
                    val secLevel = input.readInt()

                    val keyType = if (version >= 2) input.readByte().toInt() else 0
                    val keyPair: KeyPair?
                    val secretKey: javax.crypto.SecretKey?
                    var certAlgo: String

                    if (keyType == 1) {
                        keyPair = null
                        certAlgo = input.readUTF()
                        val encLen = input.readInt()
                        val enc = ByteArray(encLen)
                        input.readFully(enc)
                        secretKey = javax.crypto.spec.SecretKeySpec(enc, certAlgo)
                    } else {
                        certAlgo = input.readUTF()
                        val pkLen = input.readInt()
                        val pk = ByteArray(pkLen)
                        input.readFully(pk)
                        val pubLen = input.readInt()
                        val pub = ByteArray(pubLen)
                        input.readFully(pub)
                        val kf = KeyFactory.getInstance(certAlgo)
                        keyPair = KeyPair(kf.generatePublic(X509EncodedKeySpec(pub)), kf.generatePrivate(PKCS8EncodedKeySpec(pk)))
                        secretKey = null
                    }

                    val mdLen = input.readInt()
                    val md = ByteArray(mdLen)
                    input.readFully(md)
                    val mp = Parcel.obtain()
                    mp.unmarshall(md, 0, md.size)
                    mp.setDataPosition(0)
                    val metadata = mp.readTypedObject(KeyMetadata.CREATOR)
                    mp.recycle()

                    val certCount = input.readInt()
                    val chain = mutableListOf<X509Certificate>()
                    for (i in 0 until certCount) {
                        val cbLen = input.readInt()
                        val cb = ByteArray(cbLen)
                        input.readFully(cb)
                        val cert = certFactory.generateCertificate(ByteArrayInputStream(cb)) as X509Certificate
                        chain.add(cert)
                    }

                    Logger.d("persist: loaded key $key (uid=$uid alias=$alias)")
                    return LoadedKey(uid, alias, nspace, secLevel, keyPair, secretKey, metadata, chain)
                }
            } catch (e: Exception) {
                Logger.e("persist: load failed for ${file.name}", e)
                return null
            }
        }
    }

    fun remove(uid: Int, alias: String) {
        val file = File(DIR, filename(uid, alias))
        if (file.exists()) file.delete()
    }

    fun rePersist(entry: StateManager.KeyEntry) {
        try {
            store(entry)
        } catch (_: Exception) {}
    }

    private fun filename(uid: Int, alias: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest("$uid:$alias".toByteArray(Charsets.UTF_8)).toHex()
    }

    data class LoadedKey(
        val uid: Int,
        val alias: String,
        val nspace: Long,
        val securityLevel: Int,
        val keyPair: KeyPair?,
        val secretKey: javax.crypto.SecretKey?,
        val metadata: KeyMetadata?,
        val certChain: List<X509Certificate>,
    )
}
