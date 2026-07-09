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

import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyMetadata
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

object StateManager {

    data class KeyIdentifier(val uid: Int, val alias: String)

    data class KeyEntry(
        val uid: Int,
        val alias: String,
        val nspace: Long,
        val metadata: KeyMetadata,
        val keyPair: KeyPair? = null,
        val secretKey: javax.crypto.SecretKey? = null,
        val securityLevel: Int,
        val securityLevelBinder: IKeystoreSecurityLevel?,
        val certChain: List<X509Certificate>,
    )

    data class SoftwareGrant(
        val granteeUid: Int,
        val accessVector: Int,
        val ownerKeyId: KeyIdentifier,
    )

    private val grantMap = ConcurrentHashMap<Long, SoftwareGrant>()

    fun issueGrant(ownerKeyId: KeyIdentifier, granteeUid: Int, accessVector: Int): Long {
        var nspace: Long
        do { nspace = SecureRandom().nextLong() } while (nspace == 0L || grantMap.containsKey(nspace))
        grantMap[nspace] = SoftwareGrant(granteeUid, accessVector, ownerKeyId)
        Logger.d("Grant issued owner=$ownerKeyId grantee=$granteeUid nspace=$nspace")
        return nspace
    }

    fun resolveGrant(nspace: Long, callerUid: Int): KeyIdentifier? {
        val grant = grantMap[nspace] ?: return null
        if (grant.granteeUid != callerUid) return null
        return grant.ownerKeyId
    }

    fun isGrantNspaceKnown(nspace: Long): Boolean = grantMap.containsKey(nspace)

    fun getGrantAccessVector(nspace: Long): Int? = grantMap[nspace]?.accessVector

    fun revokeGrantForOwner(ownerKeyId: KeyIdentifier, granteeUid: Int) {
        val toRemove = grantMap.entries.filter {
            it.value.ownerKeyId == ownerKeyId && it.value.granteeUid == granteeUid
        }.map { it.key }
        toRemove.forEach { grantMap.remove(it) }
    }

    fun purgeGrants(keyId: KeyIdentifier) {
        val toRemove = grantMap.entries.filter {
            it.value.ownerKeyId == keyId
        }.map { it.key }
        toRemove.forEach { grantMap.remove(it) }
    }
}
