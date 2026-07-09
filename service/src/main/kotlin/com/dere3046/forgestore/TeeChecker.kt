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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom

object TeeChecker {

    private const val TEST_ALIAS = "forgestore_tee_check"

    fun isTeeFunctional(): Boolean {
        return try {
            try {
                KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    .deleteEntry(TEST_ALIAS)
            } catch (_: Exception) {}

            val spec = KeyGenParameterSpec.Builder(
                TEST_ALIAS,
                KeyProperties.PURPOSE_SIGN,
            ).apply {
                setDigests(KeyProperties.DIGEST_SHA256)
                setAlgorithmParameterSpec(
                    java.security.spec.ECGenParameterSpec("secp256r1")
                )
                val challenge = ByteArray(32)
                SecureRandom().nextBytes(challenge)
                setAttestationChallenge(challenge)
            }.build()

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            kpg.initialize(spec)
            kpg.generateKeyPair()

            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(TEST_ALIAS)

            Logger.i("TEE is functional")
            true
        } catch (e: Exception) {
            Logger.w("TEE not functional: ${e.message}")
            false
        }
    }
}
