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

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose

object AuthorizeCreate {

    data class ValidationResult(
        val allowed: Boolean,
        val errorCode: Int?,
    )

    fun validate(
        params: KeyMintAttestation,
        keyParams: KeyMintAttestation,
        forced: Boolean,
    ): ValidationResult {
        if (forced) {
            return ValidationResult(false, -28)
        }

        val purpose = params.purpose.firstOrNull() ?: return ValidationResult(false, -1000)

        validateAlgorithmPurpose(params.algorithm, purpose)?.let { return it }

        validatePurposeMatch(purpose, keyParams.purpose)?.let { return it }

        validateDigestMatch(params, keyParams)?.let { return it }

        validatePaddingMatch(params, keyParams)?.let { return it }

        validateBlockModeMatch(params, keyParams)?.let { return it }

        validateTemporal(
            params.activeDateTime?.time,
            params.originationExpireDateTime?.time,
            params.usageExpireDateTime?.time,
        )?.let { return it }

        if (purpose == KeyPurpose.SIGN && params.callerNonce == true) {
            if (keyParams.callerNonce != true) {
                return ValidationResult(false, -55)
            }
        }

        return ValidationResult(true, null)
    }

    private fun validateAlgorithmPurpose(algorithm: Int, purpose: Int): ValidationResult? {
        when (algorithm) {
            Algorithm.EC -> {
                if (purpose == KeyPurpose.ENCRYPT || purpose == KeyPurpose.DECRYPT) {
                    return ValidationResult(false, -38)
                }
            }
            Algorithm.AES -> {
                if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.VERIFY) {
                    return ValidationResult(false, -38)
                }
            }
        }
        return null
    }

    private fun validatePurposeMatch(purpose: Int, keyPurposes: List<Int>): ValidationResult? {
        if (!keyPurposes.contains(purpose)) {
            return ValidationResult(false, -38)
        }
        return null
    }

    private fun validateDigestMatch(params: KeyMintAttestation, keyParams: KeyMintAttestation): ValidationResult? {
        val opDigest = params.digest
        if (opDigest.isEmpty()) return null
        if (opDigest.any { it !in keyParams.digest }) return ValidationResult(false, -17)
        return null
    }

    private fun validatePaddingMatch(params: KeyMintAttestation, keyParams: KeyMintAttestation): ValidationResult? {
        val opPadding = params.padding
        if (opPadding.isEmpty()) return null
        if (opPadding.any { it !in keyParams.padding }) return ValidationResult(false, -32)
        return null
    }

    private fun validateBlockModeMatch(params: KeyMintAttestation, keyParams: KeyMintAttestation): ValidationResult? {
        val opMode = params.blockMode
        if (opMode.isEmpty()) return null
        if (opMode.any { it !in keyParams.blockMode }) return ValidationResult(false, -29)
        return null
    }

    private fun validateTemporal(
        activeDateTime: Long?,
        originationExpire: Long?,
        usageExpire: Long?,
    ): ValidationResult? {
        val now = System.currentTimeMillis()
        activeDateTime?.let { if (now < it) return ValidationResult(false, -38) }
        originationExpire?.let { if (now >= it) return ValidationResult(false, -38) }
        usageExpire?.let { if (now >= it) return ValidationResult(false, -38) }
        return null
    }
}
