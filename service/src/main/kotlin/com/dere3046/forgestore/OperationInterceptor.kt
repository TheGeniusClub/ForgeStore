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

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreOperation

class OperationInterceptor(
    private val original: IKeystoreOperation?,
    private val backdoor: IBinder,
    private val isAead: Boolean,
) : BinderInterceptor() {

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == UPDATE_AAD_TRANSACTION && !isAead) {
            return replySse(KeystoreErrorCodes.invalidTag)
        }
        if (code == FINISH_TRANSACTION || code == ABORT_TRANSACTION) {
            BinderInterceptor.unregister(backdoor, target)
        }
        return TransactionResult.ContinueAndSkipPost
    }

    private fun replySse(errorCode: Int): TransactionResult {
        val override = Parcel.obtain()
        override.writeInt(-8)
        override.writeString("Error::Km($errorCode)")
        override.writeInt(0)
        override.writeInt(errorCode)
        return TransactionResult.OverrideReply(override)
    }

    companion object {
        val UPDATE_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_update") }
        val FINISH_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_finish") }
        val ABORT_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_abort") }
        val UPDATE_AAD_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_updateAad") }

        private fun resolveCode(name: String): Int {
            return try {
                IKeystoreOperation.Stub::class.java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .getInt(null)
            } catch (_: Exception) { -1 }
        }
    }
}
