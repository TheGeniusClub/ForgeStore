package com.dere3046.forgemint

import android.os.IBinder
import android.os.Parcel

class OperationInterceptor : BinderInterceptor() {

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == FINISH_TRANSACTION || code == ABORT_TRANSACTION) {
            unregister(target)
        }
        return TransactionResult.ContinueAndSkipPost
    }

    companion object {
        val UPDATE_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_update") }
        val FINISH_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_finish") }
        val ABORT_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_abort") }
        val UPDATE_AAD_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_updateAad") }

        fun unregister(binder: IBinder) {
            gBackdoorBinder?.let { BinderInterceptor.unregister(it, binder) }
        }

        @Volatile var gBackdoorBinder: IBinder? = null

        private fun resolveCode(name: String): Int {
            return try {
                android.system.keystore2.IKeystoreOperation.Stub::class.java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .getInt(null)
            } catch (_: Exception) { -1 }
        }
    }
}
