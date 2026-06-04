package com.dere3046.forgemint

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Parcelable

open class BinderInterceptor : Binder() {

    sealed class TransactionResult {
        data object Skip : TransactionResult()
        data object Continue : TransactionResult()
        data class OverrideReply(val parcel: Parcel) : TransactionResult()
        data object ContinueAndSkipPost : TransactionResult()
        data class OverrideData(val data: Parcel) : TransactionResult()
    }

    open fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult = TransactionResult.Continue

    open fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult = TransactionResult.Skip

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        val txId = data.readLong()
        return when (code) {
            PRE_CODE -> handlePreTransact(txId, data, reply)
            POST_CODE -> handlePostTransact(txId, data, reply)
            else -> super.onTransact(code, data, reply, flags)
        }
    }

    private fun handlePreTransact(txId: Long, data: Parcel, reply: Parcel?): Boolean {
        try {
            val target = data.readStrongBinder()
            val txCode = data.readInt()
            val txFlags = data.readInt()
            val callingUid = data.readInt()
            val callingPid = data.readInt()

            val dataSize = data.readLong().toInt()
            val subData = Parcel.obtain()
            subData.appendFrom(data, data.dataPosition(), dataSize)
            subData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)

            val result = onPreTransact(txId, target, txCode, txFlags, callingUid, callingPid, subData)
            subData.recycle()

            if (reply == null) return true
            when (result) {
                is TransactionResult.Skip -> reply.writeInt(ACTION_SKIP)
                is TransactionResult.Continue -> reply.writeInt(ACTION_CONTINUE)
                is TransactionResult.OverrideReply -> {
                    reply.writeInt(ACTION_OVERRIDE_REPLY)
                    reply.writeInt(0)
                    reply.writeLong(result.parcel.dataSize().toLong())
                    reply.appendFrom(result.parcel, 0, result.parcel.dataSize())
                }
                is TransactionResult.OverrideData -> {
                    reply.writeInt(ACTION_OVERRIDE_DATA)
                    reply.writeLong(result.data.dataSize().toLong())
                    reply.appendFrom(result.data, 0, result.data.dataSize())
                    result.data.recycle()
                }
                is TransactionResult.ContinueAndSkipPost -> reply.writeInt(ACTION_SKIP_POST)
            }
        } catch (e: Exception) {
            Logger.e("handlePreTransact error", e)
            reply?.writeInt(ACTION_CONTINUE)
        }
        return true
    }

    private fun handlePostTransact(txId: Long, data: Parcel, reply: Parcel?): Boolean {
        try {
            val target = data.readStrongBinder()
            val txCode = data.readInt()
            val txFlags = data.readInt()
            val callingUid = data.readInt()
            val callingPid = data.readInt()

            val dataSize = data.readLong().toInt()
            val subData = Parcel.obtain()
            subData.appendFrom(data, data.dataPosition(), dataSize)
            subData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)

            val replySize = data.readLong()
            val subReply = if (replySize > 0) {
                val p = Parcel.obtain()
                p.appendFrom(data, data.dataPosition(), replySize.toInt())
                p.setDataPosition(0)
                p
            } else null
            if (replySize > 0)
                data.setDataPosition(data.dataPosition() + replySize.toInt())

            val resultCode = data.readInt()

            val result = onPostTransact(
                txId, target, txCode, txFlags,
                callingUid, callingPid, subData, subReply, resultCode
            )
            subData.recycle()

            if (reply == null) return true
            when (result) {
                is TransactionResult.OverrideReply -> {
                    reply.writeInt(ACTION_OVERRIDE_REPLY)
                    reply.writeInt(resultCode)
                    reply.writeLong(result.parcel.dataSize().toLong())
                    reply.appendFrom(result.parcel, 0, result.parcel.dataSize())
                }
                else -> reply.writeInt(ACTION_SKIP)
            }
        } catch (e: Exception) {
            Logger.e("handlePostTransact error", e)
            reply?.writeInt(ACTION_SKIP)
        }
        return true
    }

    companion object {
        val BACKDOOR_CODE = 0xfeedface.toInt()
        const val REGISTER_CODE = 1
        const val UNREGISTER_CODE = 2
        const val PRE_CODE = 3
        const val POST_CODE = 4

        const val ACTION_SKIP = 0
        const val ACTION_CONTINUE = 1
        const val ACTION_OVERRIDE_REPLY = 2
        const val ACTION_SKIP_POST = 3
        const val ACTION_OVERRIDE_DATA = 4

        fun getBackdoor(binder: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                if (binder.transact(BACKDOOR_CODE, data, reply, 0)) {
                    return reply.readStrongBinder()
                }
            } catch (_: Exception) {
            } finally {
                data.recycle()
                reply.recycle()
            }
            return null
        }

        fun register(backdoor: IBinder, target: IBinder, interceptor: BinderInterceptor) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                backdoor.transact(REGISTER_CODE, data, reply, 0)
            } catch (e: Exception) {
                Logger.e("Failed to register interceptor", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        fun unregister(backdoor: IBinder, target: IBinder) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                backdoor.transact(UNREGISTER_CODE, data, reply, 0)
            } catch (e: Exception) {
                Logger.e("Failed to unregister interceptor", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    }
}
