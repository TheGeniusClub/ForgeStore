package com.dere3046.forgemint

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata

class Keystore2Interceptor : BinderInterceptor() {

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_KEY_ENTRY_TRANSACTION) {
            return handleGetKeyEntry(data, callingUid)
        }
        if (code == DELETE_KEY_TRANSACTION) {
            return handleDeleteKey(data, callingUid)
        }
        if (shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }
        return TransactionResult.Continue
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (resultCode != 0 || reply == null) return TransactionResult.Skip
        if (shouldSkip(callingUid)) return TransactionResult.Skip

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            return injectGeneratedKeys(reply, callingUid)
        }

        return TransactionResult.Skip
    }

    private fun handleGetKeyEntry(data: Parcel, uid: Int): TransactionResult {
        try {
            data.readInt()
            data.readString()
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val alias = descriptor.alias ?: return TransactionResult.Continue

            val entry = StateManager.lookup(uid, alias) ?: return TransactionResult.Continue

            Logger.i("getKeyEntry alias=$alias UID=$uid → returning generated key")

            val response = KeyEntryResponse().apply {
                metadata = entry.metadata
                iSecurityLevel = entry.securityLevelBinder
            }
            val reply = Parcel.obtain()
            reply.writeNoException()
            reply.writeTypedObject(response, 0)
            return TransactionResult.OverrideReply(reply)
        } catch (e: Exception) {
            Logger.e("getKeyEntry failed", e)
            return TransactionResult.Continue
        }
    }

    private fun handleDeleteKey(data: Parcel, uid: Int): TransactionResult {
        try {
            data.readInt()
            data.readString()
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.Continue
            val alias = descriptor.alias ?: return TransactionResult.Continue

            if (StateManager.lookup(uid, alias) != null) {
                Logger.i("deleteKey alias=$alias UID=$uid → cleaning up")
                StateManager.remove(uid, alias)
            }
        } catch (_: Exception) {}
        return TransactionResult.Continue
    }

    private fun injectGeneratedKeys(reply: Parcel, uid: Int): TransactionResult {
        try {
            reply.readException()
            val entries = reply.createTypedArray(KeyDescriptor.CREATOR)?.toMutableList()
                ?: return TransactionResult.Skip

            val generated = StateManager.listForUid(uid)
            for (gk in generated) {
                entries.add(KeyDescriptor().apply {
                    domain = Domain.KEY_ID
                    nspace = gk.nspace
                    alias = gk.alias
                    blob = null
                })
            }

            Logger.i("listEntries injected ${generated.size} keys for UID=$uid (total=${entries.size})")

            val override = Parcel.obtain()
            override.writeNoException()
            override.writeTypedArray(entries.toTypedArray(), 0)
            return TransactionResult.OverrideReply(override)
        } catch (e: Exception) {
            Logger.e("listEntries injection failed", e)
            return TransactionResult.Skip
        }
    }

    private fun shouldSkip(uid: Int): Boolean {
        return uid < 10000 || ConfigManager.shouldSkip(uid)
    }

    companion object {
        val LIST_ENTRIES_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_listEntries") }
        val LIST_ENTRIES_BATCHED_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_listEntriesBatched") }
        val GET_KEY_ENTRY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_getKeyEntry") }
        val DELETE_KEY_TRANSACTION: Int by lazy { resolveCode("TRANSACTION_deleteKey") }

        private fun resolveCode(name: String): Int {
            return try {
                IKeystoreService.Stub::class.java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .getInt(null)
            } catch (e: Exception) {
                Logger.e("Failed to resolve $name", e)
                -1
            }
        }
    }
}
