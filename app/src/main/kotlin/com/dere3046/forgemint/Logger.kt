package com.dere3046.forgemint

import android.util.Log
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

object Logger {
    private const val TAG = "ForgeMint"

    private const val RATE_LIMIT_BURST = 15
    private const val RATE_LIMIT_WINDOW_MS = 1000L
    private val windowStart = AtomicLong(System.currentTimeMillis())
    private val windowCount = AtomicInteger(0)
    private val suppressedCount = AtomicInteger(0)

    private fun acquireLogPermit(): Boolean {
        val now = System.currentTimeMillis()
        val start = windowStart.get()
        if (now - start > RATE_LIMIT_WINDOW_MS) {
            if (windowStart.compareAndSet(start, now)) {
                val suppressed = suppressedCount.getAndSet(0)
                windowCount.set(1)
                if (suppressed > 0) {
                    Log.i(TAG, "[rate-limit] suppressed $suppressed log messages in previous window")
                }
                return true
            }
        }
        val count = windowCount.incrementAndGet()
        if (count <= RATE_LIMIT_BURST) return true
        suppressedCount.incrementAndGet()
        return false
    }

    fun d(msg: String) {
        if (!acquireLogPermit()) return
        Log.d(TAG, msg)
    }

    fun i(msg: String) {
        if (!acquireLogPermit()) return
        Log.i(TAG, msg)
    }

    fun w(msg: String) {
        Log.w(TAG, msg)
    }

    fun w(msg: String, t: Throwable) {
        Log.w(TAG, msg, t)
    }

    fun e(msg: String, t: Throwable? = null) {
        if (t != null) Log.e(TAG, msg, t) else Log.e(TAG, msg)
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
