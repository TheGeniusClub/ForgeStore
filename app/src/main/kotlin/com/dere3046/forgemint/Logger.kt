/*
 * Copyright (C) 2026  TheGeniusClub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <https://www.gnu.org/licenses/>.
 */

package com.dere3046.forgemint

import android.util.Log

object Logger {
    private const val TAG = "ForgeMint"

    @Volatile var useLogcat = false
    @Volatile var verbose = false

    fun setMode(debugMode: Boolean) {
        useLogcat = debugMode
        if (!debugMode) {
            KmsgLogger.init()
        }
    }

    private fun logd(msg: String) {
        if (useLogcat) {
            Log.d(TAG, msg)
        } else if (!KmsgLogger.write(7, TAG, msg)) {
            Log.d(TAG, msg)
        }
    }

    private fun logi(msg: String) {
        if (useLogcat) {
            Log.i(TAG, msg)
        } else if (!KmsgLogger.write(5, TAG, msg)) {
            Log.i(TAG, msg)
        }
    }

    private fun logw(msg: String) {
        if (useLogcat) {
            Log.w(TAG, msg)
        } else if (!KmsgLogger.write(4, TAG, msg)) {
            Log.w(TAG, msg)
        }
    }

    private fun loge(msg: String) {
        if (useLogcat) {
            Log.e(TAG, msg)
        } else if (!KmsgLogger.write(3, TAG, msg)) {
            Log.e(TAG, msg)
        }
    }

    fun d(msg: String) { if (verbose) logd(msg) }
    fun i(msg: String) { if (verbose) logi(msg) }
    fun w(msg: String) = logw(msg)
    fun w(msg: String, t: Throwable) = Log.w(TAG, msg, t)
    fun e(msg: String, t: Throwable? = null) {
        if (t != null) {
            Log.e(TAG, msg, t)
        } else {
            loge(msg)
        }
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
