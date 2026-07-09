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

import android.util.Log

object Logger {
    private const val TAG = "ForgeStore"

    @Volatile var enabled = false
    @Volatile var verbose = false

    fun d(msg: String) { if (verbose && enabled) Log.d(TAG, msg) }
    fun i(msg: String) { if (verbose && enabled) Log.i(TAG, msg) }
    fun w(msg: String) { if (enabled) Log.w(TAG, msg) }
    fun w(msg: String, t: Throwable) { if (enabled) Log.w(TAG, msg, t) }
    fun e(msg: String, t: Throwable? = null) {
        if (!enabled) return
        if (t != null) Log.e(TAG, msg, t) else Log.e(TAG, msg)
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
