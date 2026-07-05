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

package com.dere3046.forgestore

import android.util.Log

object KmsgLogger {

    private var available = false

    fun init() {
        try {
            System.loadLibrary("forgestore_kmsg")
            available = true
        } catch (_: UnsatisfiedLinkError) {
            Log.w("ForgeStore", "kmsg native lib not available, falling back to logcat")
        }
    }

    fun write(priority: Int, tag: String, message: String): Boolean {
        return if (available) nativeLog(priority, tag, message) else false
    }

    @JvmStatic
    private external fun nativeLog(priority: Int, tag: String, message: String): Boolean
}
