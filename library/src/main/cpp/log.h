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

#ifndef FM_LOG_H
#define FM_LOG_H

#include <fcntl.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#define LOG(fmt, ...) do { \
    __android_log_print(ANDROID_LOG_INFO, "ForgeStore", fmt, ##__VA_ARGS__); \
} while(0)
#define LOGD(fmt, ...) do { \
    __android_log_print(ANDROID_LOG_DEBUG, "ForgeStore", fmt, ##__VA_ARGS__); \
} while(0)
#else
#include <stdio.h>
#define LOG(fmt, ...)  fprintf(stderr, "ForgeStore [I] " fmt "\n", ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stderr, "ForgeStore [D] " fmt "\n", ##__VA_ARGS__)
#endif

#endif
