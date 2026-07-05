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

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static int kmsg_fd = -1;

__attribute__((constructor))
static void init_kmsg(void) {
    kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
}

__attribute__((destructor))
static void close_kmsg(void) {
    if (kmsg_fd >= 0) close(kmsg_fd);
}

JNIEXPORT jboolean JNICALL
Java_com_dere3046_forgestore_KmsgLogger_nativeLog(
    JNIEnv *env, jclass cls, jint priority, jstring jtag, jstring jmsg)
{
    (void)cls;
    if (kmsg_fd < 0) return JNI_FALSE;

    const char *tag = (*env)->GetStringUTFChars(env, jtag, NULL);
    const char *msg = (*env)->GetStringUTFChars(env, jmsg, NULL);
    if (!tag || !msg) return JNI_FALSE;

    char buf[4096];
    int len = snprintf(buf, sizeof(buf), "<%d>%s: %s\n", priority, tag, msg);

    ssize_t written = write(kmsg_fd, buf, (size_t)len);

    (*env)->ReleaseStringUTFChars(env, jtag, tag);
    (*env)->ReleaseStringUTFChars(env, jmsg, msg);

    return written >= 0 ? JNI_TRUE : JNI_FALSE;
}
