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

#include "hook.h"
#include "log.h"
#include "raplt.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <queue>

using namespace android;

#define BACKDOOR_CODE   0xfeedface
#define REGISTER_CODE   1
#define UNREGISTER_CODE 2
#define PRE_CODE        3
#define POST_CODE       4

#define ACTION_SKIP             0
#define ACTION_CONTINUE         1
#define ACTION_OVERRIDE_REPLY   2
#define ACTION_SKIP_POST        3
#define ACTION_OVERRIDE_DATA    4

static int (*g_orig_ioctl)(int, unsigned long, ...);

struct ThreadTxInfo {
    uint64_t tx_id;
    uint32_t code;
    uint32_t uid;
    uint32_t pid;
    sp<IBinder> callback;
    sp<BBinder> target;
};

static std::mutex g_thread_mutex;
static std::map<std::thread::id, std::queue<ThreadTxInfo>> g_thread_map;

static std::shared_mutex g_registry_mutex;
static std::map<wp<IBinder>, sp<IBinder>> g_registry;
static std::atomic<uint64_t> g_tx_id_counter = 0;

class BinderInterceptor : public BBinder {
public:
    status_t onTransact(uint32_t code, const Parcel &data,
                        Parcel *reply, uint32_t flags) override;
};

class BinderStub : public BBinder {
public:
    status_t onTransact(uint32_t code, const Parcel &data,
                        Parcel *reply, uint32_t flags) override;
};

static sp<BinderInterceptor> g_interceptor;
static sp<BinderStub> g_stub;
static bool g_stub_ready = false;

status_t BinderInterceptor::onTransact(uint32_t code, const Parcel &data,
                                        Parcel *reply, uint32_t flags)
{
    LOG("BinderInterceptor onTransact code=0x%x flags=%u", code, flags);
    switch (code) {
    case REGISTER_CODE: {
        sp<IBinder> target, callback;
        if (data.readStrongBinder(&target) != OK || !target) return BAD_VALUE;
        if (data.readStrongBinder(&callback) != OK || !callback) return BAD_VALUE;
        if (!target->localBinder()) return BAD_TYPE;

        std::unique_lock lock(g_registry_mutex);
        g_registry[target] = callback;
        LOG("registered binder %p", target.get());
        return OK;
    }
    case UNREGISTER_CODE: {
        sp<IBinder> target;
        if (data.readStrongBinder(&target) != OK || !target) return BAD_VALUE;
        std::unique_lock lock(g_registry_mutex);
        g_registry.erase(target);
        LOG("unregistered binder %p", target.get());
        return OK;
    }
    }
    return BBinder::onTransact(code, data, reply, flags);
}

status_t BinderStub::onTransact(uint32_t code, const Parcel &data,
                                 Parcel *reply, uint32_t flags)
{
    LOG("BinderStub onTransact code=0x%x flags=%u", code, flags);

    ThreadTxInfo info = {};
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(g_thread_mutex);
        auto it = g_thread_map.find(std::this_thread::get_id());
        if (it != g_thread_map.end() && !it->second.empty()) {
            info = std::move(it->second.front());
            it->second.pop();
            if (it->second.empty())
                g_thread_map.erase(it);
            found = true;
        }
    }

    LOG("BinderStub found=%d info.code=0x%x info.target=%p", found, info.code, info.target.get());

    if (!found || !info.target) {
        if (code == BACKDOOR_CODE && reply) {
            LOG("BinderStub writing backdoor binder");
            reply->writeStrongBinder(g_interceptor);
            return OK;
        }
        return UNKNOWN_TRANSACTION;
    }

    sp<BBinder> real_target = info.target;
    sp<IBinder> callback = info.callback;

    Parcel final_data;
    bool use_modified_data = false;

    Parcel pre_req, pre_resp;
    pre_req.writeInt64(info.tx_id);
    pre_req.writeStrongBinder(real_target);
    pre_req.writeUint32(info.code);
    pre_req.writeUint32(flags);
    pre_req.writeInt32(IPCThreadState::self()->getCallingUid());
    pre_req.writeInt32(IPCThreadState::self()->getCallingPid());
    pre_req.writeUint64(data.dataSize());
    pre_req.appendFrom(&data, 0, data.dataSize());

    status_t cb_status = OK;
    if (callback != nullptr) {
        if (!callback->isBinderAlive()) {
            LOG("deadman: interceptor daemon is dead, blocking transaction");
            return DEAD_OBJECT;
        }
        status_t pre_result = callback->transact(PRE_CODE, pre_req, &pre_resp);
        if (pre_result != OK) {
            LOG("warn: PRE transact failed (result=%d), forwarding unmodified", pre_result);
        } else {
            int32_t action = pre_resp.readInt32();
            if (action == ACTION_OVERRIDE_REPLY) {
                status_t result;
                if (pre_resp.readInt32(&result) == OK) {
                    size_t sz = pre_resp.readUint64();
                    if (reply && sz > 0)
                        reply->appendFrom(&pre_resp, pre_resp.dataPosition(), sz);
                    return result;
                }
            }
            if (action == ACTION_SKIP)
                return OK;
            if (action == ACTION_SKIP_POST)
                cb_status = (status_t)-1;
            if (action == ACTION_OVERRIDE_DATA) {
                size_t sz = pre_resp.readUint64();
                final_data.appendFrom(&pre_resp, pre_resp.dataPosition(), sz);
                use_modified_data = true;
            }
        }
    }

    status_t result = real_target->transact(info.code,
        use_modified_data ? final_data : data, reply, flags);

    if (cb_status != (status_t)-1 && callback && result == OK) {
        Parcel post_req, post_resp;
        post_req.writeInt64(info.tx_id);
        post_req.writeStrongBinder(real_target);
        post_req.writeUint32(info.code);
        post_req.writeUint32(flags);
        post_req.writeInt32(IPCThreadState::self()->getCallingUid());
        post_req.writeInt32(IPCThreadState::self()->getCallingPid());
        const Parcel &post_data = use_modified_data ? final_data : data;
        post_req.writeUint64(post_data.dataSize());
        post_req.appendFrom(&post_data, 0, post_data.dataSize());

        size_t reply_sz = reply ? reply->dataSize() : 0;
        post_req.writeUint64(reply_sz);
        if (reply && reply_sz > 0)
            post_req.appendFrom(reply, 0, reply_sz);
        post_req.writeInt32(result);

        if (callback->transact(POST_CODE, post_req, &post_resp) == OK) {
            int32_t action = post_resp.readInt32();
            if (action == ACTION_OVERRIDE_REPLY && reply) {
                status_t new_result;
                if (post_resp.readInt32(&new_result) == OK) {
                    size_t new_sz = post_resp.readUint64();
                    reply->setDataSize(0);
                    if (new_sz > 0)
                        reply->appendFrom(&post_resp, post_resp.dataPosition(), new_sz);
                    result = new_result;
                }
            }
        }
    }

    return result;
}

static int hooked_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    if (!g_stub_ready)
        return g_orig_ioctl(fd, request, arg);

    int ret = g_orig_ioctl(fd, request, arg);
    if (ret < 0 || request != BINDER_WRITE_READ || !arg) return ret;

    auto *bwr = (struct binder_write_read *)arg;
    if (bwr->read_size == 0 || bwr->read_consumed == 0 || !bwr->read_buffer) return ret;

    uintptr_t ptr = (uintptr_t)bwr->read_buffer;
    uintptr_t end  = ptr + bwr->read_consumed;

    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t cmd = *(uint32_t *)ptr;
        ptr += 4;
        size_t cmd_sz = _IOC_SIZE(cmd);

        if (cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX) {
            if (ptr + cmd_sz > end) break;

            auto *tr = (cmd == BR_TRANSACTION_SEC_CTX)
                ? &((binder_transaction_data_secctx *)ptr)->transaction_data
                : (struct binder_transaction_data *)ptr;
            if (!tr || !tr->target.ptr || !tr->cookie) goto next;

            BBinder *target = nullptr;
            bool hijack = false;
            ThreadTxInfo info = {};
            info.tx_id = ++g_tx_id_counter;

            if (tr->code == BACKDOOR_CODE && tr->sender_euid == 0) {
                LOG("BACKDOOR matched (root), hijacking tx_id=%llu", (unsigned long long)info.tx_id);
                hijack = true;
                info.code = BACKDOOR_CODE;
                info.target = nullptr;
                info.callback = nullptr;
            } else if (tr->sender_euid == 0) {
                tr->sender_euid = 1000;
                LOGD("Spoofed UID 0 → 1000 for code=0x%x", tr->code);
            } else {
                RefBase::weakref_type *weak_ref = reinterpret_cast<RefBase::weakref_type *>(tr->target.ptr);
                if (weak_ref && weak_ref->attemptIncStrong(nullptr)) {
                    target = reinterpret_cast<BBinder *>(tr->cookie);
                    wp<IBinder> wp_target = target;
                    LOG("BR code=0x%x cookie=%llx uid=%d pid=%d", tr->code, (unsigned long long)tr->cookie, tr->sender_euid, tr->sender_pid);

                    {
                        std::shared_lock lock(g_registry_mutex);
                        auto it = g_registry.find(wp_target);
                        if (it != g_registry.end()) {
                            info.code     = tr->code;
                            info.target   = target;
                            info.callback = it->second;
                            hijack = true;
                        }
                    }

                    target->decStrong(nullptr);
                }
            }

            if (hijack) {
                info.uid = tr->sender_euid;
                info.pid = tr->sender_pid;

                {
                    std::lock_guard<std::mutex> lock(g_thread_mutex);
                    g_thread_map[std::this_thread::get_id()].push(std::move(info));
                }

                tr->target.ptr = reinterpret_cast<uintptr_t>(g_stub->getWeakRefs());
                tr->cookie     = reinterpret_cast<uintptr_t>(g_stub.get());
                tr->code       = BACKDOOR_CODE;
            }
        }

next:
        ptr += cmd_sz;
    }

    return ret;
}

extern "C" int fm_hook_init(void)
{
    const char *libs[] = {".*libbinder\\.so$", NULL};
    void *orig = NULL;
    raplt_hook_t *h = NULL;

    for (int i = 0; libs[i]; i++) {
        h = raplt_register(libs[i], "ioctl", (void*)hooked_ioctl, &orig, 0);
        if (h) break;
    }
    if (!h) { LOG("ioctl not found"); return -1; }
    g_orig_ioctl = (decltype(g_orig_ioctl))orig;
    LOG("ioctl hook OK");

    g_interceptor = sp<BinderInterceptor>::make();
    g_stub       = sp<BinderStub>::make();
    g_stub_ready = true;
    LOG("stub ready");
    return 0;
}
