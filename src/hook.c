#include "hook.h"
#include "log.h"
#include "raplt.h"
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>
#include <unistd.h>

static struct fm_ctx *g_ctx;
static int (*g_orig_ioctl)(int, unsigned long, void *);

#define GENKEY_CODE 2

static int32_t rd_i32(const uint8_t **pp, const uint8_t *end)
{
    if (*pp + 4 > end) return -1;
    int32_t v; memcpy(&v, *pp, 4); *pp += 4;
    return v;
}

static void al4(uint8_t **pp)
{
    *pp = (uint8_t *)(((uintptr_t)*pp + 3) & ~3ULL);
}

static int skip_bytevec(uint8_t **pp, const uint8_t *end)
{
    int32_t len = rd_i32((const uint8_t **)pp, end);
    if (len < 0 || *pp + len > end) return -1;
    *pp += len;
    al4(pp);
    return 0;
}

static int skip_keyparam(uint8_t **pp, const uint8_t *end)
{
    if (*pp + 8 > end) return -1;
    *pp += 4;
    int32_t disc = rd_i32((const uint8_t **)pp, end);
    switch (disc) {
    case 0: case 1:
        if (*pp + 4 > end) return -1; *pp += 4; return 0;
    case 2: case 3:
        if (*pp + 8 > end) return -1; *pp += 8; return 0;
    case 4:
        return skip_bytevec(pp, end);
    case 5: {
        int32_t cnt = rd_i32((const uint8_t **)pp, end);
        for (int i = 0; i < cnt; i++)
            if (skip_bytevec(pp, end) < 0) return -1;
        return 0;
    }
    default:
        return -1;
    }
}

static uint8_t *find_certs(uint8_t *data, uint32_t size, int *out_cnt)
{
    uint8_t *end = data + size;
    uint8_t *p = data;
    if (skip_bytevec(&p, end) < 0) return NULL;
    if (p + 4 > end) return NULL;
    int32_t nc = rd_i32((const uint8_t **)&p, end);
    for (int i = 0; i < nc; i++) {
        if (p + 8 > end) return NULL;
        p += 4;
        int32_t np = rd_i32((const uint8_t **)&p, end);
        for (int j = 0; j < np; j++)
            if (skip_keyparam(&p, end) < 0) return NULL;
    }
    if (p + 4 > end) return NULL;
    *out_cnt = rd_i32((const uint8_t **)&p, end);
    return p;
}

static void replace_certs(uint8_t *start, int num, uint8_t *end)
{
    uint8_t *p = start;
    int n = num < g_ctx->key.num_certs ? num : g_ctx->key.num_certs;
    for (int i = 0; i < n; i++) {
        int32_t len = rd_i32((const uint8_t **)&p, end);
        if (len < 0) break;
        struct fm_cert *fc = &g_ctx->key.certs[i];
        if (fc->der_len == len) {
            memcpy(p, fc->der, len);
            LOG("replaced cert[%d] %d bytes", i, len);
        } else {
            LOG("cert[%d] size mismatch: orig=%d new=%d",
                i, len, fc->der_len);
        }
        p += len;
        al4(&p);
    }
}

static int hooked_ioctl(int fd, unsigned long request, void *arg)
{
    int ret = g_orig_ioctl(fd, request, arg);
    if (request == BINDER_WRITE_READ && g_ctx && g_ctx->ready && arg) {
        int32_t rc = (int32_t)((struct binder_write_read *)arg)->read_consumed;
        if (rc > 0)
            LOGD("WR fd=%d rc=%d", fd, rc);
    }
    if (ret < 0 || request != BINDER_WRITE_READ || !arg) return ret;

    struct binder_write_read *bwr = arg;
    if (bwr->read_consumed == 0) return ret;

    uint8_t *rp = (uint8_t *)bwr->read_buffer;
    uint8_t *re = rp + bwr->read_consumed;

    while (rp + 4 <= re) {
        uint32_t cmd = *(uint32_t *)rp;
        rp += 4;
        size_t cmd_sz = 0;

        switch (cmd) {
        case BR_REPLY: {
            cmd_sz = sizeof(struct binder_transaction_data);
            if (rp + cmd_sz > re) break;
            struct binder_transaction_data *tr = (struct binder_transaction_data *)rp;

            if (tr->code == GENKEY_CODE && tr->data.ptr.buffer && tr->data_size > 0) {
                LOG("BR code=%u size=%u ready=%d num=%d",
                    tr->code, (unsigned)tr->data_size,
                    g_ctx ? g_ctx->ready : -1,
                    g_ctx ? g_ctx->key.num_certs : -1);
                if (g_ctx && g_ctx->ready && g_ctx->key.num_certs > 0) {
                    int cnt = 0;
                    uint8_t *cs = find_certs((uint8_t *)tr->data.ptr.buffer,
                                              tr->data_size, &cnt);
                    if (cs && cnt > 0)
                        replace_certs(cs, cnt,
                            (uint8_t *)tr->data.ptr.buffer + tr->data_size);
                    else
                        LOG("find_certs: cs=%p cnt=%d", cs, cnt);
                }
            }
            break;
        }
        default: {
            size_t sz = _IOC_SIZE(cmd);
            if (sz >= sizeof(uint32_t) * 6 && rp + sz <= re) {
                struct binder_transaction_data *tr;
                tr = (struct binder_transaction_data *)rp;
                LOG("cmd=0x%x code=%u sz=%zu dsz=%u",
                    cmd, tr->code, sz, (unsigned)tr->data_size);
                if (tr->code == GENKEY_CODE && tr->data.ptr.buffer
                    && tr->data_size > 0 && g_ctx && g_ctx->ready
                    && g_ctx->key.num_certs > 0) {
                    int cnt = 0;
                    uint8_t *cs = find_certs((uint8_t *)tr->data.ptr.buffer,
                                              tr->data_size, &cnt);
                    if (cs && cnt > 0)
                        replace_certs(cs, cnt,
                            (uint8_t *)tr->data.ptr.buffer + tr->data_size);
                }
            }
            cmd_sz = sz;
            break;
        }
        }
        rp += cmd_sz;
    }
    return ret;
}

int fm_hook_init(struct fm_ctx *ctx)
{
    g_ctx = ctx;

    void *orig = NULL;
    raplt_hook_t *h = raplt_register(".*libbinder\\.so$", "ioctl",
                                       (void *)hooked_ioctl, &orig, 0);
    if (!h) {
        LOG("no ioctl in libbinder.so GOT");
        return -1;
    }
    g_orig_ioctl = (__typeof(g_orig_ioctl))orig;
    LOG("ioctl hook installed on libbinder.so");
    return 0;
}
