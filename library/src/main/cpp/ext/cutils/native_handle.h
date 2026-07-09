#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct native_handle {
    int version;
    int numFds;
    int numInts;
    int data[0];
} native_handle_t;

static inline native_handle_t *native_handle_create(int numFds, int numInts) {
    native_handle_t *h = (native_handle_t *)malloc(sizeof(native_handle_t) + sizeof(int) * (numFds + numInts));
    if (h) { h->version = sizeof(native_handle_t); h->numFds = numFds; h->numInts = numInts; }
    return h;
}
static inline void native_handle_close(const native_handle_t *h) { (void)h; }
static inline void native_handle_delete(native_handle_t *h) { free(h); }
