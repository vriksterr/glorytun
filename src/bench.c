#include "common.h"
#include "argz.h"

#include <inttypes.h>
#include <sodium.h>
#include <time.h>
#include <pthread.h>

#include "../mud/aegis256/aegis256.h"

#define NPUBBYTES 32
#define KEYBYTES  32
#define ABYTES    16

/* Mirrors mud.c's own MUD_WORKERS_MAX cap, so "multicore" spawns the same
 * number of participants a real tunnel would use on this box. */
#define GT_BENCH_WORKERS_MAX (8U)

struct gt_bench_params {
    int64_t size;
    int fallback;
    unsigned char npub[NPUBBYTES];
    unsigned char key[KEYBYTES];
    uint64_t deadline_ns;
};

static uint64_t
gt_bench_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void
gt_bench_encrypt(unsigned char *buf, const struct gt_bench_params *p)
{
    if (p->fallback) {
        crypto_aead_chacha20poly1305_encrypt(
            buf, NULL, buf, p->size, NULL, 0, NULL, p->npub, p->key);
    } else {
        aegis256_encrypt(buf, NULL, buf, p->size, NULL, 0, p->npub, p->key);
    }
}

/* "ceiling" workers: fully independent, no shared state at all -- the
 * theoretical max throughput if every core encrypted flat-out with zero
 * coordination cost. */
struct gt_bench_ceiling_ctx {
    struct gt_bench_params p;
    int64_t bytes;
};

static void *
gt_bench_ceiling_worker(void *arg)
{
    struct gt_bench_ceiling_ctx *ctx = arg;
    unsigned char buf[1450 + ABYTES];
    memset(buf, 0, sizeof(buf));

    int64_t bytes = 0;

    while (gt_bench_now_ns() < ctx->p.deadline_ns) {
        gt_bench_encrypt(buf, &ctx->p);
        bytes += ctx->p.size;
    }
    ctx->bytes = bytes;
    return NULL;
}

/* "pool" workers: share one mutex-guarded job counter -- unlock before the
 * crypto call, relock after to update shared state. This models a
 * shared-dispatch design's coordination cost in isolation; it does not
 * mirror mud.c's current implementation, which gives each worker thread
 * its own full pipeline with no shared per-packet job queue at all (see
 * mud_worker_loop()) -- there, the only shared locking is brief
 * bookkeeping around path/session state, never around the crypto call
 * itself. Kept as a reference point for how much a shared-dispatch
 * approach would have cost, not as a model of the real overhead today. */
struct gt_bench_pool_shared {
    struct gt_bench_params p;
    pthread_mutex_t lock;
    int64_t jobs_done;
};

static void *
gt_bench_pool_worker(void *arg)
{
    struct gt_bench_pool_shared *shared = arg;
    unsigned char buf[1450 + ABYTES];
    memset(buf, 0, sizeof(buf));

    pthread_mutex_lock(&shared->lock);

    for (;;) {
        if (gt_bench_now_ns() >= shared->p.deadline_ns) {
            pthread_mutex_unlock(&shared->lock);
            return NULL;
        }
        pthread_mutex_unlock(&shared->lock);

        gt_bench_encrypt(buf, &shared->p);

        pthread_mutex_lock(&shared->lock);
        shared->jobs_done++;
    }
}

static unsigned
gt_bench_nthreads(void)
{
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    unsigned n = (ncpu > 1) ? (unsigned)ncpu : 1;

    if (n > GT_BENCH_WORKERS_MAX + 1)
        n = GT_BENCH_WORKERS_MAX + 1;

    return n;
}

static void
gt_bench_multicore(int fallback, int term,
                   const unsigned char *npub, const unsigned char *key)
{
    unsigned nthreads = gt_bench_nthreads();
    const uint64_t sample_ns = 300 * UINT64_C(1000000); /* 300ms/sample */

    if (term) {
        printf("bench %s multicore (%u threads)\n", GT_CIPHER(fallback), nthreads);
        printf("  size        ceiling             pool          overhead\n");
        printf("---------------------------------------------------------\n");
    }
    int64_t size = 20;

    for (int i = 0; !gt_quit && size <= 1450; i++) {
        /* --- ceiling --- */
        struct gt_bench_ceiling_ctx cctx[GT_BENCH_WORKERS_MAX + 1];
        pthread_t ctid[GT_BENCH_WORKERS_MAX];
        uint64_t c_start = gt_bench_now_ns();

        for (unsigned t = 0; t < nthreads; t++) {
            cctx[t].p.size = size;
            cctx[t].p.fallback = fallback;
            memcpy(cctx[t].p.npub, npub, NPUBBYTES);
            memcpy(cctx[t].p.key, key, KEYBYTES);
            cctx[t].p.deadline_ns = c_start + sample_ns;
            cctx[t].bytes = 0;
        }
        for (unsigned t = 1; t < nthreads; t++)
            pthread_create(&ctid[t - 1], NULL, gt_bench_ceiling_worker, &cctx[t]);

        gt_bench_ceiling_worker(&cctx[0]);

        int64_t ceiling_bytes = cctx[0].bytes;

        for (unsigned t = 1; t < nthreads; t++) {
            pthread_join(ctid[t - 1], NULL);
            ceiling_bytes += cctx[t].bytes;
        }
        uint64_t c_elapsed = gt_bench_now_ns() - c_start;

        /* --- pool --- */
        struct gt_bench_pool_shared pshared = {0};
        pshared.p.size = size;
        pshared.p.fallback = fallback;
        memcpy(pshared.p.npub, npub, NPUBBYTES);
        memcpy(pshared.p.key, key, KEYBYTES);
        pthread_mutex_init(&pshared.lock, NULL);

        pthread_t ptid[GT_BENCH_WORKERS_MAX];
        uint64_t p_start = gt_bench_now_ns();
        pshared.p.deadline_ns = p_start + sample_ns;

        for (unsigned t = 1; t < nthreads; t++)
            pthread_create(&ptid[t - 1], NULL, gt_bench_pool_worker, &pshared);

        gt_bench_pool_worker(&pshared);

        for (unsigned t = 1; t < nthreads; t++)
            pthread_join(ptid[t - 1], NULL);

        uint64_t p_elapsed = gt_bench_now_ns() - p_start;
        pthread_mutex_destroy(&pshared.lock);

        int64_t pool_bytes = pshared.jobs_done * size;

        int64_t ceiling_mbps = (int64_t)
            ((8.0 * (double)ceiling_bytes * 1000.0) / (double)c_elapsed);
        int64_t pool_mbps = (int64_t)
            ((8.0 * (double)pool_bytes * 1000.0) / (double)p_elapsed);
        int64_t overhead_pct = ceiling_mbps
                              ? (100 * (ceiling_mbps - pool_mbps)) / ceiling_mbps
                              : 0;

        if (term) {
            printf(" %5"PRIi64" %9"PRIi64" Mbps %9"PRIi64" Mbps %9"PRIi64"%%\n",
                    size, ceiling_mbps, pool_mbps, overhead_pct);
        } else {
            printf("bench %s multicore %u %"PRIi64" %"PRIi64" %"PRIi64"\n",
                    GT_CIPHER(fallback), nthreads, size, ceiling_mbps, pool_mbps);
        }
        size += 2 * 5 * 13;
    }
}

int
gt_bench(int argc, char **argv, void *data)
{
    struct argz z[] = {
        {"fallback",  "Bench fallback cipher"},
        {"multicore", "Also bench aggregate multi-core throughput: "
                      "independent-worker ceiling vs glorytun's own "
                      "pooled/locked throughput"},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return -1;
    }
    int term = isatty(1);
    int fallback = argz_is_set(z, "fallback");

    if (!fallback && !aegis256_is_available()) {
        gt_log("%s is not available on your platform\n", GT_CIPHER(0));
        return -1;
    }
    unsigned char buf[1450 + ABYTES];
    unsigned char npub[NPUBBYTES];
    unsigned char key[KEYBYTES];

    memset(buf, 0, sizeof(buf));
    randombytes_buf(npub, sizeof(npub));
    randombytes_buf(key, sizeof(key));

    if (argz_is_set(z, "multicore")) {
        gt_bench_multicore(fallback, term, npub, key);
        return 0;
    }

    if (term) {
        printf("bench %s\n", GT_CIPHER(fallback));
        printf("  size       min           mean            max      \n");
        printf("----------------------------------------------------\n");
    }
    int64_t size = 20;

    for (int i = 0; !gt_quit && size <= 1450; i++) {
        struct {
            int64_t min, mean, max, n;
        } mbps = {.n = 0};

        int64_t bytes_max = (int64_t)1 << 24;

        while (!gt_quit && mbps.n < 10) {
            int64_t bytes = 0;
            int64_t base = (int64_t)clock();

            while (!gt_quit && bytes <= bytes_max) {
                if (fallback) {
                    crypto_aead_chacha20poly1305_encrypt(
                        buf, NULL, buf, size, NULL, 0, NULL, npub, key);
                } else {
                    aegis256_encrypt(buf, NULL, buf, size, NULL, 0, npub, key);
                }
                bytes += size;
            }
            int64_t dt = (int64_t)clock() - base;
            bytes_max = (bytes * (CLOCKS_PER_SEC / 3)) / dt;
            int64_t _mbps = (8 * bytes * CLOCKS_PER_SEC) / (dt * 1000 * 1000);

            if (!mbps.n++) {
                mbps.min = _mbps;
                mbps.max = _mbps;
                mbps.mean = _mbps;
                continue;
            }
            if (mbps.min > _mbps)
                mbps.min = _mbps;

            if (mbps.max < _mbps)
                mbps.max = _mbps;

            mbps.mean += (_mbps - mbps.mean) / mbps.n;

            if (term) {
                printf("\r %5"PRIi64" %9"PRIi64" Mbps %9"PRIi64" Mbps %9"PRIi64" Mbps",
                        size, mbps.min, mbps.mean, mbps.max);
                fflush(stdout);
            }
        }
        if (term) {
            printf("\n");
        } else {
            printf("bench %s %"PRIi64" %"PRIi64" %"PRIi64" %"PRIi64"\n",
                    GT_CIPHER(fallback), size, mbps.min, mbps.mean, mbps.max);
        }
        size += 2 * 5 * 13;
    }
    return 0;
}
