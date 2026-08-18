#include "common.h"
#include "ctl.h"
#include "argz.h"
#include "path_manager.h"

#include <time.h>

static const char *
gt_path_status_text(struct ctl_msg *res)
{
    switch (res->path_availability) {
        case GT_PATH_INTERFACE_DOWN:  return "interface-down";
        case GT_PATH_WAITING_ADDRESS: return "waiting-address";
        case GT_PATH_ADMIN_DOWN:      return "down";
    }
    switch (res->path.status) {
        case MUD_DELETING: return "deleting";
        case MUD_PROBING:  return "probing";
        case MUD_DEGRADED: return "degraded";
        case MUD_LOSSY:    return "lossy";
        case MUD_LATE:     return "late";
        case MUD_WAITING:  return "waiting";
        case MUD_READY:    return "ready";
        case MUD_RUNNING:  return "running";
        default:           return "waiting";
    }
}

/* Two rows belong under the same group header if they're sub-flows of the
 * same logical path -- same interface (or both legacy/no interface) and
 * same remote endpoint, differing only in conf.sock. */
static int
gt_path_same_group(struct ctl_msg *a, struct ctl_msg *b)
{
    if (strcmp(a->ifname, b->ifname))
        return 0;

    char ra[INET6_ADDRSTRLEN], rb[INET6_ADDRSTRLEN];
    gt_toaddr(ra, sizeof(ra), &a->path.conf.remote);
    gt_toaddr(rb, sizeof(rb), &b->path.conf.remote);

    return !strcmp(ra, rb) &&
           gt_get_port(&a->path.conf.remote) == gt_get_port(&b->path.conf.remote);
}

static int
gt_path_remote_equal(const union mud_sockaddr *a, const union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == AF_INET)
        return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr &&
               a->sin.sin_port == b->sin.sin_port;
    if (a->sa.sa_family == AF_INET6)
        return !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                       sizeof(a->sin6.sin6_addr)) &&
               a->sin6.sin6_port == b->sin6.sin6_port;
    return 0;
}

static uint64_t
gt_path_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

struct gt_path_sample {
    int valid;
    char ifname[IFNAMSIZ];
    union mud_sockaddr remote;
    unsigned char sock;
    uint64_t tx_bytes, rx_bytes;
    uint64_t time_ns;
};

/* Live per-sub-flow throughput isn't exposed by the daemon at all -- tx.rate
 * is the AIMD-computed *allowed* rate, not what's actually moving, so an
 * idle sub-flow can still show a healthy tx.rate long after it stopped
 * carrying anything. This computes a real observed rate entirely client-
 * side instead: diff this call's cumulative tx.bytes/rx.bytes against the
 * previous call's, over the wall-clock time actually elapsed between them.
 * Requires two samples, so it only produces a number in `watch` mode (a
 * single one-shot query has nothing prior to diff against) -- *tx_bps/
 * *rx_bps are left at -1 to mean "no data yet" in that case. */
static void
gt_path_track_rate(struct ctl_msg *res, double *tx_bps, double *rx_bps)
{
    static struct gt_path_sample samples[MUD_PATH_MAX * 2];

    *tx_bps = -1;
    *rx_bps = -1;

    const uint64_t now = gt_path_now_ns();
    struct gt_path_sample *slot = NULL, *free_slot = NULL;

    for (unsigned int i = 0; i < MUD_PATH_MAX * 2; i++) {
        struct gt_path_sample *s = &samples[i];

        if (!s->valid) {
            if (!free_slot)
                free_slot = s;
            continue;
        }
        if (!strcmp(s->ifname, res->ifname) &&
            s->sock == res->path.conf.sock &&
            gt_path_remote_equal(&s->remote, &res->path.conf.remote)) {
            slot = s;
            break;
        }
    }
    if (!slot)
        slot = free_slot;

    if (slot && slot->valid) {
        const uint64_t dt = now - slot->time_ns;

        if (dt >= 100 * UINT64_C(1000000) &&
            res->path.tx.bytes >= slot->tx_bytes &&
            res->path.rx.bytes >= slot->rx_bytes) {
            *tx_bps = (double)(res->path.tx.bytes - slot->tx_bytes) *
                      8.0 * 1e9 / (double)dt;
            *rx_bps = (double)(res->path.rx.bytes - slot->rx_bytes) *
                      8.0 * 1e9 / (double)dt;
        }
    }
    if (slot) {
        slot->valid = 1;
        memcpy(slot->ifname, res->ifname, sizeof(slot->ifname));
        slot->sock = res->path.conf.sock;
        slot->remote = res->path.conf.remote;
        slot->tx_bytes = res->path.tx.bytes;
        slot->rx_bytes = res->path.rx.bytes;
        slot->time_ns = now;
    }
}

/* Fixed Mbps (megabits/second) rather than gt_torate()'s dynamic bit/kbit/
 * Mbit/Gbit scaling -- easier to scan a column of these at a glance without
 * mentally converting between units row to row. */
static void
gt_path_format_mbps(char *buf, size_t size, double bps)
{
    if (bps < 0)
        snprintf(buf, size, "-");
    else
        snprintf(buf, size, "%.2fmbps", bps / 1e6);
}

static void
gt_path_print_row(struct ctl_msg *res, int last)
{
    double tx_bps, rx_bps;
    gt_path_track_rate(res, &tx_bps, &rx_bps);

    char tx_str[32], rx_str[32];

    gt_path_format_mbps(tx_str, sizeof(tx_str), tx_bps);
    gt_path_format_mbps(rx_str, sizeof(rx_str), rx_bps);

    printf("  %s %u  %-8s", last ? "\xe2\x94\x94\xe2\x94\x80" /* "└─" */
                                  : "\xe2\x94\x9c\xe2\x94\x80" /* "├─" */,
           res->path.conf.sock, gt_path_status_text(res));

    char tmp[INET6_ADDRSTRLEN];

    printf("  tx %s  rx %s  rtt %.3f  tx-loss %3.2f  rx-loss %3.2f",
           tx_str, rx_str,
           res->path.rtt.val / 1e3,
           res->path.tx.loss * 100 / 255.0,
           res->path.rx.loss * 100 / 255.0);
    if (res->path.traffic_idle)
        printf("  tx-loss-live null  rx-loss-live null");
    else
        printf("  tx-loss-live %3.2f  rx-loss-live %3.2f",
               res->path.tx.loss_live * 100 / 255.0,
               res->path.rx.loss_live * 100 / 255.0);
    printf("  mtu %zu", res->path.mtu);
    if (gt_toaddr(tmp, sizeof(tmp), &res->path.remote))
        printf("  public unknown\n");
    else
        printf("  public %s.%"PRIu16"\n", tmp, gt_get_port(&res->path.remote));
}

static void
gt_path_conf(struct ctl_msg *res)
{
    const char *state = NULL;
    char local[INET6_ADDRSTRLEN];
    char remote[INET6_ADDRSTRLEN];
    char beat[32];
    char tx[32], rx[32];
    char rttlimit[32];

    switch (res->path.conf.state) {
        case MUD_PASSIVE: state = "passive"; break;
        case MUD_UP:      state = "up";      break;
        case MUD_DOWN:    state = "down";    break;
        default:          return;
    }
    gt_toaddr(local, sizeof(local), &res->path.conf.local);
    gt_toaddr(remote, sizeof(remote), &res->path.conf.remote);

    if (gt_totime(beat, sizeof(beat), res->path.conf.beat / 1000))
        return;

    if (gt_torate(tx, sizeof(tx), res->path.conf.tx_max_rate * 8) ||
        gt_torate(rx, sizeof(rx), res->path.conf.rx_max_rate * 8))
        return;

    if (res->path.conf.rtt_limit) {
        if (gt_totime(rttlimit, sizeof(rttlimit), res->path.conf.rtt_limit / 1000))
            return;
    } else {
        memcpy(rttlimit, "off", 4);
    }

    printf("path dev %s %s %s to addr %s port %"PRIu16" "
           "set %s pref %u beat %s losslimit %u%% rttlimit %s mtu %"PRIu64
           " rate %s tx %s rx %s\n",
            res->tun_name, res->ifname[0] ? "via" : "addr",
            res->ifname[0] ? res->ifname : local,
            remote, gt_get_port(&res->path.conf.remote),
            state, res->path.conf.pref, beat,
            res->path.conf.loss_limit * 100U / 255U,
            rttlimit,
            res->path.conf.mtu,
            res->path.conf.fixed_rate ? "fixed" : "auto",
            tx, rx);
}

static int
gt_path_status(int fd)
{
    struct ctl_msg res = {0};
    static struct ctl_msg rows[MUD_PATH_MAX * 2];
    unsigned int count = 0;

    for (unsigned int i = 0; i < MUD_PATH_MAX * 2; i++) {
        if (recv(fd, &res, sizeof(res), 0) == -1)
            return -1;

        if (res.type != CTL_PATH_STATUS) {
            errno = EBADMSG;
            return -1;
        }
        if (!res.ret)
            break;

        if (res.ret != EAGAIN) {
            errno = res.ret;
            return -1;
        }
        rows[count++] = res;
    }
    int printed[MUD_PATH_MAX * 2] = {0};
    unsigned int members[MUD_PATH_MAX * 2];

    for (unsigned int g = 0; g < count; g++) {
        if (printed[g])
            continue;

        unsigned int member_count = 0;

        for (unsigned int j = g; j < count; j++) {
            if (!printed[j] && gt_path_same_group(&rows[g], &rows[j]))
                members[member_count++] = j;
        }
        char local[INET6_ADDRSTRLEN];
        char remote[INET6_ADDRSTRLEN];
        char index_str[16];

        gt_toaddr(local, sizeof(local), &rows[g].path.conf.local);
        gt_toaddr(remote, sizeof(remote), &rows[g].path.conf.remote);

        if (rows[g].ifindex)
            snprintf(index_str, sizeof(index_str), "%u", rows[g].ifindex);
        else
            memcpy(index_str, "-", 2);

        printf("%s  index %s  %s -> %s.%"PRIu16"\n",
               rows[g].ifname[0] ? rows[g].ifname : "-",
               index_str, local, remote,
               gt_get_port(&rows[g].path.conf.remote));

        for (unsigned int k = 0; k < member_count; k++) {
            printed[members[k]] = 1;
            gt_path_print_row(&rows[members[k]], k == member_count - 1);
        }
        printf("\n");
    }
    return 0;
}

static int
gt_path_marker(int argc, char **argv, void *data)
{
    (void)argv;
    (void)data;
    return argc - 1;
}

int
gt_path(int argc, char **argv, void *data)
{
    char *normalized[(argc * 2) + 1];
    int normalized_argc = 0;

    for (int i = 0; i < argc; i++) {
        if (i > 1 && (!strcmp(argv[i - 1], "up") ||
                      !strcmp(argv[i - 1], "down"))) {
            struct in6_addr addr;
            if (inet_pton(AF_INET, argv[i], &addr) == 1 ||
                inet_pton(AF_INET6, argv[i], &addr) == 1)
                normalized[normalized_argc++] = "addr";
        }
        normalized[normalized_argc++] = argv[i];
    }
    argc = normalized_argc;
    argv = normalized;

    struct argz_ull tx = {.suffix = argz_size_suffix};
    struct argz_ull rx = {.suffix = argz_size_suffix};

    struct argz ratez[] = {
        {"fixed", "Fixed rate",                            .grp = 2},
        {"auto",  "Dynamic rate detection (experimental)", .grp = 2},
        {"tx",    "Maximum transmission rate",   argz_ull,      &tx},
        {"rx",    "Maximum reception rate",      argz_ull,      &rx},
        {0}};

    struct argz_ull beat = {.suffix = argz_time_suffix};
    struct argz_ull pref = {.max = 0xFF >> 1};
    struct argz_ull connections = {.min = 1, .max = MUD_SOCK_MAX};
    struct argz_ull loss = {.max = 100, .suffix = gt_argz_percent_suffix};
    struct argz_ull rttlimit = {.suffix = argz_time_suffix};
    struct argz_ull mtu = {.max = MUD_MTU_HARD_MAX};

    struct gt_argz_addr local = {0};
    struct gt_argz_addr remote = {0};
    const char *dev = NULL;
    char ifname[IFNAMSIZ] = {0};

    struct argz z[] = {
        {"dev",  "Select tunnel device",       gt_argz_dev,       &dev},
        {"via",  "Select path by interface",   gt_argz_ifname, ifname,
                                                            .grp = 2},
        {"addr", "Select path by local addr",  gt_argz_addr_ip, &local,
                                                            .grp = 2},
        {"to",   "Select path by remote addr", gt_argz_addr,   &remote},
        {"set",  "Change path properties", gt_path_marker, NULL},
        {"show", "Show path status",       gt_path_marker, NULL},
        {"up",        "Enable path",                         .grp = 3},
        {"down",      "Disable path",                        .grp = 3},
        {"rate",      "Rate limit properties",  argz, &ratez},
        {"beat",      "Internal beat rate", argz_ull,  &beat},
        {"pref",      "Path preference",    argz_ull,  &pref},
        {"connections", "Parallel UDP sub-flows for this path (default 1, "
                        "requires via)",     argz_ull,  &connections},
        {"losslimit", "Disable lossy path", argz_ull,  &loss},
        {"rttlimit",  "Disable path if RTT exceeds this", argz_ull, &rttlimit},
        {"mtu",  "Fixed MTU to use (wire size, default 1400)",
                                                        argz_ull, &mtu},
        {"watch", "Refresh the view every second until interrupted"},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = 0;

    int change = argz_is_set(z, "up") || argz_is_set(z, "down") ||
                 argz_is_set(z, "rate") || argz_is_set(z, "beat") ||
                 argz_is_set(z, "pref") || argz_is_set(z, "connections") ||
                 argz_is_set(z, "losslimit") ||
                 argz_is_set(z, "rttlimit") || argz_is_set(z, "mtu");
    if (change && (argz_is_set(z, "show") ||
                  argz_is_set(z, "watch"))) {
        gt_log("Path changes and status views cannot be combined\n");
        ctl_delete(fd);
        return -1;
    }
    if (argz_is_set(z, "connections") && connections.value > 1 &&
        !ifname[0]) {
        gt_log("connections > 1 requires a path selected by 'via'\n");
        ctl_delete(fd);
        return -1;
    }

    if (change) {
        struct ctl_msg req = {
            .type = CTL_PATH_CONF,
            .connections = argz_is_set(z, "connections")
                          ? connections.value : 0,
            .path.conf = {
                .local       = local.sock,
                .remote      = remote.sock,
                .state       = MUD_EMPTY,
                .tx_max_rate = tx.value,
                .rx_max_rate = rx.value,
                .beat        = beat.value,
                .pref        = argz_is_set(z, "pref")
                             ? (pref.value << 1) | 1 : 0,
                .loss_limit  = loss.value * 255 / 100,
                .rtt_limit   = rttlimit.value,
                .mtu         = mtu.value,
            },
        }, res = {0};
        memcpy(req.ifname, ifname, sizeof(req.ifname));

        if (argz_is_set(z, "up"))
            req.path.conf.state = MUD_UP;

        if (argz_is_set(z, "down"))
            req.path.conf.state = MUD_DOWN;

        if (argz_is_set(ratez, "fixed"))
            req.path.conf.fixed_rate = 3;

        if (argz_is_set(ratez, "auto"))
            req.path.conf.fixed_rate = 1;

        ret = ctl_reply(fd, &res, &req);

        if (!ret)
            gt_path_conf(&res);
    } else {
        struct ctl_msg req = {
            .type = CTL_PATH_STATUS,
            .path.conf = {
                .local  = local.sock,
                .remote = remote.sock,
            },
        };
        memcpy(req.ifname, ifname, sizeof(req.ifname));

        if (argz_is_set(z, "watch")) {
            while (!gt_quit) {
                if (send(fd, &req, sizeof(req), 0) != sizeof(req)) {
                    ret = -1;
                    break;
                }
                printf("\033[H\033[J");
                printf("Every 1s: glorytun path   Ctrl+C to stop\n\n");
                ret = gt_path_status(fd);
                fflush(stdout);

                if (ret)
                    break;

                sleep(1);
            }
            /* Ctrl+C during send/recv surfaces as EINTR -- that is the
             * requested stop, not a failure worth reporting. */
            if (gt_quit)
                ret = 0;
        } else {
            if (send(fd, &req, sizeof(req), 0) != sizeof(req))
                ret = -1;

            if (!ret)
                ret = gt_path_status(fd);
        }
    }
    if (ret == -1 && errno)
        perror("path");

    ctl_delete(fd);

    return ret;
}
