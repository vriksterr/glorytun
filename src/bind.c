#include "common.h"
#include "ctl.h"
#include "iface.h"
#include "ip.h"
#include "tun.h"
#include "argz.h"
#include "netlink.h"
#include "path_manager.h"

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/select.h>
#include <sodium.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int
fd_set_nonblock(int fd)
{
    if (fd == -1)
        return 0;

    int ret;

    do {
        ret = fcntl(fd, F_GETFL, 0);
    } while (ret == -1 && errno == EINTR);

    int flags = (ret == -1) ? 0 : ret;

    do {
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    } while (ret == -1 && errno == EINTR);

    return ret;
}

static int
gt_sockaddr_equal(const union mud_sockaddr *a, const union mud_sockaddr *b)
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

static int
gt_read_keyfile(unsigned char *key, const char *keyfile)
{
    int fd;

    do {
        fd = open(keyfile, O_RDONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        gt_log("couldn't open %s: %s\n", keyfile, strerror(errno));
        return -1;
    }
    char buf[2 * MUD_PUBKEY_SIZE];
    size_t size = 0;

    while (size < sizeof(buf)) {
        ssize_t r = read(fd, buf + size, sizeof(buf) - size);

        if (r <= (ssize_t)0) {
            if (r && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
        size += (size_t)r;
    }
    close(fd);

    if (size != sizeof(buf)) {
        gt_log("couldn't read secret key\n");
        return -1;
    }
    if (gt_fromhex(key, MUD_PUBKEY_SIZE, buf, sizeof(buf))) {
        gt_log("secret key is not valid\n");
        return -1;
    }
    return 0;
}

static size_t
gt_setup_mtu(struct mud *mud, size_t old, const char *tun_name)
{
    size_t mtu = mud_get_mtu(mud);

    if (!mtu || mtu == old)
        return mtu;

    if (iface_set_mtu(tun_name, mtu) == -1)
        gt_log("couldn't setup MTU at %zu on device %s\n", mtu, tun_name);

    return mtu;
}

/* mud_worker_loop() (mud.c) takes tun_write as a plain function pointer --
 * the mud library deliberately knows nothing about glorytun's own IP
 * validation. Matches mud_tun_write_fn's signature exactly so it can be
 * passed straight through; drops anything that doesn't parse as a
 * well-formed IPv4/IPv6 packet instead of writing it to the TUN device,
 * same check bind.c's old single-threaded RX loop did inline. */
static int
gt_tun_write_validated(int fd, const void *buf, size_t size)
{
    if (!ip_is_valid(buf, (int)size))
        return 0;

    return tun_write(fd, buf, size);
}

struct gt_worker_arg {
    struct mud *mud;
    int tun_fd;
    unsigned int worker_index;
    unsigned int worker_count;
};

static void *
gt_worker_main(void *arg)
{
    struct gt_worker_arg *a = arg;

    mud_worker_loop(a->mud, a->worker_index, a->worker_count, a->tun_fd,
                    tun_read, gt_tun_write_validated, &gt_quit);
    return NULL;
}

int
gt_bind(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    struct argz_path keyfile = {0};
    struct gt_argz_addr local = {
        .sock.sin = {
            .sin_family = AF_INET,
            .sin_port = htons(5000),
        },
    };
    struct gt_argz_addr remote = local;
    struct argz_ull qlen = {.max = INT_MAX};

    struct argz z[] = {
        {"dev",     "Tunnel device",                  argz_str,      &dev},
        {"keyfile", "Secret file to use",             argz_path, &keyfile},
        {"from",    "Address and port to bind",    gt_argz_addr,   &local},
        {"to",      "Address and port to connect", gt_argz_addr,  &remote},
        {"persist", "Keep the tunnel device after exiting"               },
        {"chacha" , "Force fallback cipher"                              },
        {"qlen",    "Set the tun device's tx queue length",
                                                        argz_ull,   &qlen},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    if (EMPTY(keyfile.path)) {
        gt_log("a keyfile is needed!\n");
        return -1;
    }
    const int chacha = argz_is_set(z, "chacha");
    const int persist = argz_is_set(z, "persist");

    if (sodium_init() == -1) {
        gt_log("couldn't init sodium\n");
        return -1;
    }
    unsigned char key[MUD_PUBKEY_SIZE];

    if (gt_read_keyfile(key, keyfile.path))
        return -1;

    int aes = !chacha;
    struct mud *mud = mud_create(&local.sock, key, &aes);
    const int mud_fd0 = mud_get_fd(mud, 0);

    if (mud_fd0 == -1) {
        gt_log("couldn't create mud\n");
        return -1;
    }
    if (!chacha && !aes)
        gt_log("AES is not available, enjoy ChaCha20!\n");

    char tun_name[64];
    const int tun_fd = tun_create(tun_name, sizeof(tun_name), dev);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return -1;
    }
    if (argz_is_set(z, "qlen") &&
        iface_set_qlen(tun_name, qlen.value) == -1) {
        gt_log("couldn't setup qlen at %llu on device %s\n",
               qlen.value, tun_name);
    }
    size_t mtu = gt_setup_mtu(mud, 0, tun_name);

    if (tun_set_persist(tun_fd, persist) == -1) {
        gt_log("couldn't %sable persist mode on device %s\n",
               persist ? "en" : "dis", tun_name);
    }
    const int ctl_fd = ctl_create(tun_name);

    if (ctl_fd == -1) {
        char dir[64];
        if (ctl_rundir(dir, sizeof(dir))) {
            gt_log("couldn't create %s/%s: %s\n",
                   dir, tun_name, strerror(errno));
        } else {
            gt_log("couldn't find a writable run/tmp directory\n");
        }
        return -1;
    }
    if (fd_set_nonblock(tun_fd) ||
        fd_set_nonblock(mud_fd0) ||
        fd_set_nonblock(ctl_fd)) {
        gt_log("couldn't setup non-blocking fds\n");
        return -1;
    }
    struct gt_path_manager path_manager;
    gt_path_manager_init(&path_manager);

    const int netlink_fd = gt_netlink_open();
    if (netlink_fd == -1 && errno != ENOSYS)
        gt_log("couldn't monitor network interfaces: %s\n", strerror(errno));

    const long pid = (long)getpid();
    gt_log("running on device %s as pid %li\n", tun_name, pid);

    /* All actual packet I/O (TUN <-> mud sockets: receive, decrypt, path
     * lookup, encrypt, send) now happens on these worker threads, spread
     * across cores instead of funneling through this one -- see
     * mud_worker_loop()'s doc comment in mud.h. This thread (below) is
     * left with only housekeeping: the periodic mud_update() tick, and the
     * control socket / netlink events, none of which are per-packet. */
    const unsigned int worker_count = mud_worker_count();
    pthread_t *workers = malloc(worker_count * sizeof(pthread_t));
    struct gt_worker_arg *worker_args =
        malloc(worker_count * sizeof(struct gt_worker_arg));
    unsigned int workers_started = 0;

    if (!workers || !worker_args) {
        gt_log("couldn't allocate worker thread table\n");
        free(workers);
        free(worker_args);
        return -1;
    }
    /* mud_worker_loop()'s TX/RX halves each keep a pair of
     * MUD_MTU_HARD_MAX/MUD_PKT_MAX_SIZE-sized buffers (~128KB) live on the
     * stack at once, and the RX path can nest straight into mud_send_msg()
     * for another ~128KB on top of that -- comfortably past 256KB per call.
     * The platform default pthread stack size (musl's in particular, as
     * used by OpenWrt) can be smaller than that, which segfaults the
     * worker the moment it handles one real packet. Set an explicit,
     * generous stack size instead of trusting the default. */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1 << 20);

    for (unsigned int i = 0; i < worker_count; i++) {
        worker_args[i] = (struct gt_worker_arg){
            .mud = mud,
            .tun_fd = tun_fd,
            .worker_index = i,
            .worker_count = worker_count,
        };
        if (pthread_create(&workers[i], &attr, gt_worker_main,
                           &worker_args[i])) {
            gt_log("couldn't start worker thread %u: %s\n",
                   i, strerror(errno));
            break;
        }
        workers_started++;
    }
    pthread_attr_destroy(&attr);
    if (!workers_started) {
        gt_log("no worker threads could be started\n");
        free(workers);
        free(worker_args);
        return -1;
    }
    if (workers_started < worker_count) {
        gt_log("only %u of %u worker threads started, continuing\n",
               workers_started, worker_count);
    }
    fd_set rfds;
    FD_ZERO(&rfds);

    while (!gt_quit) {
        FD_SET(ctl_fd, &rfds);
        if (netlink_fd >= 0)
            FD_SET(netlink_fd, &rfds);

        /* mud_update() still needs a periodic tick from somewhere on this
         * thread -- it's the AIMD/loss-tracking/keepalive sweep, not
         * per-packet work, so it stays here rather than on the worker
         * threads (see mud.c's mud_update() locking comment). A fixed
         * ~100ms cadence (matching the default path beat granularity) is
         * enough; the finer update()-return-value-driven timeout the old
         * single-threaded loop used existed to pace TX/RX polling, which
         * the worker threads now own themselves. */
        mud_update(mud);

        struct timeval tv = {.tv_usec = 100000};
        int last_fd = ctl_fd;
        if (netlink_fd >= 0)
            last_fd = MAX(last_fd, netlink_fd);

        const int ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret == -1) {
            if (errno == EBADF) {
                perror("select");
                break;
            }
            continue;
        }
        if (netlink_fd >= 0 && FD_ISSET(netlink_fd, &rfds)) {
            int changed = gt_netlink_drain(netlink_fd);
            if (changed == -1) {
                gt_log("couldn't read interface events: %s\n", strerror(errno));
            } else if (changed && gt_path_manager_reconcile(&path_manager, mud)) {
                gt_log("couldn't reconcile interface paths: %s\n", strerror(errno));
            }
        }

        mtu = gt_setup_mtu(mud, mtu, tun_name);
        if (FD_ISSET(ctl_fd, &rfds)) {
            struct ctl_msg req, res = {.reply = 1};
            struct mud_paths paths;
            union ctl_sun sun;
            socklen_t slen = sizeof(sun);
            ssize_t r = recvfrom(ctl_fd, &req, sizeof(req), 0, &sun.sa, &slen);
            if (r == -1) {
                if (errno != EAGAIN)
                    perror("recvfrom(ctl)");
            } else if (r == (ssize_t)sizeof(req)) {
                res.type = req.type;
                memcpy(res.tun_name, tun_name, sizeof(res.tun_name));
                switch (req.type) {
                case CTL_NONE:
                    break;
                case CTL_STATUS:
                    res.status.pid = pid;
                    res.status.mtu = mtu;
                    res.status.cipher = !aes;
                    res.status.local  = local.sock;
                    res.status.remote = remote.sock;
                    break;
                case CTL_CONF:
                    if (mud_set(mud, &req.conf))
                        res.ret = errno;
                    res.conf = req.conf;
                    break;
                case CTL_PATH_STATUS:
                    if (req.path.conf.remote.sa.sa_family &&
                        !gt_get_port(&req.path.conf.remote))
                        gt_set_port(&req.path.conf.remote,
                                    gt_get_port(&remote.sock));

                    res.ret = EAGAIN;
                    if (!req.path.conf.local.sa.sa_family) {
                        struct gt_managed_status managed[MUD_PATH_MAX];
                        unsigned int count = gt_path_manager_status(
                            &path_manager, mud, req.ifname,
                            &req.path.conf.remote, managed, MUD_PATH_MAX);
                        for (unsigned int i = 0; i < count; i++) {
                            res.path = managed[i].path;
                            memcpy(res.ifname, managed[i].ifname,
                                   sizeof(res.ifname));
                            res.ifindex = managed[i].ifindex;
                            res.path_availability = managed[i].availability;
                            if (sendto(ctl_fd, &res, sizeof(res), 0,
                                       &sun.sa, slen) == -1)
                                perror("sendto(ctl)");
                        }
                    }
                    if (!req.ifname[0]) {
                        if (mud_get_paths(mud, &paths,
                                          &req.path.conf.local,
                                          &req.path.conf.remote)) {
                            res.ret = errno;
                            break;
                        }
                        memset(res.ifname, 0, sizeof(res.ifname));
                        res.ifindex = 0;
                        res.path_availability = GT_PATH_AVAILABLE;
                        for (unsigned i = 0; i < paths.count; i++) {
                            if (paths.path[i].conf.local_ifindex)
                                continue;
                            res.path = paths.path[i];
                            if (sendto(ctl_fd, &res, sizeof(res), 0,
                                       &sun.sa, slen) == -1)
                                perror("sendto(ctl)");
                        }
                    }
                    res.ret = 0;
                    break;
                case CTL_PATH_CONF: {
                    if (req.path.conf.remote.sa.sa_family) {
                        if (!gt_get_port(&req.path.conf.remote))
                            gt_set_port(&req.path.conf.remote,
                                        gt_get_port(&remote.sock));
                    } else {
                        req.path.conf.remote = remote.sock;
                    }
                    const unsigned int conn_count =
                        req.connections ? req.connections : 1;

                    if (conn_count > MUD_SOCK_MAX) {
                        res.ret = EINVAL;
                        break;
                    }
                    if (conn_count > 1 && !req.ifname[0]) {
                        /* sub-flows are only tracked/torn-down via the
                         * interface-managed path_manager; legacy addr-only
                         * paths have no equivalent durable state */
                        res.ret = ENOTSUP;
                        break;
                    }
                    if (req.ifname[0]) {
                        if (!memchr(req.ifname, 0, sizeof(req.ifname))) {
                            res.ret = EINVAL;
                            break;
                        }
                        /* Each (ifname, remote) group gets its own
                         * dedicated, non-overlapping block of sock indices
                         * -- reusing an existing group's own block on a
                         * resize, or starting one past the highest index
                         * any group currently holds. Without this, every
                         * group's fan-out started back at sock 0, so two
                         * physical interfaces both configured with
                         * `connections N` would silently share the same N
                         * real sockets (and therefore the same source
                         * ports) instead of getting independent ones. */
                        unsigned int base_sock = 0;
                        int have_group = 0;

                        for (unsigned int i = 0; i < path_manager.count; i++) {
                            struct gt_managed_path *mp = &path_manager.path[i];
                            if (!strcmp(mp->ifname, req.ifname) &&
                                gt_sockaddr_equal(&mp->remote,
                                                  &req.path.conf.remote)) {
                                if (!have_group || mp->sock < base_sock)
                                    base_sock = mp->sock;
                                have_group = 1;
                            }
                        }
                        if (!have_group) {
                            unsigned int max_sock = 0;
                            int any = 0;

                            for (unsigned int i = 0; i < path_manager.count; i++) {
                                unsigned int s = path_manager.path[i].sock;
                                if (!any || s > max_sock)
                                    max_sock = s;
                                any = 1;
                            }
                            base_sock = any ? max_sock + 1 : 0;
                        }
                        if ((uint64_t)base_sock + conn_count > MUD_SOCK_MAX) {
                            res.ret = ENOSPC;
                            break;
                        }
                        if (mud_set_sock_count(mud, base_sock + conn_count)) {
                            res.ret = errno;
                            break;
                        }
                        for (unsigned int i = 0;
                             i < mud_get_sock_count(mud); i++)
                            fd_set_nonblock(mud_get_fd(mud, i));

                        /* Every iteration must copy from the original,
                         * untouched request -- gt_path_manager_set() writes
                         * back an internally-converted conf (e.g. beat
                         * scaled x1000 into microseconds), and feeding that
                         * back in as the next sub-flow's starting template
                         * would re-scale it again on top of the conversion
                         * gt_path_manager_update_conf() already applied. */
                        struct mud_path_conf first_conf = req.path.conf;
                        int have_first_conf = 0;

                        for (unsigned int c = 0; c < conn_count; c++) {
                            struct mud_path_conf conf = req.path.conf;
                            conf.sock = (unsigned char)(base_sock + c);
                            if (gt_path_manager_set(&path_manager, mud,
                                                    req.ifname, base_sock + c,
                                                    &conf) && !res.ret)
                                res.ret = errno;
                            if (c == 0) {
                                first_conf = conf;
                                have_first_conf = 1;
                            }
                        }
                        if (have_first_conf)
                            req.path.conf = first_conf;
                        /* bring down any sub-flows left over from a
                         * previous, larger connections=N request for this
                         * (ifname, remote) pair */
                        for (unsigned int i = 0; i < path_manager.count; i++) {
                            struct gt_managed_path *mp = &path_manager.path[i];
                            if (mp->sock < base_sock + conn_count ||
                                strcmp(mp->ifname, req.ifname) ||
                                !gt_sockaddr_equal(&mp->remote,
                                                   &req.path.conf.remote))
                                continue;
                            struct mud_path_conf down = mp->desired_conf;
                            down.remote = mp->remote;
                            down.sock = mp->sock;
                            down.state = MUD_DOWN;
                            gt_path_manager_set(&path_manager, mud,
                                                req.ifname, mp->sock, &down);
                        }
                        memcpy(res.ifname, req.ifname, sizeof(res.ifname));
                        res.ifindex = req.path.conf.local_ifindex;
                    } else if (mud_set_path(mud, &req.path.conf)) {
                        res.ret = errno;
                    }
                    res.path.conf = req.path.conf;
                    break;
                }
                case CTL_ERRORS:
                    if (mud_get_errors(mud, &res.errors))
                        res.ret = errno;
                    break;
                }
                if (sendto(ctl_fd, &res, sizeof(res), 0, &sun.sa, slen) == -1)
                    perror("sendto(ctl)");
            }
        }
    }
    if (gt_reload && tun_fd >= 0)
        tun_set_persist(tun_fd, 1);

    /* gt_quit is already set by the time we get here (it's what ended the
     * loop above) -- each worker thread notices within its own bounded
     * poll() wait (mud_worker_loop(), ~100ms) and returns on its own, so
     * this join just waits for that, never blocks indefinitely. Must
     * happen before mud_delete()/closing tun_fd: the workers are still
     * dereferencing both until they actually exit. */
    for (unsigned int i = 0; i < workers_started; i++)
        pthread_join(workers[i], NULL);
    free(workers);
    free(worker_args);

    mud_delete(mud);
    if (netlink_fd >= 0)
        close(netlink_fd);
    ctl_delete(ctl_fd);

    return 0;
}
