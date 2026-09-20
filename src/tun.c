#include "common.h"
#include "tun.h"
#include "ip.h"

#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef __linux__
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
/* Lets more than one fd attach to the same interface, each becoming its
 * own independent queue -- see tun_create()/tun_create_queue()'s own
 * comments for why this exists: giving each worker thread its own queue
 * instead of every one of them racing poll() on a single shared fd. */
#define IFF_MULTI_QUEUE 0x0100
#define TUNSETIFF _IOW('T', 202, int)
#define TUNSETPERSIST _IOW('T', 203, int)
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#if defined(__APPLE__) || defined(__OpenBSD__)
#define GT_BSD_TUN
#endif

#ifdef __APPLE__

/* multiqueue is always ignored here -- utun has no equivalent of Linux's
 * IFF_MULTI_QUEUE, kept only so tun_create() below can call this the same
 * way regardless of platform. */
static int
tun_create_by_id(char *name, size_t len, unsigned id, int multiqueue)
{
    (void)multiqueue;
    int ret = snprintf(name, len, "utun%u", id);

    if (ret <= 0 || (size_t)ret >= len) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd == -1)
        return -1;

    struct ctl_info ci = {
        .ctl_name = UTUN_CONTROL_NAME,
    };
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    union {
        struct sockaddr sa;
        struct sockaddr_ctl sctl;
    } sock = {
        .sctl = {
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_id = ci.ctl_id,
            .sc_len = sizeof(sock),
            .sc_unit = id + 1,
        },
    };
    if (connect(fd, &sock.sa, sizeof(sock))) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

static int
tun_create_by_name(char *name, size_t len, const char *dev_name, int multiqueue)
{
    unsigned id = 0;

    if (sscanf(dev_name, "utun%u", &id) != 1) {
        errno = EINVAL;
        return -1;
    }
    return tun_create_by_id(name, len, id, multiqueue);
}

#else /* not __APPLE__ */

#ifdef __linux__

static int
tun_create_by_name(char *name, size_t len, const char *dev_name, int multiqueue)
{
    int ret = snprintf(name, len, "%s", dev_name);

    if (ret <= 0 || (size_t)ret >= len) {
        errno = EINVAL;
        return -1;
    }
    struct ifreq ifr = {
        .ifr_flags = (short)(IFF_TUN | IFF_NO_PI | (multiqueue ? IFF_MULTI_QUEUE : 0)),
    };
    ret = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    if (ret <= 0 || (size_t)ret >= sizeof(ifr.ifr_name)) {
        errno = EINVAL;
        return -1;
    }
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd == -1)
        return -1;

    if (ioctl(fd, TUNSETIFF, &ifr)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

#else /* not __linux__ not __APPLE__ */

/* multiqueue is always ignored here -- this generic BSD-style /dev node
 * path has no multi-queue equivalent, kept only so tun_create() below can
 * call this the same way regardless of platform. */
static int
tun_create_by_name(char *name, size_t len, const char *dev_name, int multiqueue)
{
    (void)multiqueue;
    int ret = snprintf(name, len, "%s", dev_name);

    if (ret <= 0 || (size_t)ret >= len) {
        errno = EINVAL;
        return -1;
    }
    char tmp[64];
    ret = snprintf(tmp, sizeof(tmp), "/dev/%s", dev_name);

    if (ret <= 0 || (size_t)ret >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }
    return open(tmp, O_RDWR);
}

#endif /* not __APPLE__ */

static int
tun_create_by_id(char *name, size_t len, unsigned id, int multiqueue)
{
    char tmp[64];
    int ret = snprintf(tmp, sizeof(tmp), "tun%u", id);

    if (ret <= 0 || (size_t)ret >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }
    return tun_create_by_name(name, len, tmp, multiqueue);
}

#endif

/* `multiqueue`, if non-NULL, is set to whether the returned fd actually
 * came up as queue 0 of a multi-queue-capable interface (Linux only) --
 * see tun_create_queue()'s own comment for what that buys a caller with
 * more than one worker thread. Always tried first when requested; on
 * anything that can't do it (non-Linux, an old kernel, or a persistent
 * device from a previous run that was never created with the multi-queue
 * flag in the first place and won't accept it retroactively) this falls
 * straight back to a plain single-queue open instead of failing outright
 * -- multi-queue is an optimization here, never a requirement. */
int
tun_create(char *name, size_t len, const char *dev_name, int *multiqueue)
{
    int fd = -1;
    int mq = 1;

    if (EMPTY(dev_name)) {
        for (unsigned id = 0; id < 32 && fd == -1; id++)
            fd = tun_create_by_id(name, len, id, mq);
    } else {
        fd = tun_create_by_name(name, len, dev_name, mq);
    }
    if (fd == -1) {
        mq = 0;
        if (EMPTY(dev_name)) {
            for (unsigned id = 0; id < 32 && fd == -1; id++)
                fd = tun_create_by_id(name, len, id, mq);
        } else {
            fd = tun_create_by_name(name, len, dev_name, mq);
        }
    }
    if (multiqueue)
        *multiqueue = (fd != -1) && mq;
    return fd;
}

/* Attaches one more independent queue to an already-created multi-queue
 * interface (see tun_create()'s own `multiqueue` out-parameter) -- each
 * queue is its own fd with its own kernel-side packet queue, so N worker
 * threads each polling their own queue's fd genuinely split the TUN
 * device's traffic N ways, the same clean partitioning the socket pool
 * already has via mud_worker_loop()'s own striding. Without this, every
 * worker instead polls one shared fd and races the others for whichever
 * packet the kernel handed to it -- see mud_worker_loop()'s own comment
 * on that shared-fd cost. Linux-only; the caller is expected to only ever
 * call this after tun_create() reported multiqueue support. */
int
tun_create_queue(const char *dev_name)
{
#ifdef __linux__
    char tmp[64];
    return tun_create_by_name(tmp, sizeof(tmp), dev_name, 1);
#else
    (void)dev_name;
    errno = ENOSYS;
    return -1;
#endif
}

int
tun_read(int fd, void *data, size_t size)
{
    if (!size)
        return 0;

#ifdef GT_BSD_TUN
    uint32_t family;

    struct iovec iov[2] = {
        {.iov_base = &family, .iov_len = sizeof(family)},
        {.iov_base = data,    .iov_len = size          },
    };
    int ret = (int)readv(fd, iov, 2);

    if (ret <= 0)
        return ret;

    if ((size_t)ret <= sizeof(family))
        return 0;

    return ret - (int)sizeof(family);
#else
    return (int)read(fd, data, size);
#endif
}

int
tun_write(int fd, const void *data, size_t size)
{
    if (!size)
        return 0;

#ifdef GT_BSD_TUN
    uint32_t family;

    switch (ip_get_version(data, (int)size)) {
        case 4: family = htonl(AF_INET);  break;
        case 6: family = htonl(AF_INET6); break;
        default: errno = EINVAL;          return -1;
    }
    struct iovec iov[2] = {
        {.iov_base = &family,      .iov_len = sizeof(family)},
        {.iov_base = (void *)data, .iov_len = size          },
    };
    int ret = (int)writev(fd, iov, 2);

    if (ret <= 0)
        return ret;

    if ((size_t)ret <= sizeof(family))
        return 0;

    return ret - (int)sizeof(family);
#else
    return (int)write(fd, data, size);
#endif
}

int
tun_set_persist(int fd, int on)
{
#ifdef TUNSETPERSIST
    return ioctl(fd, TUNSETPERSIST, on);
#else
    errno = ENOSYS;
    return -1;
#endif
}
