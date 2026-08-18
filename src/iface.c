#include "common.h"
#include "iface.h"

#include <limits.h>
#include <net/if.h>
#include <sys/ioctl.h>

int
iface_set_mtu(const char *dev_name, size_t mtu)
{
    if (mtu > (size_t)0xFFFF) {
        errno = EINVAL;
        return -1;
    }

    struct ifreq ifr = {
        .ifr_mtu = (int)mtu,
    };
    int ret = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    if (ret <= 0 || (size_t)ret >= sizeof(ifr.ifr_name)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    ret = ioctl(fd, SIOCSIFMTU, &ifr);

    int err = errno;
    close(fd);
    errno = err;

    return ret;
}

int
iface_set_qlen(const char *dev_name, size_t qlen)
{
    if (qlen > (size_t)INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    struct ifreq ifr = {
        .ifr_qlen = (int)qlen,
    };
    int ret = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    if (ret <= 0 || (size_t)ret >= sizeof(ifr.ifr_name)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    ret = ioctl(fd, SIOCSIFTXQLEN, &ifr);

    int err = errno;
    close(fd);
    errno = err;

    return ret;
}
