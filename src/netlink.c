#include "common.h"
#include "netlink.h"

#include <fcntl.h>
#include <net/if.h>

#if defined __linux__
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

static int
gt_netlink_socket(unsigned int groups, int nonblock)
{
    int type = SOCK_RAW;
#ifdef SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    if (nonblock)
        type |= SOCK_NONBLOCK;
#endif
    int fd = socket(AF_NETLINK, type, NETLINK_ROUTE);

    if (fd == -1)
        return -1;

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = groups,
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

int
gt_netlink_open(void)
{
    return gt_netlink_socket(RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
                             RTMGRP_IPV6_IFADDR, 1);
}

int
gt_netlink_drain(int fd)
{
    int changed = 0;
    unsigned char buf[8192];

    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

        if (len == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return changed;
            return -1;
        }
        if (!len)
            return changed;

        changed = 1;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
             NLMSG_OK(nh, (unsigned int)len);
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type != NLMSG_ERROR)
                continue;
            struct nlmsgerr *err = NLMSG_DATA(nh);
            if (!err->error)
                continue;
            errno = -err->error;
            return -1;
        }
    }
}

static int
gt_addr_equal(const union mud_sockaddr *a, const union mud_sockaddr *b)
{
    if (!a || a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (b->sa.sa_family == AF_INET)
        return !memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                       sizeof(b->sin.sin_addr));
    if (b->sa.sa_family == AF_INET6)
        return !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                       sizeof(b->sin6.sin6_addr));
    return 0;
}

static int
gt_addr_score(int family, const void *addr, unsigned int flags)
{
    if (family == AF_INET) {
        const unsigned char *p = addr;
        if (p[0] == 127 || (p[0] == 169 && p[1] == 254))
            return 0;
        return (flags & IFA_F_SECONDARY) ? 1 : 2;
    }
    if (family == AF_INET6) {
        const struct in6_addr *a = addr;
        if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a) ||
            (flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED | IFA_F_DEPRECATED)))
            return 0;
        return (flags & IFA_F_TEMPORARY) ? 2 : 3;
    }
    return 0;
}

static int
gt_netlink_address(unsigned int ifindex, int family,
                   const union mud_sockaddr *current,
                   union mud_sockaddr *selected)
{
    int fd = gt_netlink_socket(0, 0);
    if (fd == -1)
        return -1;

    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
    } req = {
        .nh = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
            .nlmsg_type = RTM_GETADDR,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_seq = 1,
        },
        .ifa = {.ifa_family = family},
    };
    if (send(fd, &req, req.nh.nlmsg_len, 0) == -1) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    int best = 0;
    int done = 0;
    unsigned char buf[16384];

    while (!done) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len == -1) {
            if (errno == EINTR)
                continue;
            int err = errno;
            close(fd);
            errno = err;
            return -1;
        }
        if (!len)
            break;

        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
             NLMSG_OK(nh, (unsigned int)len);
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nh);
                if (err->error) {
                    int saved = -err->error;
                    close(fd);
                    errno = saved;
                    return -1;
                }
                continue;
            }
            if (nh->nlmsg_type != RTM_NEWADDR)
                continue;

            struct ifaddrmsg *ifa = NLMSG_DATA(nh);
            if (ifa->ifa_index != ifindex || ifa->ifa_family != family)
                continue;

            unsigned int flags = ifa->ifa_flags;
            void *address = NULL;
            int attrlen = IFA_PAYLOAD(nh);
            for (struct rtattr *rta = IFA_RTA(ifa); RTA_OK(rta, attrlen);
                 rta = RTA_NEXT(rta, attrlen)) {
                if (rta->rta_type == IFA_FLAGS &&
                    RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                    memcpy(&flags, RTA_DATA(rta), sizeof(flags));
                } else if (rta->rta_type == IFA_LOCAL) {
                    address = RTA_DATA(rta);
                } else if (rta->rta_type == IFA_ADDRESS && !address) {
                    address = RTA_DATA(rta);
                }
            }
            if (!address)
                continue;

            int score = gt_addr_score(family, address, flags);
            if (!score)
                continue;

            union mud_sockaddr candidate = {0};
            if (family == AF_INET) {
                candidate.sin.sin_family = AF_INET;
                memcpy(&candidate.sin.sin_addr, address,
                       sizeof(candidate.sin.sin_addr));
            } else {
                candidate.sin6.sin6_family = AF_INET6;
                memcpy(&candidate.sin6.sin6_addr, address,
                       sizeof(candidate.sin6.sin6_addr));
            }
            if (gt_addr_equal(current, &candidate)) {
                *selected = candidate;
                best = 100;
            } else if (score > best) {
                *selected = candidate;
                best = score;
            }
        }
    }
    close(fd);
    return best ? 0 : 1;
}

int
gt_netlink_resolve(const char *ifname, int family,
                   const union mud_sockaddr *current,
                   struct gt_link_info *info)
{
    if (!ifname || !ifname[0] || !info ||
        (family != AF_INET && family != AF_INET6)) {
        errno = EINVAL;
        return -1;
    }
    memset(info, 0, sizeof(*info));
    info->ifindex = if_nametoindex(ifname);
    if (!info->ifindex) {
        if (!errno)
            errno = ENODEV;
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
        return -1;
    struct ifreq ifr = {0};
    memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    close(fd);
    info->link_up = !!(ifr.ifr_flags & IFF_UP);
    if (!info->link_up)
        return 0;

    int ret = gt_netlink_address(info->ifindex, family, current,
                                 &info->local);
    if (ret == -1)
        return -1;
    info->address_ready = !ret;
    return 0;
}

#else

int gt_netlink_open(void) { errno = ENOSYS; return -1; }
int gt_netlink_drain(int fd) { (void)fd; errno = ENOSYS; return -1; }
int
gt_netlink_resolve(const char *ifname, int family,
                   const union mud_sockaddr *current,
                   struct gt_link_info *info)
{
    (void)ifname; (void)family; (void)current; (void)info;
    errno = ENOSYS;
    return -1;
}

#endif
