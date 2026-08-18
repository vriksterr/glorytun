#pragma once

#include "../mud/mud.h"

#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

struct gt_link_info {
    unsigned int ifindex;
    int link_up;
    int address_ready;
    union mud_sockaddr local;
};

int gt_netlink_open(void);
int gt_netlink_drain(int);
int gt_netlink_resolve(const char *, int, const union mud_sockaddr *,
                       struct gt_link_info *);
