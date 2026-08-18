#pragma once

#include "../mud/mud.h"

#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

enum gt_path_availability {
    GT_PATH_AVAILABLE = 0,
    GT_PATH_INTERFACE_DOWN,
    GT_PATH_WAITING_ADDRESS,
    GT_PATH_ADMIN_DOWN,
};

struct gt_managed_path {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    unsigned int bound_ifindex;
    union mud_sockaddr current_local;
    union mud_sockaddr bound_local;
    union mud_sockaddr remote;
    unsigned char sock; /* mud socket-pool index this sub-flow uses; a
                          * logical path with N sub-flows occupies N
                          * gt_managed_path entries, one per sock 0..N-1 */
    struct mud_path_conf desired_conf;
    int desired_up;
    int link_up;
    int address_ready;
    int runtime_bound;
    int runtime_active;
    int config_dirty;
};

struct gt_path_manager {
    struct gt_managed_path path[MUD_PATH_MAX];
    unsigned int count;
};

struct gt_managed_status {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    enum gt_path_availability availability;
    struct mud_path path;
};

void gt_path_manager_init(struct gt_path_manager *);
int gt_path_manager_set(struct gt_path_manager *, struct mud *, const char *,
                        unsigned int sock, struct mud_path_conf *);
int gt_path_manager_reconcile(struct gt_path_manager *, struct mud *);
unsigned int gt_path_manager_status(struct gt_path_manager *, struct mud *,
                                    const char *, union mud_sockaddr *,
                                    struct gt_managed_status *, unsigned int);
