#include "common.h"
#include "netlink.h"
#include "path_manager.h"

static int
gt_sockaddr_addr_equal(const union mud_sockaddr *a,
                       const union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == AF_INET)
        return !memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                       sizeof(a->sin.sin_addr));
    if (a->sa.sa_family == AF_INET6)
        return !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                       sizeof(a->sin6.sin6_addr));
    return 0;
}

static int
gt_sockaddr_port_equal(const union mud_sockaddr *a,
                       const union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == AF_INET)
        return a->sin.sin_port == b->sin.sin_port;
    if (a->sa.sa_family == AF_INET6)
        return a->sin6.sin6_port == b->sin6.sin6_port;
    return 0;
}

static int
gt_remote_equal(const union mud_sockaddr *a, const union mud_sockaddr *b)
{
    return gt_sockaddr_addr_equal(a, b) && gt_sockaddr_port_equal(a, b);
}

static int
gt_remote_matches(const union mud_sockaddr *filter,
                  const union mud_sockaddr *remote)
{
    if (!filter || !filter->sa.sa_family)
        return 1;
    if (!gt_sockaddr_addr_equal(filter, remote))
        return 0;
    if (filter->sa.sa_family == AF_INET && !filter->sin.sin_port)
        return 1;
    if (filter->sa.sa_family == AF_INET6 && !filter->sin6.sin6_port)
        return 1;
    return gt_sockaddr_port_equal(filter, remote);
}

void
gt_path_manager_init(struct gt_path_manager *manager)
{
    memset(manager, 0, sizeof(*manager));
}

static struct gt_managed_path *
gt_path_manager_find(struct gt_path_manager *manager, const char *ifname,
                     union mud_sockaddr *remote, unsigned int sock)
{
    for (unsigned int i = 0; i < manager->count; i++) {
        struct gt_managed_path *path = &manager->path[i];
        if (!strcmp(path->ifname, ifname) &&
            path->sock == sock &&
            gt_remote_equal(&path->remote, remote))
            return path;
    }
    return NULL;
}

static void
gt_path_manager_update_conf(struct gt_managed_path *path,
                            const struct mud_path_conf *conf)
{
    if (conf->state == MUD_UP) {
        path->desired_up = 1;
        path->desired_conf.state = MUD_UP;
    } else if (conf->state == MUD_DOWN) {
        path->desired_up = 0;
        path->desired_conf.state = MUD_DOWN;
    }
    if (conf->pref)
        path->desired_conf.pref = conf->pref >> 1;
    if (conf->beat)
        path->desired_conf.beat = conf->beat * 1000;
    if (conf->fixed_rate)
        path->desired_conf.fixed_rate = conf->fixed_rate >> 1;
    if (conf->loss_limit)
        path->desired_conf.loss_limit = conf->loss_limit;
    if (conf->tx_max_rate)
        path->desired_conf.tx_max_rate = conf->tx_max_rate;
    if (conf->rx_max_rate)
        path->desired_conf.rx_max_rate = conf->rx_max_rate;
    if (conf->mtu)
        path->desired_conf.mtu = conf->mtu;
    path->config_dirty = 1;
}

static int
gt_path_manager_apply(struct gt_managed_path *path, struct mud *mud,
                      enum mud_state state)
{
    struct mud_path_conf conf = path->desired_conf;
    conf.local = path->bound_local;
    conf.remote = path->remote;
    conf.local_ifindex = path->bound_ifindex;
    conf.sock = path->sock;
    conf.state = state;
    conf.beat /= 1000;
    conf.pref = (unsigned char)((conf.pref << 1) | 1);
    conf.fixed_rate = (unsigned char)((conf.fixed_rate << 1) | 1);

    if (mud_set_path(mud, &conf))
        return -1;
    path->config_dirty = 0;
    return 0;
}

static int
gt_path_manager_suspend(struct gt_managed_path *path, struct mud *mud)
{
    if (!path->runtime_bound || !path->runtime_active)
        return 0;
    if (gt_path_manager_apply(path, mud, MUD_DOWN)) {
        if (errno != ENOENT)
            return -1;
        path->runtime_bound = 0;
    }
    path->runtime_active = 0;
    return 0;
}

static int
gt_path_manager_reconcile_one(struct gt_managed_path *path, struct mud *mud)
{
    struct gt_link_info info;
    int family = path->remote.sa.sa_family;
    int ret = gt_netlink_resolve(path->ifname, family,
                                 path->address_ready
                                    ? &path->current_local : NULL,
                                 &info);
    if (ret == -1)
        return -1;
    if (ret == 1)
        memset(&info, 0, sizeof(info));

    path->ifindex = info.ifindex;
    path->link_up = info.link_up;
    path->address_ready = info.address_ready;
    path->current_local = info.local;

    if (!path->desired_up || !path->link_up || !path->address_ready)
        return gt_path_manager_suspend(path, mud);

    int binding_changed = path->runtime_bound &&
        (path->bound_ifindex != path->ifindex ||
         !gt_sockaddr_addr_equal(&path->bound_local, &path->current_local));

    if (binding_changed) {
        if (mud_rebind_path(mud, path->bound_ifindex, &path->remote,
                            path->ifindex, &path->current_local,
                            path->sock)) {
            if (errno != ENOENT)
                return -1;
            path->runtime_bound = 0;
        } else {
            path->bound_ifindex = path->ifindex;
            path->bound_local = path->current_local;
        }
    }
    if (!path->runtime_bound) {
        path->bound_ifindex = path->ifindex;
        path->bound_local = path->current_local;
        if (gt_path_manager_apply(path, mud, MUD_UP))
            return -1;
        path->runtime_bound = 1;
        path->runtime_active = 1;
        return 0;
    }
    if (!path->runtime_active || path->config_dirty || binding_changed) {
        if (gt_path_manager_apply(path, mud, MUD_UP)) {
            if (errno != ENOENT)
                return -1;
            path->runtime_bound = 0;
            path->bound_ifindex = path->ifindex;
            path->bound_local = path->current_local;
            if (gt_path_manager_apply(path, mud, MUD_UP))
                return -1;
            path->runtime_bound = 1;
        }
    }
    path->runtime_active = 1;
    return 0;
}

int
gt_path_manager_set(struct gt_path_manager *manager, struct mud *mud,
                    const char *ifname, unsigned int sock,
                    struct mud_path_conf *conf)
{
    if (!manager || !mud || !ifname || !ifname[0] || !conf ||
        !conf->remote.sa.sa_family) {
        errno = EINVAL;
        return -1;
    }
    struct gt_managed_path *path =
        gt_path_manager_find(manager, ifname, &conf->remote, sock);

    if (!path) {
        if (conf->state != MUD_UP) {
            errno = ENOENT;
            return -1;
        }
        if (manager->count == MUD_PATH_MAX) {
            errno = ENOSPC;
            return -1;
        }
        path = &manager->path[manager->count++];
        memset(path, 0, sizeof(*path));
        memcpy(path->ifname, ifname, strlen(ifname) + 1);
        path->remote = conf->remote;
        path->sock = sock;
        path->desired_conf.remote = conf->remote;
        path->desired_conf.sock = sock;
        path->desired_conf.beat = 100 * 1000;
        path->desired_conf.fixed_rate = 1;
        path->desired_conf.loss_limit = 255;
    }
    gt_path_manager_update_conf(path, conf);
    if (gt_path_manager_reconcile_one(path, mud))
        return -1;

    *conf = path->desired_conf;
    conf->local = path->current_local;
    conf->local_ifindex = path->ifindex;
    return 0;
}

int
gt_path_manager_reconcile(struct gt_path_manager *manager, struct mud *mud)
{
    for (unsigned int i = 0; i < manager->count; i++)
        if (gt_path_manager_reconcile_one(&manager->path[i], mud))
            return -1;
    return 0;
}

unsigned int
gt_path_manager_status(struct gt_path_manager *manager, struct mud *mud,
                       const char *ifname, union mud_sockaddr *remote,
                       struct gt_managed_status *status, unsigned int max)
{
    struct mud_paths runtime = {0};
    if (mud_get_paths(mud, &runtime, NULL, NULL))
        return 0;

    unsigned int count = 0;
    for (unsigned int i = 0; i < manager->count && count < max; i++) {
        struct gt_managed_path *managed = &manager->path[i];
        if (ifname && ifname[0] && strcmp(ifname, managed->ifname))
            continue;
        if (!gt_remote_matches(remote, &managed->remote))
            continue;

        struct gt_managed_status *out = &status[count++];
        memset(out, 0, sizeof(*out));
        memcpy(out->ifname, managed->ifname, sizeof(out->ifname));
        out->ifindex = managed->ifindex;
        out->path.conf = managed->desired_conf;
        out->path.conf.remote = managed->remote;
        out->path.conf.local = managed->current_local;
        out->path.conf.local_ifindex = managed->ifindex;

        if (!managed->desired_up) {
            out->availability = GT_PATH_ADMIN_DOWN;
        } else if (!managed->link_up) {
            out->availability = GT_PATH_INTERFACE_DOWN;
        } else if (!managed->address_ready) {
            out->availability = GT_PATH_WAITING_ADDRESS;
        } else {
            out->availability = GT_PATH_AVAILABLE;
        }

        for (unsigned int k = 0; k < runtime.count; k++) {
            struct mud_path *candidate = &runtime.path[k];
            if (!candidate->conf.local_ifindex ||
                candidate->conf.local_ifindex != managed->bound_ifindex ||
                candidate->conf.sock != managed->sock ||
                !gt_remote_equal(&candidate->conf.remote, &managed->remote))
                continue;
            out->path = *candidate;
            break;
        }
        if (!managed->address_ready) {
            memset(&out->path.conf.local, 0, sizeof(out->path.conf.local));
            out->path.conf.local_ifindex = managed->ifindex;
        }
    }
    return count;
}
