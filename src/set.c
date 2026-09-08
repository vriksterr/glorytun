#include "common.h"
#include "ctl.h"
#include "argz.h"

int
gt_set(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    struct argz_ull kx = {.suffix = argz_time_suffix};
    struct argz_ull tt = {.suffix = argz_time_suffix};
    struct argz_ull ka = {.suffix = argz_time_suffix};
    struct argz_ull rw = {.suffix = argz_time_suffix};

    struct argz z[] = {
        {"dev",           "Tunnel device",       gt_argz_dev, &dev},
        {"kxtimeout",     "Key rotation timeout",   argz_ull,  &kx},
        {"timetolerance", "Clock sync tolerance",   argz_ull,  &tt},
        {"keepalive",     "Keep alive timeout",     argz_ull,  &ka},
        {"reorderwindow", "Packet resequencing window (default off)",
                                                     argz_ull,  &rw},
        {"flow",   "Path scheduling: one flow rides one path (default) "
                   "-- avoids a single ordered-delivery stream mistaking "
                   "cross-path reordering for loss",         .grp = 1},
        {"packet", "Path scheduling: spread every packet across paths "
                   "regardless of flow -- lets one flow exceed a single "
                   "path's own capacity, at the cost of reordering; "
                   "pair with reorderwindow",                .grp = 1},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    struct ctl_msg req = {
        .type = CTL_CONF,
        .conf = {
            .kxtimeout      = kx.value * UINT64_C(1000),
            .timetolerance  = tt.value * UINT64_C(1000),
            .keepalive      = ka.value * UINT64_C(1000),
            .reorder_window = rw.value * UINT64_C(1000),
        },
    }, res = {0};

    if (argz_is_set(z, "flow"))
        req.conf.path_schedule = (MUD_SCHEDULE_FLOW << 1) | 1;
    else if (argz_is_set(z, "packet"))
        req.conf.path_schedule = (MUD_SCHEDULE_PACKET << 1) | 1;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = ctl_reply(fd, &res, &req);

    if (!ret) {
        char t0[32], t1[32], t2[32], t3[32];
        gt_totime(t0, sizeof(t0), res.conf.kxtimeout      / 1000);
        gt_totime(t1, sizeof(t1), res.conf.timetolerance  / 1000);
        gt_totime(t2, sizeof(t2), res.conf.keepalive      / 1000);
        gt_totime(t3, sizeof(t3), res.conf.reorder_window / 1000);

        printf("set dev %s kxtimeout %s timetolerance %s keepalive %s "
               "reorderwindow %s schedule %s\n",
                res.tun_name, t0, t1, t2, t3,
                res.conf.path_schedule == MUD_SCHEDULE_PACKET
                    ? "packet" : "flow");
    }
    if (ret == -1 && errno)
        perror("set");

    ctl_delete(fd);

    return ret;
}
