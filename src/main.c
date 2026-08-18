#include "common.h"
#include "argz.h"

volatile sig_atomic_t gt_alarm;
volatile sig_atomic_t gt_reload;
volatile sig_atomic_t gt_quit;

static void
gt_sa_handler(int sig)
{
    switch (sig) {
    case SIGALRM:
        gt_alarm = 1;
        return;
    case SIGHUP:
        gt_reload = 1; /* FALLTHRU */
    default:
        gt_quit = 1;
    }
}

static void
gt_set_signal(void)
{
    struct sigaction sa = {0};

    sa.sa_handler = gt_sa_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

int gt_list    (int, char **, void *);
int gt_show    (int, char **, void *);
int gt_bench   (int, char **, void *);
int gt_bind    (int, char **, void *);
int gt_set     (int, char **, void *);
int gt_keygen  (int, char **, void *);
int gt_path    (int, char **, void *);
int gt_version (int, char **, void *);

/* argz_print_help()'s own ARGZ_LEN column (14) is too narrow for entries
 * like "bench multicore fallback", so the bare `glorytun` summary uses its
 * own wider column instead of the shared argz_print() path. Descriptions
 * for the real top-level commands still come from z[] itself below -- only
 * the sub-command hint lines are one-off strings, since "bench multicore"
 * etc. aren't top-level argz entries with a description of their own. */
#define GT_HELP_LEN 25

static void
gt_help_line(const char *name, const char *help)
{
    printf("  %-*s  %s\n", GT_HELP_LEN, name, help);
}

static void
gt_print_commands(struct argz *z)
{
    gt_help_line("option", "description");

    for (int i = 0; z[i].name; i++) {
        gt_help_line(z[i].name, z[i].help);

        if (!strcmp(z[i].name, "bench")) {
            gt_help_line("bench multicore",
                        "Bench aggregate multi-core crypto throughput");
            gt_help_line("bench multicore fallback",
                        "Same, using the ChaCha20 fallback cipher");
        } else if (!strcmp(z[i].name, "bind")) {
            gt_help_line("bind qlen",
                        "Set the tun device's tx queue length, e.g. "
                        "bind qlen 1000 (default is the kernel's own)");
        } else if (!strcmp(z[i].name, "path")) {
            gt_help_line("path watch",
                        "Live-refresh path status every second");
            gt_help_line("path mtu",
                        "Set the fixed MTU to use, e.g. "
                        "path up mtu 1400 (default 1400, no probing)");
            gt_help_line("path connections",
                        "Parallel UDP sub-flows for one path, e.g. "
                        "path up via wan0 connections 4 (default 1, "
                        "requires via)");
        }
    }
}

int
main(int argc, char **argv)
{
    gt_set_signal();

    struct argz z[] = {
        {"list",    "List all tunnels",          gt_list,    .grp = 1},
        {"show",    "Show tunnel information",   gt_show,    .grp = 1},
        {"bench",   "Start a crypto bench",      gt_bench,   .grp = 1},
        {"bind",    "Start a new tunnel",        gt_bind,    .grp = 1},
        {"set",     "Change tunnel properties",  gt_set,     .grp = 1},
        {"keygen",  "Generate a new secret key", gt_keygen,  .grp = 1},
        {"path",    "Manage paths",              gt_path,    .grp = 1},
        {"version", "Show version",              gt_version, .grp = 1},
        {0}};

    if (argc == 1) {
        gt_print_commands(z);
        return 0;
    }
    return argz_main(argc, argv, z);
}
