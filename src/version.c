#include "common.h"
#include "argz.h"

#include <sodium.h>

int
gt_version(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    printf("%s 1.0\n", PACKAGE_NAME);
    printf("libsodium %i.%i\n",
           sodium_library_version_major(),
           sodium_library_version_minor());

    return 0;
}
