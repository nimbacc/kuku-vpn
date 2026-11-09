/*
 * Kuku VPN v1.6.0 — tor runner shim.
 *
 * The tor binary that ships in the APK (libtor.so, built by the Tor Project's
 * kmp-tor packaging, NDK r28) is a SHARED LIBRARY that exports the libtor C
 * API (`tor_main`, `tor_main_configuration_*`). It cannot be exec'd directly,
 * so this tiny PIE executable dlopen()s it by ABSOLUTE path and calls
 * tor_main with tor's arguments.
 *
 * Why an executable at all: running tor as a CHILD PROCESS (same pattern as
 * libpsiphon.so) gives us stdout/stderr piping, the 2s-then-force teardown
 * ladder via Process.destroy()/destroyForcibly(), and process isolation —
 * a hung or crashed tor can never take the app down.
 *
 * CI compiles this per ABI with the NDK clang:
 *   $CC -O2 -s torrun.c -o libtorrun.so -ldl
 * (NDK executables are PIE by default; the -ldl is harmless/needed on API 24.)
 *
 * Loop safety: the VPN service excludes the app's own UID from the tunnel,
 * so tor's sockets bypass the TUN exactly like the Psiphon core's do.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*tor_main_fn)(int argc, char **argv);

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <libtor.so> <tor args...>\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", argv[1], dlerror());
        return 3;
    }
    tor_main_fn tor_main = (tor_main_fn)dlsym(h, "tor_main");
    if (!tor_main) {
        fprintf(stderr, "dlsym(tor_main) failed: %s\n", dlerror());
        return 4;
    }
    /* tor_main wants argv[0] to be the program name. */
    char **targv = (char **)malloc((size_t)(argc - 1) * sizeof(char *));
    if (!targv) return 5;
    targv[0] = "tor";
    for (int i = 2; i < argc; i++) targv[i - 1] = argv[i];
    int rc = tor_main(argc - 1, targv);
    fprintf(stderr, "tor_main exited rc=%d\n", rc);
    free(targv);
    return rc;
}
