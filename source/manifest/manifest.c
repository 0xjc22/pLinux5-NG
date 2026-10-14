#include "manifest.h"
#include <stdio.h>

/* ===========================================================================
   EDIT THESE VALUES.

   This is the single definition of pLinux5-NG's identity. On a release: bump
   `version` - that is the only number to touch. The Makefile (and CI, for the
   release name) read it straight out of this file, so nothing else needs to
   change. Keep it MAJOR.MINOR or MAJOR.MINOR.PATCH, all numeric.
   =========================================================================== */
const char *const kContributors[] = {
    "niko86c",
    "dseif0x",
    NULL,
};

const char *const kCredits[] = {
    "theflow",
    "c0w",
    "flatz",
    "cragson",
    "john-tornblom",
    "Byepervisor-Reborn",
    NULL,
};

const manifest_t kManifest = {
    .app_name = "pLinux5-NG",
    .version = "0.1.0",
    .dev_name = "niko86c",
    .org_name = "pLabs5",
    .license = "AGPL-3.0-only",
    .repo_url = "https://github.com/pLabs5/pLinux5-NG",
    .contributors = kContributors,
    .credits = kCredits,
};

void manifest_identity(char *out, size_t cap) {
  if (!out || cap == 0)
    return;
  snprintf(out, cap, "%s %s", kManifest.app_name, kManifest.version);
}
