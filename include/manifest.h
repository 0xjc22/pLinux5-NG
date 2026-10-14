#pragma once

#include <stddef.h>

/* ===========================================================================
   Build and identity metadata for the payload.

   The values are written in exactly one place - source/manifest/manifest.c -
   and read everywhere else through kManifest. Nothing here is configurable at
   runtime. The Makefile and CI read `version` out of that same file (the
   manifest table is the single source of truth for the version), so the ELF,
   the file/release name and this table cannot drift apart.

   This is deliberately self-contained: pLinux5-NG builds against the PS5
   payload SDK, not the pLabs5 SDK, so the layout lives here rather than in
   <plabs5/manifest.h>.
   =========================================================================== */
typedef struct {
  /* Short name, used in the payload's banner/log header and release text. */
  const char *app_name;

  /* The project's own version. Bump this on a release; it is the ONLY version
     field. Read by the Makefile (version derivation) and by CI to name
     releases - keep it MAJOR.MINOR or MAJOR.MINOR.PATCH, numeric. */
  const char *version;

  /* Who wrote it, and the org it belongs to. Attribution is a factual claim,
     kept next to the licence rather than in user-facing text. */
  const char *dev_name;
  const char *org_name;

  /* SPDX identifier. */
  const char *license;

  /* Canonical repository. */
  const char *repo_url;

  /* NULL-terminated list of people who contribute to this project. */
  const char *const *contributors;

  /* NULL-terminated list of upstream credits/attribution. The boot path and
     shellcode come from ps5-linux-loader and the escape from
     Byepervisor-Reborn, so their authors are credited here. */
  const char *const *credits;
} manifest_t;

extern const manifest_t kManifest;

/* "<app name> <version>" - one line naming the payload and its version, for
   log headers and release text. Always NUL-terminates when cap > 0. */
void manifest_identity(char *out, size_t cap);
