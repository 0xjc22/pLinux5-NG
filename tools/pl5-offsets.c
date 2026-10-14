/*
 * pl5-offsets.c -- live memory dumper + offset extractor for pLinux5-NG.
 *
 * This is a *development* helper. It is built exactly like the normal payload
 * (see tools/Makefile, same prospero toolchain), sent to a console, and it:
 *
 *   1. dumps the kernel text, the kernel data region and the HV image,
 *   2. resolves every field of offset_list against the *running* firmware by
 *      verifying a signature at the expected offset and, if that fails,
 *      scanning the live kernel for it,
 *   3. packages the dumps and the resulting off_<fw>.c / offsets.json /
 *      report.txt into /data/pl5-<fw>.zip (and a copy on the USB stick).
 *
 * The point is that a user on an unsupported firmware can run this, send us
 * the resulting zip, and we derive that firmware's offsets/bake them in.
 *
 * Requirements: run after the kernel is readable, i.e. exactly where the normal
 * pLinux5-NG payload already runs (Byepervisor-style kread must work).
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include <ps5/kernel.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PL5_SIGTABLE_HEADER
#define PL5_SIGTABLE_HEADER "sigtable_1320.h"
#endif
#include PL5_SIGTABLE_HEADER

#define DMAP_BASE 0xFFFF800000000000ULL

#ifndef PL5_OUT_ROOT
#define PL5_OUT_ROOT "/data"
#endif
#ifndef PL5_USB_ROOT
#define PL5_USB_ROOT "/mnt/usb0"
#endif

#define HV_ANCHOR_OFF 0x1ba10
#define HV_ANCHOR_LEN 5
#define HV_DUMP_MAX 0x1800000 /* 24 MiB covers the whole HV reservation */

#define DUMP_CHUNK 0x10000

enum {
  HOW_MISSING = 0,
  HOW_CONST,
  HOW_VERIFIED,
  HOW_HINT,
  HOW_SCANNED,
  HOW_HV,
};

static uint64_t ktext;

static uint64_t resolved[PL5_OFF_TABLE_LEN];
static uint8_t how[PL5_OFF_TABLE_LEN];

/* -------------------------------------- kernel .text readability gating --
 * 13.20 maps kernel .text execute-only (PTE bit 58, XOTEXT): a plain
 * kernel_copyout of a .text page faults inside the kernel and panics. The
 * Byepervisor escape (run by the payload before rest mode, like the main
 * payload) clears XOTEXT on the .text PTEs and the resume flushes the stale TLB,
 * so post-resume .text reads work normally. We still verify the PTE is XOTEXT-
 * free before reading (text_readable()) so a surprise can never fault the
 * kernel -- worst case the .text is skipped. Only page tables are touched
 * during the check, and those live in ordinary memory. */
static const pl5_off_t *find_entry(const char *name);

/* Set once the kernel pmap is known and .text is confirmed readable. */
static int g_text_ok;

static uint64_t g_cr3;  /* kernel CR3 (PMAP_STORE + 0x28)      */
static uint64_t g_dmap; /* direct-map base (pm_pml4 - pm_cr3) */

#define PA_MASK 0x000FFFFFFFFFF000ULL

static uint64_t pv_rd64(uint64_t a) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)a, &v, sizeof v);
  return v;
}

/* Derive the kernel pmap + direct-map base (read-only). */
static int init_paging(void) {
  const pl5_off_t *e = find_entry("VMSPACE_VM_PMAP");
  uint64_t pmap_off = e ? (e->value ? e->value : e->expected) : 0;
  if (!pmap_off)
    return -1;

  uint64_t proc = (uint64_t)kernel_get_proc(0);
  uint64_t vm = proc ? pv_rd64(proc + KERNEL_OFFSET_PROC_P_VMSPACE) : 0;
  uint64_t pmap = vm ? pv_rd64(vm + pmap_off) : 0;
  uint64_t pm_pml4 = pmap ? pv_rd64(pmap + 0x20) : 0;
  uint64_t pm_cr3 = pmap ? pv_rd64(pmap + 0x28) : 0;
  if (!pm_pml4 || !pm_cr3)
    return -1;

  g_cr3 = pm_cr3;
  g_dmap = pm_pml4 - pm_cr3;
  return 0;
}

/* Leaf page-table entry for `va` in the kernel pmap (0 if not present). */
static uint64_t va_leaf_entry(uint64_t va, int *is_leaf) {
  uint64_t table_phys = g_cr3;

  *is_leaf = 0;
  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry = pv_rd64(g_dmap + (table_phys & PA_MASK) + idx * 8);

    if (!(entry & 1))
      return 0;
    if ((level == 1 || level == 2) && (entry & (1ULL << 7))) {
      *is_leaf = 1;
      return entry;
    }
    if (level == 3) {
      *is_leaf = 1;
      return entry;
    }
    table_phys = entry & PA_MASK;
  }
  return 0;
}

/* Confirm kernel .text is actually readable BEFORE reading it, so a surprise can
 * never fault the kernel -- worst case the .text dump is skipped. The
 * Byepervisor escape clears XOTEXT (bit 58) on the .text PTEs and the
 * suspend/resume cycle flushes the stale TLB, so post-resume the leaf entry has
 * bit 58 clear -- which is exactly why this payload enters rest mode like the
 * main one. Only page tables are read here, and they live in ordinary memory. */
static int text_readable(void) {
  int leaf = 0;
  uint64_t entry = va_leaf_entry(ktext, &leaf);
  return leaf && (entry & 1) && !(entry & (1ULL << 58));
}

static const uint64_t hv_candidates[] = {0x062800000ULL, 0x8e0800000ULL};

/* ------------------------------------------------------------------ kread */

static void wr_all(int fd, const void *buf, size_t n) {
  const uint8_t *p = buf;
  while (n > 0) {
    ssize_t r = write(fd, p, n);
    if (r <= 0)
      return;
    p += r;
    n -= (size_t)r;
  }
}

static const pl5_off_t *find_entry(const char *name) {
  for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++)
    if (strcmp(pl5_off_table[i].name, name) == 0)
      return &pl5_off_table[i];
  return NULL;
}

static int opt_va(const char *name, uint64_t *out) {
  const pl5_off_t *e = find_entry(name);
  if (!e)
    return -1;
  *out = ktext + e->expected;
  return 0;
}

/* ------------------------------------------------------------------- dumps */

static int dump_region(const char *path, uint64_t va, uint64_t cap,
                       uint64_t *actual) {
  static uint8_t buf[0x10000];
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return -1;

  uint64_t done = 0;
  while (done < cap) {
    uint32_t want = (cap - done > DUMP_CHUNK) ? DUMP_CHUNK : (uint32_t)(cap - done);
    if (kernel_copyout((intptr_t)(va + done), buf, want) != 0)
      break;
    if (write(fd, buf, want) != (ssize_t)want)
      break;
    done += want;
  }
  close(fd);
  if (actual)
    *actual = done;
  return 0;
}

/* --------------------------------------------------------------------- crc */

static uint32_t crc_tab[256];
static void crc_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++)
      c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    crc_tab[i] = c;
  }
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *p, uint32_t n) {
  crc = ~crc;
  for (uint32_t i = 0; i < n; i++)
    crc = crc_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

/* Store-only (method 0) zip writer. */
typedef struct {
  int fd;
  uint32_t off;
  int n;
  struct {
    char name[64];
    uint32_t crc, csz, usz, hoff;
  } e[16];
} zip_t;

static void zle16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void zle32(uint8_t *p, uint32_t v) {
  p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static void zwrite(zip_t *z, const void *d, uint32_t n) {
  if (write(z->fd, d, n) == (ssize_t)n)
    z->off += n;
}

static void zlocal(zip_t *z, const char *name, uint32_t crc, uint32_t csz,
                   uint32_t usz, uint16_t nlen) {
  uint8_t h[30];
  zle32(h + 0, 0x04034b50);
  zle16(h + 4, 20);
  zle16(h + 6, 0);
  zle16(h + 8, 0);
  zle16(h + 10, 0);
  zle16(h + 12, 0);
  zle32(h + 14, crc);
  zle32(h + 18, csz);
  zle32(h + 22, usz);
  zle16(h + 26, nlen);
  zle16(h + 28, 0);
  zwrite(z, h, 30);
  zwrite(z, name, nlen);
}

static void zadd_buf(zip_t *z, const char *name, const void *data, uint32_t n) {
  if (z->n >= 16)
    return;
  uint16_t nlen = (uint16_t)strlen(name);
  uint32_t crc = crc32_update(0, data, n);
  uint32_t hoff = z->off;
  zlocal(z, name, crc, n, n, nlen);
  zwrite(z, data, n);
  int i = z->n++;
  snprintf(z->e[i].name, sizeof(z->e[i].name), "%s", name);
  z->e[i].crc = crc;
  z->e[i].csz = z->e[i].usz = n;
  z->e[i].hoff = hoff;
}

static void zadd_file(zip_t *z, const char *name, const char *path) {
  if (z->n >= 16)
    return;
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return;
  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    return;
  }
  uint32_t size = (uint32_t)st.st_size;
  uint16_t nlen = (uint16_t)strlen(name);
  uint32_t hoff = z->off;
  zlocal(z, name, 0, size, size, nlen);

  static uint8_t buf[0x10000];
  uint32_t crc = 0, total = 0;
  ssize_t r;
  while ((r = read(fd, buf, sizeof(buf))) > 0) {
    crc = crc32_update(crc, buf, (uint32_t)r);
    total += (uint32_t)r;
    zwrite(z, buf, (uint32_t)r);
  }
  close(fd);

  uint8_t patch[12];
  zle32(patch + 0, crc);
  zle32(patch + 4, total);
  zle32(patch + 8, total);
  lseek(z->fd, hoff + 14, SEEK_SET);
  wr_all(z->fd, patch, sizeof(patch));
  lseek(z->fd, 0, SEEK_END);

  int i = z->n++;
  snprintf(z->e[i].name, sizeof(z->e[i].name), "%s", name);
  z->e[i].crc = crc;
  z->e[i].csz = z->e[i].usz = total;
  z->e[i].hoff = hoff;
}

static void zclose(zip_t *z) {
  uint32_t cd_off = z->off;
  for (int i = 0; i < z->n; i++) {
    uint8_t h[46];
    uint16_t nlen = (uint16_t)strlen(z->e[i].name);
    zle32(h + 0, 0x02014b50);
    zle16(h + 4, 20);
    zle16(h + 6, 20);
    zle16(h + 8, 0);
    zle16(h + 10, 0);
    zle16(h + 12, 0);
    zle16(h + 14, 0);
    zle32(h + 16, z->e[i].crc);
    zle32(h + 20, z->e[i].csz);
    zle32(h + 24, z->e[i].usz);
    zle16(h + 28, nlen);
    zle16(h + 30, 0);
    zle16(h + 32, 0);
    zle16(h + 34, 0);
    zle16(h + 36, 0);
    zle32(h + 38, 0);
    zle32(h + 42, z->e[i].hoff);
    zwrite(z, h, 46);
    zwrite(z, z->e[i].name, nlen);
  }
  uint32_t cd_size = z->off - cd_off;
  uint8_t e[22];
  zle32(e + 0, 0x06054b50);
  zle16(e + 4, 0);
  zle16(e + 6, 0);
  zle16(e + 8, (uint16_t)z->n);
  zle16(e + 10, (uint16_t)z->n);
  zle32(e + 12, cd_size);
  zle32(e + 16, cd_off);
  zle16(e + 20, 0);
  zwrite(z, e, 22);
}

/* ---------------------------------------------------------------- scanning */

static const char *how_name(uint8_t h) {
  switch (h) {
  case HOW_CONST: return "const";
  case HOW_VERIFIED: return "verified";
  case HOW_SCANNED: return "scanned";
  case HOW_HINT: return "hint";
  case HOW_HV: return "hv";
  default: return "missing";
  }
}

static void scan_kernel(void) {
  if (!g_text_ok) /* kernel pmap/dmap unknown; can't read .text safely */
    return;
  uint64_t base = ktext;
  uint64_t size = (uint64_t)PL5_KERNEL_TEXT_SIZE + PL5_KERNEL_DATA_SIZE;
  static uint8_t buf[0x40000 + PL5_SIG_MAX];
  uint32_t carry = 0;

  for (uint64_t pos = 0; pos < size;) {
    uint32_t want = (size - pos > 0x40000) ? 0x40000 : (uint32_t)(size - pos);
    if (kernel_copyout((intptr_t)(base + pos), buf + carry, want) != 0)
      break;
    uint32_t have = carry + want;

    for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++) {
      const pl5_off_t *e = &pl5_off_table[i];
      if (e->mode != PL5_MODE_SIG || e->region == PL5_REGION_HV)
        continue;
      if (resolved[i])
        continue;
      for (uint32_t j = 0; j + e->sig_len <= have; j++) {
        if (memcmp(buf + j, e->sig, e->sig_len) == 0) {
          resolved[i] = base - ktext + (pos - carry + j);
          break;
        }
      }
    }

    carry = (have < PL5_SIG_MAX - 1) ? have : PL5_SIG_MAX - 1;
    memmove(buf, buf + have - carry, carry);
    pos += want;
  }
}

/* -------------------------------------------------------------------- main */

static int find_hv(uint64_t dmap_base, uint64_t *hv_out) {
  for (unsigned i = 0; i < sizeof(hv_candidates) / sizeof(hv_candidates[0]); i++) {
    char anchor[8] = {0};
    if (kernel_copyout((intptr_t)(dmap_base + hv_candidates[i] + HV_ANCHOR_OFF),
                       anchor, sizeof(anchor)) != 0)
      continue;
    if (memcmp(anchor, "hvcGF", HV_ANCHOR_LEN) == 0) {
      *hv_out = hv_candidates[i];
      return 0;
    }
  }
  return -1;
}

int pl5_dump_offsets(void) {
  crc_init();

  uint32_t ver = kernel_get_fw_version();
  uint32_t fwv = (ver >> 0x10) & 0xFFFF;
  uint64_t hv_pa = 0;
  ktext = KERNEL_ADDRESS_TEXT_BASE;

  printf("[pl5-offsets] fw=0x%04x (raw 0x%08x) ktext=0x%llx\n", fwv, ver,
         (unsigned long long)ktext);
  fflush(stdout);

#if defined(PL5_SIGTABLE_FW)
  if (fwv != PL5_SIGTABLE_FW)
    printf("[pl5-offsets] WARNING: built with signatures for 0x%04x, running "
           "0x%04x -- results will be unreliable\n",
           (unsigned)PL5_SIGTABLE_FW, fwv);
#endif

  char dir[128];
  snprintf(dir, sizeof(dir), PL5_OUT_ROOT "/pl5-%04x", fwv);
  if (mkdir(dir, 0777) != 0 && errno != EEXIST)
    printf("[pl5-offsets] mkdir %s: %s\n", dir, strerror(errno));

  char p_text[160], p_data[160], p_hv[160], p_c[160], p_json[160], p_rep[160],
      p_zip[160];
  snprintf(p_text, sizeof(p_text), "%s/kernel_text_%04x.bin", dir, fwv);
  snprintf(p_data, sizeof(p_data), "%s/data_dump_%04x.bin", dir, fwv);
  snprintf(p_hv, sizeof(p_hv), "%s/hv_%04x.bin", dir, fwv);
  snprintf(p_c, sizeof(p_c), "%s/off_%04x.c", dir, fwv);
  snprintf(p_json, sizeof(p_json), "%s/offsets.json", dir);
  snprintf(p_rep, sizeof(p_rep), "%s/report.txt", dir);
  snprintf(p_zip, sizeof(p_zip), PL5_OUT_ROOT "/pl5-%04x.zip", fwv);

  /* Derive the kernel pmap and confirm kernel .text is actually readable before
   * touching it, so a surprise can never fault the kernel -- worst case the
   * .text dump is simply skipped. On the supported path this payload has just
   * come back from rest mode, where the Byepervisor escape left XOTEXT cleared
   * on the .text PTEs (see text_readable()). */
  g_text_ok = (init_paging() == 0) && text_readable();
  printf("[pl5-offsets] kernel text %s (cr3=%#llx dmap=%#llx)\n",
         g_text_ok ? "readable" : "unavailable",
         (unsigned long long)g_cr3, (unsigned long long)g_dmap);
  fflush(stdout);

  uint64_t got_text = 0, got_data = 0, got_hv = 0;
  if (g_text_ok)
    dump_region(p_text, ktext, PL5_KERNEL_TEXT_SIZE, &got_text);
  printf("[pl5-offsets] kernel text dump: 0x%llx bytes\n",
         (unsigned long long)got_text);
  uint64_t kdata = KERNEL_ADDRESS_DATA_BASE;
  dump_region(p_data, kdata, PL5_KERNEL_DATA_SIZE, &got_data);
  printf("[pl5-offsets] kernel data dump: 0x%llx bytes\n",
         (unsigned long long)got_data);

  /* dmap lets us read the HV reservation (guest-physical == host-physical
   * once NPT is off). It is derived from the kernel's DMPML4I/DMPDPI. */
  uint64_t dmap_base = 0;
  {
    uint64_t a;
    uint32_t ml4 = 0, pdp = 0;
    if (opt_va("KERNEL_SYM_DMPML4I", &a) == 0)
      kernel_copyout((intptr_t)a, &ml4, sizeof(ml4));
    if (opt_va("KERNEL_SYM_DMPDPI", &a) == 0)
      kernel_copyout((intptr_t)a, &pdp, sizeof(pdp));
    dmap_base = DMAP_BASE | ((uint64_t)ml4 << 39) | ((uint64_t)pdp << 30);
  }

  int hv_ok = (find_hv(dmap_base, &hv_pa) == 0);
  printf("[pl5-offsets] dmap=0x%llx hv_base=0x%llx (%s)\n",
         (unsigned long long)dmap_base, (unsigned long long)hv_pa,
         hv_ok ? "found" : "not found");
  if (hv_ok) {
    dump_region(p_hv, dmap_base + hv_pa, HV_DUMP_MAX, &got_hv);
    printf("[pl5-offsets] hv dump: 0x%llx bytes\n",
           (unsigned long long)got_hv);
  }

  /* Resolve every field. */
  memset(resolved, 0, sizeof(resolved));
  memset(how, 0, sizeof(how));

  for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++) {
    const pl5_off_t *e = &pl5_off_table[i];
    switch (e->mode) {
    case PL5_MODE_CONST:
      resolved[i] = e->value;
      how[i] = HOW_CONST;
      break;
    case PL5_MODE_HINT:
      if (e->region == PL5_REGION_HV) {
        resolved[i] = e->value;
        how[i] = (got_hv || got_data) ? HOW_HV : HOW_MISSING;
      } else {
        resolved[i] = e->value;
        how[i] = HOW_HINT;
      }
      break;
    case PL5_MODE_SIG: {
      uint8_t tmp[PL5_SIG_MAX];
      if (g_text_ok &&
          kernel_copyout((intptr_t)(ktext + e->expected), tmp, e->sig_len) == 0 &&
          memcmp(tmp, e->sig, e->sig_len) == 0) {
        resolved[i] = e->expected;
        how[i] = HOW_VERIFIED;
      }
      break;
    }
    default:
      break;
    }
  }

  scan_kernel();

  for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++) {
    const pl5_off_t *e = &pl5_off_table[i];
    if (e->mode == PL5_MODE_SIG && resolved[i] && how[i] == HOW_MISSING)
      how[i] = HOW_SCANNED;
  }

  /* report.txt */
  char *rep = malloc(1 << 16);
  if (rep) {
    int n = 0;
    n += snprintf(rep + n, (1 << 16) - n,
                  "pLinux5-NG offset extractor\nfw=0x%04x  ktext=0x%llx  "
                  "kdata=0x%llx  dmap=0x%llx\n"
                  "ktext_dump=0x%llx  data_dump=0x%llx  hv_dump=0x%llx\n\n",
                  fwv, (unsigned long long)ktext, (unsigned long long)kdata,
                  (unsigned long long)dmap_base, (unsigned long long)got_text,
                  (unsigned long long)got_data, (unsigned long long)got_hv);
    int ok = 0, hint = 0, miss = 0;
    for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++) {
      const pl5_off_t *e = &pl5_off_table[i];
      n += snprintf(rep + n, (1 << 16) - n, "%-40s 0x%09llx  %s\n", e->name,
                    (unsigned long long)resolved[i], how_name(how[i]));
      if (how[i] == HOW_CONST || how[i] == HOW_VERIFIED || how[i] == HOW_SCANNED ||
          how[i] == HOW_HV)
        ok++;
      else if (how[i] == HOW_HINT)
        hint++;
      else
        miss++;
    }
    n += snprintf(rep + n, (1 << 16) - n,
                  "\nresolved=%d hint=%d missing=%d / %zu\n", ok, hint, miss,
                  PL5_OFF_TABLE_LEN);
    int fd = open(p_rep, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      wr_all(fd, rep, (uint32_t)n);
      close(fd);
    }
  }

  /* off_<fw>.c -- drop-in replacement for source/offsets/off_<fw>.c */
  char *oc = malloc(1 << 16);
  if (oc) {
    int n = 0;
    n += snprintf(oc + n, (1 << 16) - n,
                  "#include \"offsets.h\"\n\n"
                  "/* Auto-generated by tools/pl5-offsets.c on a live 0x%04x "
                  "console. */\noffset_list off_%04x = {\n",
                  fwv, fwv);
    for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++)
      n += snprintf(oc + n, (1 << 16) - n, "    .%-40s = 0x%llX,\n",
                    pl5_off_table[i].name,
                    (unsigned long long)resolved[i]);
    n += snprintf(oc + n, (1 << 16) - n, "};\n");
    int fd = open(p_c, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      wr_all(fd, oc, (uint32_t)n);
      close(fd);
    }
  }

  /* offsets.json */
  char *js = malloc(1 << 17);
  if (js) {
    int n = 0;
    n += snprintf(js + n, (1 << 17) - n,
                  "{\n  \"firmware\": \"0x%04x\",\n  \"ktext\": \"0x%llx\",\n"
                  "  \"kdata\": \"0x%llx\",\n  \"offsets\": {\n",
                  fwv, (unsigned long long)ktext, (unsigned long long)kdata);
    for (size_t i = 0; i < PL5_OFF_TABLE_LEN; i++)
      n += snprintf(js + n, (1 << 17) - n,
                    "    \"%s\": \"0x%llX\"%s\n", pl5_off_table[i].name,
                    (unsigned long long)resolved[i],
                    (i + 1 < PL5_OFF_TABLE_LEN) ? "," : "");
    n += snprintf(js + n, (1 << 17) - n, "  }\n}\n");
    int fd = open(p_json, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      wr_all(fd, js, (uint32_t)n);
      close(fd);
    }
  }

  /* Package everything. */
  char ocname[32];
  snprintf(ocname, sizeof(ocname), "off_%04x.c", fwv);
  zip_t z = {.fd = open(p_zip, O_WRONLY | O_CREAT | O_TRUNC, 0644)};
  if (z.fd >= 0) {
    zadd_buf(&z, "report.txt", rep, rep ? (uint32_t)strlen(rep) : 0);
    zadd_buf(&z, "offsets.json", js, js ? (uint32_t)strlen(js) : 0);
    zadd_buf(&z, ocname, oc, oc ? (uint32_t)strlen(oc) : 0);
    zadd_file(&z, "kernel_text.bin", p_text);
    zadd_file(&z, "data_dump.bin", p_data);
    if (got_hv)
      zadd_file(&z, "hv.bin", p_hv);
    zclose(&z);
    close(z.fd);
    printf("[pl5-offsets] wrote %s\n", p_zip);
  }

  /* Best-effort USB copies for easy retrieval (the loader already reads the
   * stick, so it is usually mounted). */
  const char *usb_paths[] = {PL5_USB_ROOT "/pl5.zip", "/mnt/usb1/pl5.zip", NULL};
  for (int u = 0; usb_paths[u]; u++) {
    int in = open(p_zip, O_RDONLY);
    int out = in >= 0 ? open(usb_paths[u], O_WRONLY | O_CREAT | O_TRUNC, 0644) : -1;
    if (out < 0) {
      if (in >= 0)
        close(in);
      continue;
    }
    uint8_t b[0x10000];
    ssize_t r;
    while ((r = read(in, b, sizeof(b))) > 0)
      wr_all(out, b, (size_t)r);
    close(in);
    close(out);
    printf("[pl5-offsets] copied to %s\n", usb_paths[u]);
    break;
  }

  printf("[pl5-offsets] done\n");
  fflush(stdout);
  return 0;
}

#ifndef PL5_OFFSETS_MODE
/* Standalone entry point (make -C tools). Sends/runs as a plain payload; used
 * for building/CI. The supported run path is the offset payload built via
 * `make offsets`, which calls pl5_dump_offsets() from post_resume(). */
int main(void) { return pl5_dump_offsets(); }
#endif
