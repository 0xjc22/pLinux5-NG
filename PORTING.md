# Porting ps5-linux-loader to high firmware (13.20)

This document explains how pLinux5-NG reuses ps5-linux-loader's boot path and
what is required to make it boot Linux on high firmware (8.xx+, here 13.20).

## 1. How ps5-linux-loader works on 3.00–7.61

The payload never patches the hypervisor from the guest directly. It splits the
work into three blobs:

| Blob | Runs in | Job |
|------|---------|-----|
| `shellcode_0607` | guest, via ACPI-wakeup ROP | memory disclosure used to locate HV structures |
| `shellcode_kernel` | kernel context (S3 resume) | relocate bzImage/initrd, build `boot_params`/e820, display + HDMI bring-up, then trigger the HV |
| `shellcode_hv` | hypervisor root mode (all 16 cores) | `stgi`, clear `EFER.SVM` / `MSR_VM_CR`, wipe MTRRs, halt APs, disable IOMMU, build the final e820, jump into the Linux kernel |

The escape mechanism (per-FW, `hv_defeat_0304.c`, `hv_defeat_0506.c`,
`hv_defeat_0607.c`) is what gets `shellcode_kernel` to run and then pivots into
`shellcode_hv`. The relocation/boot logic in `shellcode_kernel` and all of
`shellcode_hv` is firmware-independent: the teardown constants (AMD IOMMU
`0xfdd80000+0x18`, AMDGPU MMIO `0xE0600000`, VRAM, etc.) are hardcoded.

## 2. What is different on high firmware

The 3.00–7.61 escape abuses the ACPI suspend path (`AcpiSetFirmwareWakingVector`
→ `HV_MP_STARTUP_CALL`) with a ROP chain and an IDT/TSS gate hook whose target
lives in the kernel code cave. On 13.20:

- The physical layout and the kernel code cave are different
  (kernel text is at phys `0x1b600000`, i.e. VA `0xFFFFFFFF9B600000`).
- The escape used in practice is **Byepervisor-Reborn**: a kernel-context khook
  on `KERNEL_SYM_HV_MP_STARTUP_CALL` that redirects the `RSI` startup_mp payload
  to a page we control (`STARTUP_MP_PAYLOAD_PAGE = 0x3FFFF000`), plus a
  kernel `.text` patch to unset XOTEXT and set RW.
- On resume the payload executes in hypervisor root mode on every core; we can
  reuse the same `shellcode_hv` teardown+boot blob.

So the port consists of **replacing the escape** and **re-deriving the 13.20
offsets**, while keeping the boot path.

## 3. Architecture in pLinux5-NG

```
source/main.c
  └─ setup_env()  (utils.c: set_offsets, init_global_vars)
  └─ fetch_linux() (loader.c: bzImage/initrd/cmdline/vram from USB)
  └─ prepare_resume() (prepare_resume.c: stage shellcode_kernel in the kdata cave)
  └─ vector dispatch by fw:
        0x0300..0x04xx -> hv_defeat_0304()
        0x0500..0x064F -> hv_defeat_0506()
        0x0650..0x07FF -> hv_defeat_0607()
        0x0800..0x13FF -> hv_defeat_1320()   <-- high-FW vector (Byepervisor khook)
  └─ enter_rest_mode(); wake -> hv_boot payload -> shellcode_hv (headless, single-core)
```

`shellcode_hv` and the boot-related parts of `shellcode_kernel` are unchanged
except for the `HV_HEADLESS_SINGLE_CORE` barrier guard in `shellcode_hv`;
`shellcode_hv_boot/` holds the new `hv_boot` launch payload.

The high-FW vector is implemented in `source/hv_defeat_1320.c` on top of the
vendored Byepervisor khook crate:

- `source/byepervisor/khook.c`, `include/byepervisor/khook.h` — IDT-gate hook
  (verbatim from Byepervisor-Reborn).
- `source/byepervisor/kdlsym.c` — sym/gadget lookup adapted to `env_offset`.
- `source/byepervisor/paging.c` — PTE walkers used for the escape.
- `shellcode_break_hv/` — the `break_hv` startup_mp payload (NPT teardown).

## 4. Firmware 13.20 offsets

All 13.20 values live in `offset_list off_1320` in `source/offsets.c`. They are
taken from Byepervisor-Reborn's `include/offsets/13_20.h`, cross-checked against
our own dumps.

### Known (in place)

Kernel symbols (raw offsets from `KERNEL_ADDRESS_TEXT_BASE`):

| Symbol | Offset |
|--------|--------|
| `KERNEL_SYM_SYS_GETUID` | `0x2A8B20` |
| `KERNEL_SYM_PRINTF` | `0x04ABB80` |
| `KERNEL_SYM_HV_MP_STARTUP_CALL` | `0xC0A310` |
| `KERNEL_SYM_MP_STARTUP_INIT_VECTOR` | `0x26A798` |
| `KERNEL_SYM_PMAP_STORE` | `0x3B24FF8` |
| `KERNEL_SYM_DATA_CAVE` | `0x2D29000` |
| `KERNEL_SYM_DMPML4I` | `0x3B25294` |
| `KERNEL_SYM_DMPDPI` | `0x3B25298` |
| `KERNEL_SYM_PML4PML4I` | `0x3B23E4C` |
| `KERNEL_SYM_IDT_ARRAY` (`IDT`) | `0x3B90300` |
| `KERNEL_SYM_COMMON_TSS` (`COMMON_TSS`) | `0x3B92FE0` |
| `KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK` | `0x3909B0` |
| `VMSPACE_VM_PMAP` | `0x1D8` |

HV:

| Symbol | Value |
|--------|-------|
| HV loader PA (regular) | `0x062800000` |
| HV loader PA (pro) | `0x8e0800000` |
| `HV_SYM_HEAP_BASE` | `0x83028` |
| `HV_SYM_PCPUS` | `0x82A60` |

Gadgets: the full `g_gadget_map_1320` set (`POP_RAX/RCX/RDI/RSI/RDX/RSP`,
`POP_R8`, `ST_RCX_RDX`, `ST_RCX_RAX`, `STORE_RCX_R8`, `STORE_RDI8_RCX`,
`OR_RCX_EAX`, `SET_DR7`, `IRETQ`, `PIVOT_ADD_RSP28_RET`).

Cross-checks from our dumps (`../local/playstation-SecRec/dumps/hv_re_notes.txt`):
pcpus at `hv+0x82A60`, heap-base symbol at `hv+0x83028`, 16 VMCBs at
`hv+0x257000` (phys `0x62A57000`) stride `0x2000`, HV image strings
`"HV loader"`/`"hypercore"`.

### Located by dump scan (this session)

Derived by scanning `dumps/kernel_text_1320.bin` (`.text`, base
`0xFFFFFFFF9B600000`, file offset == offset) and resolving string references in
`dumps/data_dump*.bin` (`.data`, base `0xFFFFFFFF9C2B0000`):

| Symbol | Offset | Evidence |
|--------|--------|----------|
| `FUN_SMP_RENDEZVOUS` | `0xAF94E0` | 4-arg wrapper; loads `all_cpus` (`[0x9F2E9E88]`) into `RDI` and `jmp`s `smp_rendezvous_cpus` (`0xAF92B0`). |
| `KERNEL_CFI_CHECK` | `0x44E5D0` | Out-of-line UBSan CFI handler; reached from every indirect-call slow path (e.g. `smp_targeted_tlb_shootdown` `0x817C50`, `smp_rendezvous_cpus`). References the `"cfi_check_fail"` string `0x9C900E52`. Patch byte 0 to `0xC3` to disable CFI. |

Rendezvous internals for reference: `smp_ipi_mtx` `0x9F2E9EA8` (lock
`0x9BAC4FB0`, unlock `0x9BAC5340`, init `0x9BAC5BF0`); `all_cpus`
`0x9F2E9E88`; `smp_rendezvous_action` `0x9C0F9110`; init/`mtx_init` fn
`0x9C0F9D80` (uses the `"smp rendezvous"` witness `0x9C8CA448`).

### In progress: not-yet-located symbols (leads)

These are non-blocking for the escape but needed for a booted/usable system.
Cross-firmware extrapolation is unreliable (the kernel data layout jumps between
FW families, e.g. `G_VBIOS` moves ~57 MB between 6.xx and 7.xx), so each needs
its own signature:

- `KERNEL_UART_OVERRIDE` (`.data` `uint32_t`; `activate_uart()` zeroes it).
  Likely lead: the UART driver softc at VA `0xFFFFFFFF9EA4F4A8` (base
  `0xFFFFFFFF9EA4F468`), `.data` offset `0x279F4A8` in `data_dump_88m.bin`,
  `+0x70` = `0xC1010100` (UART register base). Driver `.text` at `0x9B947180`
  and `0x9B948E80` reference the softc (`+0x00/0x18/0x20/0x28`). No `.text` ref
  to the `+0x30`/`0xC1010100` field was found, so this is not yet confirmed.
- Display/HDMI `G_VBIOS`, `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_INITIALIZE`,
  `FUN_MP3_INVOKE`: MP3/HDMI/DP module string refs mapped in `.text`, e.g.
  `"failed to suspend mp3 kmd"` -> `0x9C00C02A`, `"mp3_scanin_unblock_handler"`
  -> `0x9C00C4A7`, `"failed to resume mp3 kmd"` -> `0x9C00C114`; HDMI error
  strings cluster around `0x9BAAF...`/`0x9BAB0xxx`. Exact entry points TBD.
- `PS5_WIFI_FW_OFFSET`/`SIZE`: blob is loaded from the initrd
  `lib/nxp/pcieuartiw620_combo_v1.bin`; kernel-side copy not yet located.

### Remaining gaps (fields still `0` in `off_1320`)

The escape itself (`hv_defeat_1320()`) only needs the khook/HV/gadget offsets
enforced by `check_offsets()`; those are all populated, so the escape can run
today. The gaps below only feed the **Linux prep** (multi-core launch + boot
blob), which is not wired yet:

- `KERNEL_UART_OVERRIDE`: a `.data` global (`ktext + 0x1F...` on 5.00-7.61);
  still unlocated. The only remaining hard prerequisite for kernel prep.
- `FUN_MEMCPY`, `FUN_SMP_NO_RENDEVOUS_BARRIER`: **not required** — the
  shellcode supplies its own memcpy and no-op barrier.
- `IOMMU_SOFTC`, `DATA_BASE_GVMSPACE` (`VMSPACE_VM_VMID`=`0x1E4`,
  `VMSPACE_VM_PMAP`=`0x1D8`): upstream marks these "not needed" for 6.00+.
- Display/HDMI bring-up (headless boot does not need these): `G_VBIOS`,
  `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_INITIALIZE`, `FUN_MP3_INVOKE`.
- HV IOMMU helpers (used by the 3.00-7.61 boot): `FUN_HV_IOMMU_SET_BUFFERS`,
  `FUN_HV_IOMM_WAIT_COMPLETION`.
- WiFi firmware blob: `PS5_WIFI_FW_OFFSET`, `PS5_WIFI_FW_SIZE`.
- Possibly obsolete for this vector: `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA`
  (the Byepervisor vector does not use a fixed VMEXIT cave).

> Kernel base note: `KERNEL_ADDRESS_TEXT_BASE` / `KERNEL_ADDRESS_DATA_BASE` are
> provided by the SDK. For 13.20 they are `0xFFFFFFFF9B600000` /
> `0xFFFFFFFF9C2B0000`. If the SDK does not know 13.20, `init_global_vars()` in
> `source/utils.c` must compute them from the firmware.

## 5. Status of the high-FW vector

### Done

- Vendored the Byepervisor khook crate under `source/byepervisor/` +
  `include/byepervisor/` (khook verbatim; kdlsym adapted to `env_offset`;
  paging walkers adapted).
- Added the `off_1320` sym/gadget fields the khook needs, including
  `DMPML4I`/`DMPDPI`/`PML4PML4I`.
- Vendored the proven `break_hv` startup_mp payload under
  `shellcode_break_hv/`.
- Implemented `hv_defeat_1320()`:
  1. `kernel_set_ucred_authid` + pin to core 0.
  2. Escape: walk the kernel pmap and clear `XOTEXT` / set `RW` on `.text`.
  3. Mark `STARTUP_MP_PAYLOAD_PAGE` executable.
  4. `stage_hv_boot()`: build the 0–5 GiB identity page table at `cave_hv_paging`,
     copy `shellcode_hv` to `cave_hv_code`, and relocate `bzImage`/`initrd` +
     `linux_info` into the identity-mapped cave (`cave_bzImage`/`cave_linux_info`).
  5. Stage the `hv_boot` launch payload (`shellcode_hv_boot/`): it abandons the
     guest, sets `CR3 = cave_hv_paging` and jumps to `cave_hv_code`.
  6. Install the oneshot khook on `KERNEL_SYM_HV_MP_STARTUP_CALL` (core 0,
     IST 6), redirecting `RSI` to the payload page; persist the ARMED state.
  7. Return to `main()` which sleeps and calls `enter_rest_mode()`.

After wake the payload runs in HV root mode, switches address space and boots
Linux. This is a **headless, single-core** bring-up for staging/review; it has
**not** been run on hardware yet.

### Remaining

- **Multi-core launch.** The khook fires on one core, so `HV_HEADLESS_SINGLE_CORE`
  skips the all-cores barrier in `shellcode_hv` and appends `maxcpus=1 nosmp` to
  the cmdline. The other 15 cores stay parked in the hypervisor. A full boot
  needs to drive every core (smp_rendezvous or a LAPIC IPI to the `vmmcall`
  trigger) and drop the single-core flag.
- **Display bring-up.** Headless only; the upstream `shellcode_kernel` display
  path (`g_vbios`, `transmitter_control`, `mp3_*`) still needs the missing
  symbols listed above.
- Verify the SDK's `KERNEL_ADDRESS_TEXT_BASE` for 13.20 (or compute it).

> The multi-core path is not wired yet, so do not expect a fully usable system:
> core 0 boots Linux UP-only while the APs remain in the (now abandoned) hyper-
> visor. Keep `break_hv` (`shellcode_break_hv/`) around as the safe passthrough.

## 6. Build & deploy

```bash
export PS5_PAYLOAD_SDK=/nyaa/coding/local/playstation-SecRec/sdk/ps5-payload-sdk
export LLVM_CONFIG=/nyaa/coding/public/PS5/dRPC5/pLabs5-SDK/tools/nixos/llvm-config
make -j
nc -N <PS5_IP> 9021 < bin/pLinux5-NG.elf
```

## 7. Credits

- [theflow](https://github.com/TheOfficialFloW) / [c0w](https://github.com/c0w-ar)
  — [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) (boot path,
  shellcode, this project's base).
- [flatz](https://gist.github.com/flatz) — original HV exploit; cragson — HV
  exploit implementation.
- Byepervisor / Byepervisor-Reborn — high-firmware (8.xx+) khook escape.
- [john-tornblom](https://github.com/john-tornblom) — PS5 payload SDK.

## 7a. Live validation (13.20, console)

Read-only probe `payloads/verify-1320/` (in the SecRec tree) run against a live
13.20 console (`kernel_get_fw_version() == 0x13200006`) with Byepervisor loaded:

- Kernel R/W confirmed: `*(ALLPROC) = 0xffffa31b3305ccf0`.
- **Runtime kernel text base is `0xffffffffd49d0000`**, not the
  `0xffffffff9b600000` used when analysing our static dumps. The two dumps are
  byte-identical at the same *offset* (`base+0x4abb80` =
  `55 48 89 e5 53 48 83 ec 58 48 8d 1d 80 c7 45 03`, `base+0x44e5d0` =
  `55 48 89 e5 41 57 41 56 53 50 48 89 f3 49 89 fe`), i.e. the absolute base
  differs by a constant but every `offset_list` value (which is relative to
  `KERNEL_ADDRESS_TEXT_BASE`) is correct.
- Runtime already uses the right base: `source/utils.c` sets
  `ktext = KERNEL_ADDRESS_TEXT_BASE`. The `offsets.c` comment claiming the base
  is `0x9b600000` is stale and refers only to the dump's addressing, not to the
  live value.

Consequence: the unlocated offsets (`KERNEL_UART_OVERRIDE`, `G_VBIOS`,
`FUN_TRANSMITTER_CONTROL`, `FUN_MP3_*`, `FUN_HV_IOMMU_*`, `PS5_WIFI_FW_*`) are
only consumed by the legacy `shellcode_kernel` args in `prepare_resume.c` and by
display/WiFi features. They are **not** on the 13.20 `shellcode_hv` boot path,
which needs only the fields `check_offsets()` in `hv_defeat_1320.c` verifies.

## 7b. Wake-crash bisection (`PL5_DIAG`)

The first hardware runs armed the escape successfully (`[A]`..`[F]`) but the
console crashed instead of resuming, with no post-resume output. Because the
console has no UART and each attempt costs a power cycle, the vector is buildable
in five progressively-more-invasive diagnostic stages selected with
`-DPL5_DIAG=<n>`.

`enter_rest_mode()` only *requests* suspend and returns immediately, so
`post_resume()` runs while the console is still awake. It therefore prints a
pre-suspend marker `[W0] pre-suspend ... waiting for resume` first, then polls
the oracle until `break_hv` stamps the cookie, then prints the *real*
`[W] resumed from rest mode ... cookie=... NPT disabled`. Only `[W]` proves a
genuine resume; a run that shows `[W0]` but never `[W]` crashed in
suspend/resume, and a run with no `[W0]` at all crashed before sleeping.

| Stage | Escape | Hook | RSI redirect | Phase B staging | Phase B takeover | Tests |
|-------|--------|------|--------------|-----------------|------------------|-------|
| 0 | no | no | no | no | no | S3 round-trip + elfldr resumes this process at all |
| 1 | yes | yes | no | no | no | the IDT/DR gate survives suspend/resume and the HV `startup_mp` call fires the hook |
| 2 | yes | yes | yes (`break_hv`) | no | no | `break_hv` (NPT off, cookie, jump to init vector) |
| 3 | yes | yes | yes | yes | no | `stage_hv_boot()`'s ~66 MB cave write, isolated |
| 4 | yes | yes | yes | yes | yes | full takeover + `shellcode_hv` → Linux |

Build one stage at a time (the `-D` change does not retrigger a rebuild on its
own):

```bash
export PS5_PAYLOAD_SDK=/nyaa/coding/local/playstation-SecRec/sdk/ps5-payload-sdk
export LLVM_CONFIG=/nyaa/coding/public/PS5/dRPC5/pLabs5-SDK/tools/nixos/llvm-config
for n in 0 1 2 3 4; do
  make clean-objs >/dev/null
  make PL5_DIAG=$n -j && cp bin/pLinux5-NG.elf bin/pLinux5-NG-diag$n.elf
done
```

**Hardware results so far (2026-10-13):**

- Stage 2: `[A]`..`[F]` armed, `[W0]`, then **`[W] ... cookie=0xcafe... NPT
  disabled`** and `[Y] diag=2 stop` -- **phase A works, console stays up**. The
  arm-time `stage_hv_boot()` / `prepare_resume()` deviations were the wake-crash
  cause.
- Stage 3 (old definition = full takeover): console **crashed**. The only code
  path unique to it is `stage_hv_boot()` + the takeover hook; the new stage 3
  isolates `stage_hv_boot()`.

Recommended next: run **stage 3** (staging only). Stays up → the ~66 MB cave
write is safe and the crasher is the takeover hook (stage 4). Crashes → the cave
write itself is the problem.

`stage_hv_boot()` now prints `[S1]`..`[S6]` around each sub-step (identity map,
shellcode copy, linux_info, bzImage, initrd) so the exact faulting write is
visible on screen.

### Stage 4 crash: general VMEXIT dispatcher vs VMMCALL-specific handler

Stage 4 (full takeover) crashed again right after `[W]`, with neither the FTP
log nor the elfldr socket showing any `[P*]`. Root cause in the blob: it patched
the **general VMEXIT dispatcher entry** at `0x62846c00` with the
`mov cr3`/`jmp cave` stub. That entry is reached for *every* exit reason
(timer/RDTSC/MSR/RDRAND/NPF/...), not just VMMCALL. With NPT disabled the guest
still VMEXITs constantly, so the first unrelated exit — often on the BSP itself,
mid `smp_rendezvous` setup — sent one CPU into `shellcode_hv` while the others
were still spinning in the rendezvous. `shellcode_hv` waits for the full set, so
the console hung.

Fix, matching the intent stated in the blob header ("the first VMMCALL hands
control to shellcode_hv"):

- Patch the **VMMCALL-specific handler** `0x62847375` (target of VMEXIT
  jump-table A for `ec=0x081`) instead of the dispatcher entry, so only a
  deliberate `vmmcall` diverts.
- Drive the rendezvous action through the kernel's hypercall-4 wrapper
  `ktext+0xc09e40` (`push rbp;mov rbp,rsp;mov eax,4;vmmcall;pop rbp;ret`).
  RAX=4 keeps the guest off the `RAX==0x17` fast path that would otherwise divert
  VMMCALL to `0x62846cc9` (a different, unpatched path).

Touched: `shellcode_hv_takeover/takeover.c` (patch target + action) and
`source/hv_defeat_1320.c` (a `[W+]` post-wake settle loop that re-opens the log a
few times so `[W]`/`[P*]` actually reach the socket instead of vanishing in the
wake window). Rebuild all stages.

### Deviations from Byepervisor's arm path that were removed here

Byepervisor's arm path is only: stage `break_hv` into `DATA_CAVE+0x1000`, mark
`0x3FFFF000` executable, patch kernel `.text` RW/XOTEXT, install the oneshot
hook, then idle. Two deviations were carrying arm-time risk and are now gone:

- `stage_hv_boot()` is **no longer called before sleeping**. It wrote ~64 MB
  (bzImage + initrd + identity table) into the 4 GiB cave, which Byepervisor
  never touches pre-suspend, and it is redundant: `post_resume()` re-stages
  everything for phase B anyway.
- `prepare_resume()` (legacy `shellcode_kernel` staging + a `page_chain_set_rw`
  rewrite driven by the low-FW `cr3`/`dmap` globals) is **skipped for fw >= 8.00**:
  the 13.20 vector never uses `shellcode_kernel`.

## 8. License

AGPL-3.0 (`LICENSE`). Boot path and shellcode are GPL-3.0 from ps5-linux-loader
and retain their original authorship; combined here per the GPL/AGPL
compatibility provisions. The files under `source/byepervisor/`,
`include/byepervisor/` and `shellcode_break_hv/` are vendored from
Byepervisor-Reborn (AGPL-3.0-or-later).
