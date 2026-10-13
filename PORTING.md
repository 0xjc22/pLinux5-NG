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

### Remaining gaps (fields still `0` in `off_1320`)

These must be located (by signature-scanning `dumps/kernel_text_1320.bin` and the
kernel data dumps) before 13.20 can boot:

- Loader utils: `IOMMU_SOFTC`, `VMSPACE_VM_VMID`, `DATA_BASE_GVMSPACE`
  (`VMSPACE_VM_PMAP` is known: `0x1D8`).
- Kernel-context prep: `FUN_MEMCPY`, `FUN_SMP_RENDEZVOUS`,
  `FUN_SMP_NO_RENDEVOUS_BARRIER`, `KERNEL_CFI_CHECK`, `KERNEL_UART_OVERRIDE`.
- Display/HDMI bring-up (headless boot does not need these): `G_VBIOS`,
  `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_INITIALIZE`, `FUN_MP3_INVOKE`.
- HV IOMMU helpers (used by the 3.00–7.61 boot): `FUN_HV_IOMMU_SET_BUFFERS`,
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

## 8. License

AGPL-3.0 (`LICENSE`). Boot path and shellcode are GPL-3.0 from ps5-linux-loader
and retain their original authorship; combined here per the GPL/AGPL
compatibility provisions. The files under `source/byepervisor/`,
`include/byepervisor/` and `shellcode_break_hv/` are vendored from
Byepervisor-Reborn (AGPL-3.0-or-later).
