#include "offsets.h"

/*
 * Firmware 13.20 (high-FW, Byepervisor vector).
 *
 * Kernel/HV symbol offsets are taken from Byepervisor-Reborn's
 * include/offsets/13_20.h and cross-checked against our own 13.20 dumps
 * (see local/playstation-SecRec/dumps/hv_re_notes.txt and PORTING.md).
 *
 * NOTE: for 13.20 the kernel text base is KERNEL_ADDRESS_TEXT_BASE =
 * 0xFFFFFFFF9B600000 (phys 0x1B600000; generic PS5 rule VA = phys +
 * 0xFFFFFFFF80000000). Like every other entry, values below are raw offsets
 * from that base.
 *
 * Fields left at 0 are still unknown for 13.20 -- see PORTING.md
 * "Remaining gaps".
 */
offset_list off_1320 = {
    /* Loader utils -- VMSPACE_VM_PMAP is stable across 13.xx (Byepervisor
     * hardcodes 0x1D8 for 13.00/13.20/13.60). GVMSPACE not needed here. */
    .IOMMU_SOFTC = 0,
    .VMSPACE_VM_VMID = 0x1E4,
    .VMSPACE_VM_PMAP = 0x1D8,
    .DATA_BASE_GVMSPACE = 0,
    /* Kernel symbols */
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x03909B0,
    .KERNEL_CODE_CAVE = 0x2D29000,
    .FUN_PRINTF = 0x04ABB80,
    /* TODO(13.20): HV IOMMU helpers not yet located */
    .FUN_HV_IOMMU_SET_BUFFERS = 0,
    .FUN_HV_IOMM_WAIT_COMPLETION = 0,
    /* 4-arg wrapper: tail-calls smp_rendezvous_cpus (0xAF92B0) with all_cpus
     * ([0x9F2E9E88]).  Located by disassembling subr_smp.c region around the
     * "smp rendezvous" string (0x9C0F9D80) and following refs to the shared
     * rendezvous globals. */
    .FUN_SMP_RENDEZVOUS = 0xAF94E0,
    /* TODO(13.20): the no-op setup/teardown barrier is still unidentified; the
     * shellcode can substitute its own no-op, so this may stay unused. */
    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0,
    /* The Byepervisor vector runs from startup_mp, not a fixed VMEXIT cave */
    .HV_CODE_CAVE_PA = 0,
    .HV_HANDLE_VMEXIT_PA = 0,
    /* TODO(13.20): UART override not yet located */
    .KERNEL_UART_OVERRIDE = 0,
    /* Out-of-line UBSan CFI failure handler: called on the slow path of every
     * indirect call (e.g. smp_targeted_tlb_shootdown @0x817C50 -> 0x9BA4E5D0,
     * smp_rendezvous_cpus @0xAF92B0 -> 0x9BA4E5D0).  Patching byte 0 to 0xC3
     * disables CFI (upstream behaviour).  References the "cfi_check_fail"
     * format string (0x9C900E52). */
    .KERNEL_CFI_CHECK = 0x44E5D0,
    /* Display bring-up symbols (relative offsets from kernel text base).
     * Recovered from dumps/kernel_text_1320.bin + data_dump_88m.bin:
     *   G_VBIOS        - VBIOS ROM image, verified via the 0x55AA ROM
     *                    signature at ktext+0x3DB39F0 (memcpy'd to 0xC0000).
     *   TRANSMITTER    - generic ATOM exec taking (int cmd, void *params).
     *                    Reached with DIG1TRANSMITTERCONTROL (0x4C) from the
     *                    AMD Display Core transmitter path, which builds a
     *                    struct dig_transmitter_control_parameters_v1_6.
     *   MP3_INVOKE     - mp3 command IPC (int cmd, void *req, void *rsp).
     *                    16 internal wrappers call it with hardcoded cmd ids;
     *                    req/rsp are the 0x1404/0x1408-byte static buffers
     *                    (mp3_req[1281] / mp3_rsp[1282]).
     *   MP3_INITIALIZE - starts by creating "SceMp3MessageThread" and marks
     *                    mp3 ready (the flag MP3_INVOKE gates on). */
    .G_VBIOS = 0x3DB39F0,
    .FUN_TRANSMITTER_CONTROL = 0xC01ED0,
    .FUN_MP3_INITIALIZE = 0xA0B3E0,
    .FUN_MP3_INVOKE = 0xA0A9D0,
    /* TODO(13.20): WiFi firmware blob not yet located */
    .PS5_WIFI_FW_OFFSET = 0,
    .PS5_WIFI_FW_SIZE = 0,
    /* Gadgets (Byepervisor-Reborn 13_20.h) */
    .GAD_ADD_RSP_28_POP_RBP_RET = 0x2520FE,
    .GAD_IRETQ = 0x257AFD,
    .GAD_POP_RAX_RET = 0x291231,
    .GAD_POP_RCX_RET = 0x291842,
    .GAD_POP_RDI_RET = 0x3CBFAD,
    .GAD_POP_RSI_RET = 0x632731,
    .GAD_POP_RDX_RET = 0x2A0D3B,
    .GAD_POP_RSP_RET = 0x291BD2,
    /* Located by signature-scan of dumps/kernel_text_1320.bin: 0f 30 c3 */
    .GAD_WRMSR_RET = 0x254FF4,
    /* Byepervisor high-FW vector */
    .KERNEL_SYM_DMPML4I = 0x3B25294,
    .KERNEL_SYM_DMPDPI = 0x3B25298,
    .KERNEL_SYM_PML4PML4I = 0x3B23E4C,
    .KERNEL_SYM_SYS_GETUID = 0x2A8B20,
    .KERNEL_SYM_HV_MP_STARTUP_CALL = 0xC0A310,
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x26A798,
    .KERNEL_SYM_PMAP_STORE = 0x3B24FF8,
    .KERNEL_SYM_DATA_CAVE = 0x2D29000,
    .HV_SYM_HEAP_BASE = 0x83028,
    .HV_SYM_PCPUS = 0x82A60,
    .HV_LOADER_PA_REGULAR = 0x062800000,
    .HV_LOADER_PA_PRO = 0x8e0800000,
    .GAD_POP_R8 = 0xB822BD,
    .GAD_STORE_RCX_R8 = 0x472B89,
    .GAD_OR_RCX_EAX = 0x803150,
    .GAD_SET_DR7 = 0x9FF846,
    .GAD_ST_RCX_RAX = 0x2BB04F,
    .GAD_STORE_RDI8_RCX = 0x325D8F,
    .GAD_ST_RCX_RDX = 0x824AE5,
    .GAD_MOV_RAX_RSI = 0x8DBD04,
    .GAD_MOV_RAX_RDI = 0xBE027A,
    .GAD_REP_MOVSB = 0x25CFE7,
    .GAD_CLD = 0x304D17,
    .GAD_RET_TRAMP = 0x291232,
    .GAD_DBREG_RESUME = 0x252998,
    .IDT = 0x3B90300,
    .COMMON_TSS = 0x3B92FE0,
};
