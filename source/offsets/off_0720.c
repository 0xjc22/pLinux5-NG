#include "offsets.h"

#define KERNEL_TEXT 0xFFFFFFFF80210000

offset_list off_0720 = {
    // .IOMMU_SOFTC not needed
    // .VMSPACE_VM_VMID not needed
    .VMSPACE_VM_PMAP = 0x1D8,
    // .DATA_BASE_GVMSPACE not needed
    .ACPIGBL_FACS = (0xffffffff83ac9c50 - KERNEL_TEXT),
    .IDT = (0xffffffff83cdfdf0 - KERNEL_TEXT),
    .COMMON_TSS = (0xffffffff83ce2ad0 - KERNEL_TEXT),
    // .STOPPED_CPUS not needed
    // .FUN_STOP_CPUS not needed
    // .FUN_AS_LAPIC_EOI not needed
    // .FUN_HV_UNMAP_PT_TMR not needed
    .FUN_MEMCPY = (0xffffffff80493600 - KERNEL_TEXT),
    .GAD_ADD_RSP_28_POP_RBP_RET = (0xffffffff80c435ff - KERNEL_TEXT),
    .GAD_IRETQ = (0xffffffff809c52e8 - KERNEL_TEXT),
    .GAD_POP_RAX_RET = (0xffffffff80e4c2d5 - KERNEL_TEXT),
    .GAD_POP_RDI_RET = (0xffffffff80dfe38b - KERNEL_TEXT),
    .GAD_POP_RSI_RET = (0xffffffff80dfdd9e - KERNEL_TEXT),
    .GAD_POP_RDX_RET = (0xffffffff80a4fd38 - KERNEL_TEXT),
    .GAD_POP_RCX_RET = (0xffffffff80e24def - KERNEL_TEXT),
    .GAD_POP_RSP_RET = (0xffffffff80e2b4c0 - KERNEL_TEXT),
    .GAD_WRMSR_RET = (0xffffffff80451d04 - KERNEL_TEXT),
    // .GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET not needed
    // .HOOK_ACPI_WAKEUP_MACHDEP not needed
    .KERNEL_CODE_CAVE = 0x500,
    .FUN_PRINTF = (0xffffffff806cc830 - KERNEL_TEXT),
    // .FUN_HV_IOMMU_SET_BUFFERS not needed
    // .FUN_HV_IOMM_WAIT_COMPLETION not needed
    .FUN_SMP_RENDEZVOUS = (0xffffffff80cb6100 - KERNEL_TEXT),
    .FUN_SMP_NO_RENDEVOUS_BARRIER = (0xffffffff804c0820 - KERNEL_TEXT),
    .HV_CODE_CAVE_PA = 0x62806F00,
    .HV_HANDLE_VMEXIT_PA = 0x6283D800,
    .KERNEL_UART_OVERRIDE = (0xffffffff822c33f8 - KERNEL_TEXT),
    .KERNEL_CFI_CHECK = (0xffffffff806857a0 - KERNEL_TEXT),
    .G_VBIOS = (0xffffffff83ef7a40 - KERNEL_TEXT),
    .FUN_TRANSMITTER_CONTROL = (0xffffffff80dafcc0 - KERNEL_TEXT),
    .FUN_MP3_INITIALIZE = (0xffffffff80bcba10 - KERNEL_TEXT),
    .FUN_MP3_INVOKE = (0xffffffff80bca7d0 - KERNEL_TEXT),
    .PS5_WIFI_FW_OFFSET = (0xffffffff81655700 - KERNEL_TEXT),
    .PS5_WIFI_FW_SIZE = 497636,
};
