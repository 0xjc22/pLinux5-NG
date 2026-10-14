#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#include "hv_defeat_1320.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <signal.h>
#include <unistd.h>

static void diag_sig(int sig, siginfo_t *si, void *ctx) {
  (void)ctx;
  notify("!! signal %d at %p (code %d).\n", sig, si ? si->si_addr : 0,
         si ? si->si_code : 0);
  _exit(128 + sig);
}

int main(void) {
  struct sigaction sa;
  sa.sa_sigaction = diag_sig;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTRAP, &sa, 0);
  sigaction(SIGSEGV, &sa, 0);
  sigaction(SIGBUS, &sa, 0);
  sigaction(SIGILL, &sa, 0);
  sigaction(SIGFPE, &sa, 0);
  if (setup_env()) {
    notify("Something went wrong during initialization.\nPlease make sure "
           "your fw is supported.");
    return -1;
  }

#ifndef PL5_OFFSETS_MODE
  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }
#endif

  int is_1320 = 0;
  void *shellcode_kernel = NULL;
  size_t shellcode_kernel_len = 0;
  if (fw < 0x0800) {
    /* Legacy vectors hand off to shellcode_kernel via the ACPI-wakeup ROP, so
     * it must be staged in the kernel cave before sleeping. */
    if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
      notify("Something went wrong while preparing resume.\n");
      return -1;
    }
  } else {
    /* The 13.20 (Byepervisor khook) vector boots via shellcode_hv staged from
     * post_resume(); it never uses shellcode_kernel, so skip the legacy kernel
     * cave staging + page-table rewrite entirely (fewer arm-time deviations). */
    notify("13.20: skipping legacy shellcode_kernel staging.\n");
  }

  if ((0x0300 <= fw) && (fw < 0x0500)) {
    if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0500 <= fw) && (fw < 0x0650)) {
    if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0650 <= fw) && (fw < 0x0800)) {
    if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0800 <= fw) && (fw < 0x1400)) {
    if (hv_defeat_1320(shellcode_kernel, shellcode_kernel_len))
      goto err;
    is_1320 = 1;
  } else {
    goto err;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  /* On 13.20 the console comes back from rest mode with NPT disabled; finish
   * the takeover from here (runs on the BSP once we wake). */
  if (is_1320)
    hv_defeat_1320_post_resume();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
