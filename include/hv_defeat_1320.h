#ifndef HV_DEFEAT_1320_H
#define HV_DEFEAT_1320_H

#include <stddef.h>

/*
 * High-firmware (8.xx+) hypervisor defeat, based on the Byepervisor khook
 * escape. See source/hv_defeat_1320.c for the design and PORTING.md for the
 * list of outstanding work.
 */
int hv_defeat_1320(void *shellcode_kernel, size_t shellcode_kernel_len);

#endif
