.PHONY: all clean version offsets

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/pLinux5-NG.elf
SRC := $(wildcard source/*.c source/byepervisor/*.c source/core/*.c source/hw/*.c source/boot/*.c source/manifest/*.c source/offsets/*.c source/hv/defeat/*.c)
OBJS := $(SRC:.c=.o)

# Project identity lives in source/manifest/manifest.c (see include/manifest.h).
# Its .version is the single source of truth - CI reads the same field to name
# releases, so the ELF and the release cannot disagree.
MANIFEST_C := source/manifest/manifest.c
manifest-field = $(shell sed -n 's/^[[:space:]]*\.$(2)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' $(1))
PL5_VERSION := $(call manifest-field,$(MANIFEST_C),version)
ifeq ($(strip $(PL5_VERSION)),)
$(error could not read .version from $(MANIFEST_C))
endif

# Diagnostic bisection stage (see source/hv/defeat/hv_defeat_1320.c). Override on the
# command line, e.g. `make PL5_DIAG=1`. Remember to clear the objects first
# (the flag does not retrigger a rebuild on its own): `make -C . clean-objs`.
PL5_DIAG ?= 4
# Takeover-blob step selector (see source/shellcode/hv_takeover/takeover.S).
PL5_TAKEOVER_STAGE ?= 3
# Pre-rest-mode resume_rip probe (source/hv/defeat/hv_defeat_1320.c). Off by default so
# PL5_DIAG=4 runs the real post-resume flow; set to 1 for the probe build.
PL5_PROBE ?= 0
# shellcode_hv checkpoint bisection (source/shellcode/hv/boot_linux.c): freeze at a
# checkpoint instead of booting. 0=full boot, 1=entry, 2=post-configure_vram,
# 3=post-barrier.
PL5_HV_STOP ?= 0

CFLAGS  := -std=c23 -Wall -DPL5_DIAG=$(PL5_DIAG) -DPL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) -DPL5_PROBE=$(PL5_PROBE) -Iinclude -Iinclude/core -Iinclude/hw -Iinclude/boot -Iinclude/byepervisor -Iinclude/hv/defeat -Iinclude/manifest -Iinclude/offsets -Isource/shellcode/hv -Isource/shellcode/kernel -Isource/shellcode/break_hv -Isource/shellcode/hv_boot -Isource/shellcode/hv_takeover
# pLabs5 toolchain override (see PORTING.md). Pass LLVM_CONFIG in the environment:
#   export LLVM_CONFIG=/nyaa/coding/public/PS5/dRPC5/pLabs5-SDK/tools/nixos/llvm-config
LDFLAGS :=

SC_0607_H := source/shellcode/0607/shellcode_0607.h
SC_HV_H := source/shellcode/hv/shellcode_hv.h
SC_K_H  := source/shellcode/kernel/shellcode_kernel.h
SC_BREAK_H := source/shellcode/break_hv/break_hv.h
SC_BOOT_H := source/shellcode/hv_boot/hv_boot.h
SC_TAKEOVER_H := source/shellcode/hv_takeover/takeover.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(BIN)

# Print the manifest version (read from source/manifest/manifest.c).
version:
	@printf '%s\n' '$(PL5_VERSION)'

# Offsets-dump payload (tools/pl5-offsets.c): the normal 13.20 vector runs and,
# on resume (HV defeated, .text readable), dumps all offsets to /data/pl5-<fw>.zip
# instead of taking over / booting Linux. Same entrypoint, just -DPL5_OFFSETS_MODE.
offsets: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H)
	$(CC) $(CFLAGS) -DPL5_OFFSETS_MODE $(SRC) tools/pl5-offsets.c $(LDFLAGS) \
		-o bin/pLinux5-NG-offsets.elf
	@echo "built bin/pLinux5-NG-offsets.elf"

$(SC_0607_H):
	$(MAKE) -C source/shellcode/0607

$(SC_HV_H):
	$(MAKE) -C source/shellcode/hv PL5_HV_STOP=$(PL5_HV_STOP)

$(SC_K_H): $(SC_HV_H)
	$(MAKE) -C source/shellcode/kernel

$(SC_BREAK_H):
	$(MAKE) -C source/shellcode/break_hv

$(SC_BOOT_H):
	$(MAKE) -C source/shellcode/hv_boot

$(SC_TAKEOVER_H):
	$(MAKE) -C source/shellcode/hv_takeover

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# The userland objects include the generated shellcode headers; make the
# dependency explicit so `make -j` cannot compile them before the blobs exist.
$(OBJS): $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean-objs:
	rm -f $(OBJS)

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C source/shellcode/0607 clean
	$(MAKE) -C source/shellcode/hv clean
	$(MAKE) -C source/shellcode/kernel clean
	$(MAKE) -C source/shellcode/break_hv clean
	$(MAKE) -C source/shellcode/hv_boot clean
	$(MAKE) -C source/shellcode/hv_takeover clean
