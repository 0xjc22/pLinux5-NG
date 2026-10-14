# contributing

thanks for wanting to help out. this project is early, so the single most
useful thing right now is getting it booting on more firmware.

currently only **13.20** is supported. every other high firmware (8.xx through
13.60) has the boot path in place but is missing that firmware's kernel and
hypervisor offsets.

## `something went wrong during initialization`

if you get this on boot:

> Something went wrong during initialization.
> Please make sure your fw is supported.

nothing is broken and your console is fine. it just means your firmware hasn't
been added yet.

## adding your firmware

support is per version, and it comes from a table of kernel/hypervisor offsets
(`source/offsets/off_<fw>.c`, generated from the shared list in
`include/offsets/offsets.h`). those offsets have to be pulled out of a real
console running that firmware.

if you can run a payload, you can generate everything needed with the offsets
tool.

### 1. build the offsets tool

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -C tools
```

this produces `tools/pl5-offsets.elf`.

### 2. send it to your console

with elfldr running (the same way you send `pLinux5-NG.elf`):

```bash
PS5_IP=<your.ps5.ip> ./scripts/send.sh tools/pl5-offsets.elf
```

### 3. collect the dump

the tool reads the kernel text/data and the hypervisor, works out every offset
it can for your firmware, and packs it all into one zip. it lands in two places:

- on the console: `/data/pl5-<fw>.zip`
- on a usb stick, if one is plugged in: `pl5.zip` in the root

a usb stick is optional. without one, grab the zip off `/data` over ftp.

### 4. send it in

attach the zip to the pinned firmware-offsets issue, along with:

- your exact firmware version
- whether it's a regular or pro console
- the `report.txt` if you want to paste it inline

that's it. once the dump is in, the offsets can be turned into a table and your
firmware gets added.

## building

### locally

needs the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk), the
[pLabs5-SDK](https://github.com/pLabs5/pLabs5-SDK) and a C compiler:

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -j
```

the output is `bin/pLinux5-NG.elf`.

### docker

```shell
docker buildx bake
```

the output will be at `bin/pLinux5-NG.elf`.

## code layout

- `source/` holds the payload code, grouped by domain: `core/`, `hw/`, `boot/`,
  `byepervisor/`, `hv/`, `manifest/`, `offsets/` and the freestanding
  `shellcode/`. only `main.c` sits at the root.
- `include/` mirrors `source/`.
- `tools/` holds the host-side generators and the on-console offsets tool.

## pull requests

- keep changes scoped to one thing where you can.
- make sure `make` still builds before opening a pr.
- if you're adding a firmware, include the `off_<fw>.c` produced from a real
  console dump.
