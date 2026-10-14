.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := pl5-offsets.elf
SIGTABLE ?= sigtable_1320.h

CFLAGS += -DPL5_SIGTABLE_HEADER='"$(SIGTABLE)"'

all: $(BIN)

$(BIN): pl5-offsets.c $(SIGTABLE)
	$(CC) $(CFLAGS) pl5-offsets.c $(LDFLAGS) -o $@

clean:
	rm -f $(BIN)
