# Builds the AES-NI integral program into the analysis build directory.
# The constants header is generated from build/consts.json by analysis/run.py.
BUILD ?= ../build
CFLAGS ?= -O3 -march=native

$(BUILD)/integral: integral.c $(BUILD)/consts.h
	$(CC) $(CFLAGS) -pthread -I$(BUILD) -o $@.tmp integral.c && mv $@.tmp $@

.PHONY: clean
clean:
	rm -f $(BUILD)/integral
