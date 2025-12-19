# Makefile for building tc_flow_log.bpf.o

CLANG ?= clang

BPF_C   := tc_flow_log.bpf.c
BPF_OBJ := tc_flow_log.bpf.o

CFLAGS_BPF := -O2 -g -target bpf -D__TARGET_ARCH_x86

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_C)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

clean:
	rm -f $(BPF_OBJ)

.PHONY: all clean
