BPF_FILE = sys_write_counter

CHECK_MAP = check_map

EBPF_LOADER = ebpf_loader

FLAGS = -O2 -g -target bpf

INCLUDE = -I./include

KERNEL_SRCS =  $(wildcard kernel_space/$(BPF_FILE).c)

CHECK_MAP_SRCS = $(wildcard user_space/check_map/*c)

EBPF_LOADER_SRCS = $(wildcard user_space/ebpf_loader/*.c)

EBPF_BYTE_CODE = $(KERNEL_SRCS:.c=.o)

.c.o:
	clang $(FLAGS) $(INCLUDE) -c $< -o $@

all: $(EBPF_BYTE_CODE)

load: $(EBPF_BYTE_CODE)
	bpftool prog load $(EBPF_BYTE_CODE) /sys/fs/bpf/$(BPF_FILE) autoattach

$(CHECK_MAP): $(CHECK_MAP_SRCS)
	clang  -lbpf $(CHECK_MAP_SRCS) -o $(CHECK_MAP)

comp_check_map: $(CHECK_MAP)

$(EBPF_LOADER): $(EBPF_LOADER_SRCS)
	clang  -lbpf $(CHECK_MAP_SRCS) -o $(EBPF_LOADER)

comp_ebpf_loader: $(EBPF_LOADER)

clean:
	rm -f $(EBPF_BYTE_CODE)
	rm -f $(CHECK_MAP)
	rm -f $(EBPF_LOADER)

fclean:	clean
	rm -f /sys/fs/bpf/$(BPF_FILE)

re: fclean all