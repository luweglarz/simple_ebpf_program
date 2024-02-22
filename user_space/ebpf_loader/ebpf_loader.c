#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

int main() {
	const char *filePath = "kernel_space/sys_write_counter.o";
	struct bpf_object *bpfObject;
	struct bpf_program *prog;
	int err;
	uint64_t key, next_key;
    uint64_t value;

	bpfObject = bpf_object__open_file(filePath, NULL);
	
	if (!bpfObject){
		printf("Error! Failed to load %s\n", filePath);
		return 1;
	}
	err = bpf_object__load(bpfObject);
	if (err){
		printf("Failed to load %s\n", filePath);
		return 1;
	}
	prog = bpf_object__find_program_by_name(bpfObject, "handle_tp");
	if (!prog){
		printf("Failed to find eBPF program\n");
		return 1;
	}
	bpf_program__attach(prog);
	struct bpf_map *map = bpf_object__find_map_by_name(bpfObject, "syscall_counter");
    if (!map) {
        fprintf(stderr, "Failed to find the map in the eBPF object\n");
        bpf_object__close(bpfObject);
        return 1;
    }
	int map_fd = bpf_object__find_map_fd_by_name(bpfObject, "syscall_counter");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find the map in the eBPF object\n");
        return 1;
    }
	while (1){
		__u64 key_input = 0;
		
		printf("Enter PID:");
		scanf("%llu\n",&key_input);
		if (bpf_map_lookup_elem(map_fd, &key_input, &value) < 0) {
			printf("No value found for key %llu\n", key_input);
		} else {
			printf("Value found for key %llu: %llu\n", key_input, (unsigned long long)value);
		}
	}
    bpf_object__close(bpfObject);
	return 0;
}