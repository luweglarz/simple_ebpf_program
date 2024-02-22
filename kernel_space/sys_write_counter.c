#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
     __uint(type, BPF_MAP_TYPE_HASH);
	 __type(key, sizeof(__u64));
	 __type(value, sizeof(__u64));
     __uint(max_entries, 10000);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_counter SEC(".maps");


SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	__u64 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *counter;

	counter = bpf_map_lookup_elem(&syscall_counter, &pid);
	
	if (counter) {
		(*counter)++;
		bpf_printk("Write syscall triggered from PID %d. counter:%llu\n", pid, *counter);
		bpf_map_update_elem(&syscall_counter, &pid, counter, BPF_ANY);
	}
	 else {
		__u64 init_val = 1;
        bpf_map_update_elem(&syscall_counter, &pid, &init_val, BPF_NOEXIST);
    }
	
	return 0;
}
