#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

int main(int ac, char **av) {
 	int  map_fd = map_fd = bpf_obj_get("/sys/fs/bpf/syscall_counter");
    __u64 key_input, value;

    if (ac != 2)
        return 1;

    key_input = (__u64)atoi(av[1]);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(map_fd, &key_input, &value) == 0) {
        printf("Value at key %llu: %llu\n", key_input, value);
    } else {
        fprintf(stderr, "Failed to lookup key %llu in map: %s\n", key_input, strerror(errno));
    }

    close(map_fd);


}