#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>

// int main(int ac, char **av) {
// 	const char *filePath = "kernel_space/sys_write_counter.o";
// 	struct bpf_object *bpfObject;
//     __u64 key_input, value;

//     if (ac != 2)
//         return 1;

//     key_input = (__u64)atoi(av[1]);
// 	bpfObject = bpf_object__open_file("sys/fs/bpf/sys_write_counter", NULL);
// 	if (bpfObject == NULL){
// 		printf("Error! Failed to load %s\n", filePath);
// 		return 1;
// 	}
// 	int map_fd = bpf_object__find_map_fd_by_name(bpfObject, "syscall_counter");
//     if (map_fd < 0) {
//         fprintf(stderr, "Failed to find the map in the eBPF object\n");
//         return 1;
//     }
    
// 	if (bpf_map_lookup_elem(map_fd, &key_input, &value) < 0) {
//         printf("No value found for key %llu\n", key_input);
//     } else {
//         printf("Value found for key %llu: %llu\n", key_input, (unsigned long long)value);
//     }
// 	return 0;
// }

int main(int ac, char **av) {
 	int  map_fd = map_fd = bpf_obj_get("/sys/fs/bpf/sys_write_counter");
     __u64 key_input, value;
     struct bpf_map_info map_info = {};
    unsigned int size;

    if (ac != 2)
        return 1;

    key_input = (__u64)atoi(av[1]);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return 1;
    }
    __u32 length = sizeof(map_info);

    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &length) < 0) {
        fprintf(stderr, "Failed to get map info: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }

    size = map_info.btf_id;
    printf("Size of the map: %u\n", size);

    if (bpf_map_lookup_elem(map_fd, &key_input, &value) == 0) {
        printf("Value at key %llu: %llu\n", key_input, value);
    } else {
        fprintf(stderr, "Failed to lookup key %llu in map: %s\n", key_input, strerror(errno));
    }

    close(map_fd);


}