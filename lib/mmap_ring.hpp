/*
mmap_ring.h: Linux memory mapped circular buffer with repeated views 

---------
Overview:
---------

Aa circular buffer tha appears linear to the CPU by mapping the same physical memory multiple times at consecutive virtual addresses

    [view0 (0...N-1)] [view1 (N...2N-1)]

Having 2 consecutive views in Virtual address space never requires us to have a manual wrap. 
Since any contigious operation of up to N bytes starting anywhere will automatically wrap implicitly, like you can memcpy across "end" boundaries.
The second view is just used as a temporary spill over.
*/

#ifndef MMAP_RING_H
#define MMAP_RING_H
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <atomic>
#include <iostream>

typedef uint8_t u8;
typedef uint64_t u64;
typedef size_t st;

typedef struct mmap_ring {
    // Mapped address of the first view 
    u8* base;
    st capacity;
    st view_size;
    int replicas;
    st total_size;
    int fd;
    std::atomic<u64> head;
    std::atomic<u64> tail;
} mmap_ring ;

// Utility 

static inline st mr_round_up(st x, st align) {
    return (x + align - 1) & ~(align - 1);
}

static inline st mr_pagesize(void) {
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? (st)ps : 4096;
}

static void* mr_reserve_region(st size) {
    void* p = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p;
}

static int mr_backing_fd_create(st size, int* out_fd) {
    int fd = memfd_create("mmap_ring", MFD_CLOEXEC);
    if (fd >= 0) {
        if (ftruncate(fd, (off_t)size) != 0) {
            int e = errno;
            close(fd);
            return -e;
        }
        *out_fd = fd;
        return 0;
    }
    std::cout << "Failed to create memory backing fd" << std::endl;
    return -1;
}

static int mr_map_replicas(void* base, int fd, st view_size, int replicas) {
    for (int i=0; i < replicas; i++) {
        u8* addr = (u8*)base + (st)i*view_size;
        void *p = mmap(addr, view_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
        if (p == MAP_FAILED) {
            int e = errno;
            for (int j=0; j < i; ++j) {
                munmap((u8*)base + (st)j*view_size, view_size);
            }
            return -e;
        }
    }
    return 0;
}

// Core API
typedef struct mmap_ring_config {
    st capacity;
    int replicas;
} mmap_ring_config;


#ifdef MMAP_RING_DEMO
#include <time.h>
#include <iostream>
#include <string> 

int main(void) {
    mmap_ring r;
    mmap_ring_config cfg = {
        .capacity = 64 * 1024, // 64 KB will be rounded up to the page size
        .replicas = 2
    };

    int err = mmap_ring_create(&cfg, &r);
    if (err != 0) {
        std::cerr << "mmap_ring_create failed: " << err << strerror(-err) << std::endl;
    }

    cont std::string msg = "Hello ring buffer across boundary!";
    size_t msg_len = msg.length();

    size_t near_end = r.capacity - 8;
    size_t pad = mmap_ring_write_overwrite(&r, (const uint8_t*)"x",near_end);
    void(pad);

    size_t w = mmap_ring_write(&r, msg, msg_len);
    std::cout << "Wrote " << w << " bytes" << std::endl;

    char outbuf[128] = {0};
    size_t rbytes = mmap_ring_read(&r, outbuf, msg_len);
    std::cout << "Read " << rbytes << " bytes" << std::endl;

    mmap_ring_destroy(&r);
    return 0;
}
#endif 

#endif // MMAP_RING_H