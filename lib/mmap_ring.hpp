/*
mmap_ring.h: Linux memory mapped circular buffer with repeated views 

---------
Overview:
---------

Aa circular buffer that appears linear to the CPU by mapping the same physical memory multiple times at consecutive virtual addresses

    [view0 (0...N-1)] [view1 (N...2N-1)]

Having 2 consecutive views in Virtual address space never requires us to have a manual wrap. 
Since any contigious operation of up to N bytes starting anywhere will automatically wrap implicitly, like you can memcpy across "end" boundaries.
The second view is just used as a temporary spill over.
*/

#ifndef MMAP_RING_H
#define MMAP_RING_H
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdint.h>
#include <cstring>
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
    // usable mem in bytes 
    st capacity;
    // rounded up to page size 
    st view_size;
    // number of copies you want to have for your mem allocation in the VAS
    int replicas;
    // total size is just replicas * view_size 
    st total_size;
    // physical memory file descriptor 
    int fd;
    std::atomic<u64> head;
    std::atomic<u64> tail;
} mmap_ring ;

// Utility 

static inline st mr_round_up(st x, st align) {
    // rounds up to the multiple of align 
    return (x + align - 1) & ~(align - 1);
}

static inline st mr_pagesize(void) {
    // gives the page size for your system
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? (st)ps : 4096;
}

static void* mr_reserve_region(st size) {
    void* p = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p;
}

static int mr_backing_fd_create(st size, int* out_fd) {
    // creating backing mem actually means allocating a fixed size storage on the physical RAM
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
    std::cerr << "Failed to create memory backing fd" << std::endl;
    return -1;
}

static int mr_map_replicas(void* base, int fd, st view_size, int replicas) {
    for (int i=0; i < replicas; i++) {
        u8* addr = (u8*)base + (st)i*view_size;
        // create replicas for the virtual address space and map it to the same physical fd 
        void *p = mmap(addr, view_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
        if (p == MAP_FAILED) {
            int e = errno;
            // only unmap the region that was already mapped 
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

static int mmap_ring_create(const mmap_ring_config* cfg, mmap_ring* out) {
    if (!cfg || !out || cfg->capacity==0) {
        return -1;
    }

    st ps = mr_pagesize();
    st view_size = mr_round_up(cfg->capacity, ps);
    int replicas = (cfg->replicas >= 2) ? cfg->replicas : 2;
    st total_size = view_size * (st)replicas;

    memset(out, 0, sizeof(*out));
    out->replicas = replicas;
    out->capacity = view_size;
    out->total_size = total_size;

    int fd = -1;
    int err = mr_backing_fd_create(view_size, &fd);
    if (err != 0) {
        return err;
    }

    //!TODO: should we reserve first and then replicate ? 
    void* base = mr_reserve_region(total_size);
    if (base == MAP_FAILED) {
        int e = errno;
        close(fd);
        return -e;
    }

    err = mr_map_replicas(base, fd, view_size, replicas);
    if (err != 0) {
        munmap(base, total_size);
        close(fd);
        return err;
    }

    out->base = (u8*)base;
    out->fd = fd;
    out->head.store(0);
    out->tail.store(0);
    std::cout << "MMAP Ring Creation SUCCESS !" << std::endl;
    return 0;
}

static void mmap_ring_destroy(mmap_ring* r) {
    if (!r || !r->base) {
        return;
    }
    munmap(r->base, r->total_size);
    if (r->fd >= 0) {
        close(r->fd);
    }
    memset(r, 0, sizeof(*r));
}

static inline st mmap_ring_readable(const mmap_ring* r) {
    u64 h = r->head.load();
    u64 t = r->tail.load();
    return (st)(h - t);
}

static inline st mmap_ring_writeable(const mmap_ring* r) {
    return r->capacity - mmap_ring_readable(r);
}

// Contiguous region to write up to max bytes
static inline u8* mmap_ring_write_acquire(mmap_ring* r, st max_bytes, st* out_granted) {
    st avail = mmap_ring_writeable(r);
    st grant = (max_bytes <= avail) ? max_bytes : avail;

    if (grant == 0) {
        if (out_granted) {
            *out_granted = 0;
            return NULL;
        }
    }
    u64 h = r->head.load();
    // head pointer increases monotically so wrapping is needed here
    st off = (st)(h % r->capacity);
    if (out_granted) {
        *out_granted = grant;
    }
    return r->base + off;
}

// commit only the required memory
static inline void mmap_ring_write_commit(mmap_ring* r, st count) {
    u64 h = r->head.load();
    r->head.store(h+count);
}

static inline u8* mmap_ring_write_acquire_overwrite(mmap_ring* r, st max_bytes, st* out_grant) {
    st readable = mmap_ring_readable(r);
    if (max_bytes > r->capacity) {
        max_bytes = r->capacity;
    }

    st needed = max_bytes;
    st writeable = r->capacity - readable;
    if (needed > writeable) {
        st drop = needed - writeable;
        u64 t = r->tail.load();
        r->tail.store(t+drop);
    }
    return mmap_ring_write_acquire(r, max_bytes, out_grant);
}

static inline const u8* mmap_ring_read_acquire(mmap_ring* r, st max_bytes, st* out_grant) {
    st avail = mmap_ring_readable(r);
    st grant = (max_bytes <= avail) ? max_bytes : avail;
    if (grant == 0) {
        if (out_grant) {
            *out_grant = 0;
            return NULL;
        }
    }

    u64 t = r->tail.load();
    // tail ptr increases monotonically so we have to wrap back
    st off = (st)(t % r->capacity);
    if (out_grant) {
        *out_grant = grant;
    }
    return r->base + off;
}

static inline void mmap_ring_read_commit(mmap_ring* r, st count) {
    u64 t = r->tail.load();
    r->tail.store(t+count);
} 

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