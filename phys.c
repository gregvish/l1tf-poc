#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>


#define PAGE_SIZE (0x1000)


uint64_t virt_to_phys(volatile void *virtual_address) {
    int pagemap = 0;
    uint64_t value = 0;
    uint64_t page_frame_number = 0;

    pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0) {
        return 0;
    }

    if (sizeof(uint64_t) != pread(pagemap, &value, sizeof(uint64_t),
                                    (((uint64_t)virtual_address) / PAGE_SIZE) * sizeof(uint64_t))) {
        return 0;
    }

    page_frame_number = value & ((1ULL << 54) - 1);
    if (page_frame_number == 0) {
        return 0;
    }

    return page_frame_number * PAGE_SIZE + (uint64_t)virtual_address % PAGE_SIZE;
}

volatile uint8_t test[] = {
  0xde, 0xad, 0xbe, 0xef, 0x67, 0x04, 0x3e, 0x1c, 0x2a, 0x2e, 0x4e, 0x86, 0x3d, 0x99, 0x3f, 0xac,
  0x1b, 0x8b, 0xce, 0xb6, 0x84, 0xf8, 0x2f, 0xf9, 0x95, 0x97, 0x08, 0x63, 0xc1, 0x1d, 0xf3, 0xee,
  0xab, 0xd7, 0xb3, 0x31, 0x20, 0x36, 0xa6, 0x38, 0xa2, 0x14, 0xb3, 0x2f, 0x8b, 0x0f, 0xc7, 0xfe,
  0x5c, 0xf8, 0x67, 0xb2, 0x74, 0x69, 0xb1, 0x4c, 0x33, 0xae, 0xe8, 0x4d, 0xba, 0xbe, 0xca, 0xfe
};

void dump_memory(volatile uint8_t *ptr, uint32_t size)
{
    uint64_t i = 0;

    for (i = 0; i < size; i += 1) {
        if (i % 0x10 == 0 && i != 0) {
            printf("\n");
        }
        printf("%02x ", ptr[i]);
    }

    printf("\n");
}

int main(void)
{
    printf("Virt %p, Phys: 0x%lx\nData:\n", &test, virt_to_phys(&test));
    dump_memory(test, sizeof(test));

    // Access a byte in test. This will cache 64 bytes (a whole cache line)
    while (test[0]) {}

    return 0;
}
