#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define MAGIC_NUMBER 0x0123456789ABCDEFL
int memory_error_count;
typedef struct HEADER_TAG {
    struct HEADER_TAG *ptr_next;
    size_t bloc_size;
    long magic_number;
} HEADER;


static HEADER *free_list = NULL;

void* malloc_3is(size_t size) {
    HEADER *prev = NULL;
    HEADER *current = free_list;

    while (current) {
        if (current->bloc_size >= size) {
            if (prev)
                prev->ptr_next = current->ptr_next;
            else
                free_list = current->ptr_next;

            current->ptr_next = NULL;
            current->magic_number = MAGIC_NUMBER;

            long *start_guard = (long*)((char*)current + sizeof(HEADER));
            *start_guard = MAGIC_NUMBER;

            long *end_guard = (long*)((char*)start_guard + sizeof(long) + size);
            *end_guard = MAGIC_NUMBER;

            return (void*)((char*)current + sizeof(HEADER) + sizeof(long));
        }

        prev = current;
        current = current->ptr_next;
    }

    //   Use `sbrk()` to expand the heap
    void *new_block = sbrk(sizeof(HEADER) + sizeof(long)*2 + size);
    if (new_block == (void*)-1) {
        perror("sbrk failed");
        return NULL;
    }

    HEADER *h = (HEADER*)new_block;
    h->ptr_next = NULL;
    h->bloc_size = size;
    h->magic_number = MAGIC_NUMBER;

    long *start_guard = (long*)((char*)h + sizeof(HEADER));
    *start_guard = MAGIC_NUMBER;

    long *end_guard = (long*)((char*)start_guard + sizeof(long) + size);
    *end_guard = MAGIC_NUMBER;

    return (void*)((char*)h + sizeof(HEADER) + sizeof(long));
}

void free_3is(void *ptr) {
    if (ptr == NULL) {
        memory_error_count++;
        return;
    }

    HEADER *h = (HEADER*)((char*)ptr - sizeof(HEADER) - sizeof(long));

    long *start_guard = (long*)((char*)h + sizeof(HEADER));
    long *end_guard = (long*)((char*)start_guard + sizeof(long) + h->bloc_size);
    //memory corruption
    if (*start_guard != MAGIC_NUMBER || *end_guard != MAGIC_NUMBER) {
        memory_error_count++;
        return;
    }

    //Insert the freed block into the free list, keeping the list sorted by memory address

    if (!free_list || h < free_list) {
        h->ptr_next = free_list;
        free_list = h;
    } else {
        HEADER *current = free_list;
        while (current->ptr_next && current->ptr_next < h)
            current = current->ptr_next;

        h->ptr_next = current->ptr_next;
        current->ptr_next = h;
    }

    // merge adjacent free memory
    HEADER *current = free_list;
    while (current && current->ptr_next) {
        char *end_current = (char*)current + sizeof(HEADER) + sizeof(long) + current->bloc_size + sizeof(long);
        if (end_current == (char*)current->ptr_next) {
            current->bloc_size += sizeof(HEADER) + sizeof(long)*2 + current->ptr_next->bloc_size;
            current->ptr_next = current->ptr_next->ptr_next;
        } else {
            current = current->ptr_next;
        }
    }
}



int main() {
    printf("***Secure Memory Allocator ***Full Test \n\n");

    printf("-- **Test 1** Basic allocations --\n");
    char *a = malloc_3is(20);
    strcpy(a, "Block A");
    char *b = malloc_3is(40);
    strcpy(b, "Block B with more data");
    char *c = malloc_3is(60);
    strcpy(c, "Block C is the biggest one");
    printf("a: %s\nb: %s\nc: %s\n", a, b, c);

    printf("\n-- ** Test 2 ** Freeing and merging adjacent blocks --\n");
    free_3is(b);
    free_3is(a);
    free_3is(c);

    printf("\n-- ** Test 3** Reusing and splitting freed blocks --\n");
    char *d = malloc_3is(10);
    strcpy(d, "Reuse");
    char *e = malloc_3is(30);
    strcpy(e, "Another block reuse");
    printf("d: %s\ne: %s\n", d, e);

    printf("\n-- ** Test 4**  Buffer overflow detection --\n");
    char *f = malloc_3is(10);
    strcpy(f, "This string is too long!");
    free_3is(f);

    printf("\n-- **Test 5 ** Freeing a NULL pointer --\n");
    free_3is(NULL);

    printf("\n-- ** Test 6 ** Multiple allocations and frees for recycling --\n");
    char *g = malloc_3is(25);
    strcpy(g, "Recycling test");
    free_3is(g);
    char *h = malloc_3is(20);
    strcpy(h, "Smaller reuse");
    printf("h: %s\n", h);
    free_3is(h);


    printf("\n** Test Summary **s\n");
    printf("Total memory errors detected: %d\n", memory_error_count);
    printf("GREAT.\n");

    return 0;
}
