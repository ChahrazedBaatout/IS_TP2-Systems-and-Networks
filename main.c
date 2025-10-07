#include <unistd.h>
#include <stdio.h>

#define MAGIC_NUMBER 0x0123456789ABCDEFL

typedef struct HEADER_TAG {
    struct HEADER_TAG *ptr_next;
    size_t bloc_size;
    long magic_number;
} HEADER;

HEADER *free_list = NULL;

void set_magic_number(HEADER *header, void *ptr) {
    long *post_magic = (long *)((char *)ptr + header->bloc_size);
    *post_magic = MAGIC_NUMBER;
}

void *malloc_3is(size_t size) {
    size_t total_size = sizeof(HEADER) + size + sizeof(long);


    void *mem = sbrk(total_size);
    if (mem == (void *) -1) {
        return NULL;
    }
    HEADER *header = (HEADER *) mem;
    header->bloc_size = size;
    header->magic_number = MAGIC_NUMBER;
    header->ptr_next = NULL;
    void *user_ptr = (char *) header + sizeof(HEADER);
    set_magic_number(header, user_ptr);
    return user_ptr;
}


int main() {
    void *a = malloc_3is(32);
    void *b = malloc_3is(64);
    void *c = malloc_3is(128);

    printf("Allocations faites : a=%p, b=%p, c=%p\n", a, b, c);

    return 0;
}