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
    long *post_magic = (long *) ((char *) ptr + header->bloc_size);
    *post_magic = MAGIC_NUMBER;
}

static int verify_magic_numbers(HEADER *header, void *ptr) {
    long *post_magic = (long *) ((char *) ptr + header->bloc_size);
    if (header->magic_number != MAGIC_NUMBER || *post_magic != MAGIC_NUMBER) {
        return 0;
    }
    return 1;
}

static void insert_block_sorted(HEADER *header) {
    if (free_list == NULL || header < free_list) {
        header->ptr_next = free_list;
        free_list = header;
        return;
    }

    HEADER *current = free_list;
    while (current->ptr_next && current->ptr_next < header) {
        current = current->ptr_next;
    }
    header->ptr_next = current->ptr_next;
    current->ptr_next = header;
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

void free_3is(void *ptr) {
    if (!ptr) {
        return;
    }

    HEADER *header = (HEADER *) ((char *) ptr - sizeof(HEADER));

    if (!verify_magic_numbers(header, ptr)) {
        return;
    }

    insert_block_sorted(header);
}

int main() {
    void *a = malloc_3is(32);
    void *b = malloc_3is(64);
    void *c = malloc_3is(128);

    printf("Allocations faites : a=%p, b=%p, c=%p\n", a, b, c);

    free_3is(b);

    if (free_list)
        printf("Premier bloc libre : %p (taille %zu)\n", (void *)free_list, free_list->bloc_size);
    else
        printf("Aucun bloc libre.\n");

    return 0;
}
