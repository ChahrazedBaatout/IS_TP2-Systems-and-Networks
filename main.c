#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define MAGIC_NUMBER 0x0123456789ABCDEFL
#define INITIAL_VALUE 0
#define RETURN_OK 1
#define RETURN_KO 0

typedef struct HEADER_TAG {
    struct HEADER_TAG *ptr_next;
    size_t bloc_size;
    long magic_number;
} HEADER;

HEADER *free_list = NULL;

int FREE_ERROR = INITIAL_VALUE;

void set_magic_number(HEADER *header, void *ptr) {
    long *post_magic = ptr + header->bloc_size;
    *post_magic = MAGIC_NUMBER;
}

static int verify_magic_numbers(HEADER *header, void *ptr) {
    long *post_magic = ptr + header->bloc_size;
    if (header->magic_number != MAGIC_NUMBER || *post_magic != MAGIC_NUMBER) {
        return RETURN_KO;
    }
    return RETURN_OK;
}

static void merge_free_blocks() {
    HEADER *current = free_list;
    while (current && current->ptr_next) {
        void *end_current = (void *) current + sizeof(HEADER) + current->bloc_size + sizeof(long);
        if (end_current == (void *) current->ptr_next) {
            current->bloc_size += sizeof(HEADER) + current->ptr_next->bloc_size + sizeof(long);
            current->ptr_next = current->ptr_next->ptr_next;
        } else {
            current = current->ptr_next;
        }
    }
}

static void insert_block_sorted(HEADER *header) {
    if (free_list == NULL || header < free_list) {
        header->ptr_next = free_list;
        free_list = header;
    } else {
        HEADER *current = free_list;
        while (current->ptr_next && current->ptr_next < header) {
            current = current->ptr_next;
        }
        header->ptr_next = current->ptr_next;
        current->ptr_next = header;
    }
    merge_free_blocks();
}

static HEADER *find_suitable_block(size_t size, HEADER **prev_out) {
    HEADER *prev = NULL;
    HEADER *current = free_list;
    while (current) {
        if (current->bloc_size >= size) {
            if (prev_out) {
                *prev_out = prev;
            }
            return current;
        }
        prev = current;
        current = current->ptr_next;
    }
    if (prev_out) {
        *prev_out = NULL;
    }
    return NULL;
}

static HEADER *allocate_new_block(size_t size) {
    size_t total_size = sizeof(HEADER) + size + sizeof(long);
    void *mem = sbrk(total_size);
    if (mem == (void *) -1) {
        return NULL;
    }
    HEADER *header = mem;
    header->bloc_size = size;
    header->magic_number = MAGIC_NUMBER;
    header->ptr_next = NULL;
    return header;
}

static void *prepare_block_for_use(HEADER *block, size_t size) {
    block->magic_number = MAGIC_NUMBER;
    block->bloc_size = size;
    block->ptr_next = NULL;

    void *user_ptr = (void *) block + sizeof(HEADER);
    set_magic_number(block, user_ptr);
    return user_ptr;
}

static HEADER *split_block(HEADER *block, size_t size) {
    size_t total_size = sizeof(HEADER) + size + sizeof(long);
    if (block->bloc_size > size + sizeof(HEADER) + sizeof(long)) {
        HEADER *new_block = (void *) block + total_size;
        new_block->bloc_size = block->bloc_size - total_size;
        new_block->magic_number = MAGIC_NUMBER;
        new_block->ptr_next = NULL;
        block->bloc_size = size;
        return new_block;
    }
    return NULL;
}

void *malloc_3is(size_t size) {
    HEADER *prev = NULL;
    HEADER *block = find_suitable_block(size, &prev);
    if (block) {
        if (prev) {
            prev->ptr_next = block->ptr_next;
        } else {
            free_list = block->ptr_next;
        }
        HEADER *remaining = split_block(block, size);
        if (remaining) {
            insert_block_sorted(remaining);
        }
        return prepare_block_for_use(block, size);
    }
    block = allocate_new_block(size);
    if (!block) {
        return NULL;
    }
    return prepare_block_for_use(block, size);
}

void free_3is(void *ptr) {
    if (!ptr) {
        FREE_ERROR += 1;
    }

    HEADER *header = ptr - sizeof(HEADER);

    if (verify_magic_numbers(header, ptr)) {
        insert_block_sorted(header);
    } else {
        FREE_ERROR += 1;
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
    printf("Total memory errors detected: %d\n", FREE_ERROR);
    printf("GREAT.\n");

    return 0;
}