#include <unistd.h>
#include <stdio.h>

#define MAGIC_NUMBER 0x0123456789ABCDEFL

typedef struct HEADER_TAG {
    struct HEADER_TAG *ptr_next;
    size_t bloc_size;
    long magic_number;
} HEADER;

HEADER *free_list = NULL;

int FREE_ERROR = 0;

void set_magic_number(HEADER *header, void *ptr) {
    long *post_magic = ptr + header->bloc_size;
    *post_magic = MAGIC_NUMBER;
}

static int verify_magic_numbers(HEADER *header, void *ptr) {
    long *post_magic = ptr + header->bloc_size;
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
    if (mem == (void *)-1) {
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
    if (block->bloc_size > total_size + sizeof(HEADER) + sizeof(long)) {
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
    void *a = malloc_3is(32);
    void *b = malloc_3is(64);
    void *c = malloc_3is(128);

    printf("Allocations faites : a=%p, b=%p, c=%p\n", a, b, c);

    free_3is(b);

    if (free_list)
        printf("Premier bloc libre : %p (taille %zu)\n", (void *)free_list, free_list->bloc_size);
    else
        printf("Aucun bloc libre.\n");

    void *d = malloc_3is(50);
    printf("Nouvelle allocation d = %p\n", d);

    if (d == b)
        printf("Bloc réutilisé avec succès !\n");
    else
        printf("Bloc non réutilisé (nouvelle zone allouée)\n");

    void *x = malloc_3is(40);
    void *y = malloc_3is(80);

    printf("Test: x=%p, y=%p\n", x, y);

    free_3is(x);
    void *z = malloc_3is(32);

    printf("Réallocation z=%p\n", z);

    if (z == x)
        printf("Test réussi: bloc réutilisé\n");
    else
        printf("Test échoué: nouvelle zone allouée\n");

    free_3is(y);
    free_3is(z);

    if (FREE_ERROR > 0) {
        printf("Nombre de FREE_ERROR : %d\n", FREE_ERROR);
    }
    return 0;
}
