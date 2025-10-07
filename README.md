# TP2 – Secure Memory Allocator Project
**3rd year IS – Systems and Networks**  
By HADJ SASSI MAHDI & CHAHRAZED BAATOUT
Instructor: C. Barès

## Course Notes (Key Points We Need to Know)

1. **Virtual Memory**
    - Each process has its own private address space: code, data, heap, stack, and kernel.
    - Processes are isolated from each other for safety.

2. **Heap Memory**
    - The heap is used for dynamic allocations (`malloc`, `calloc`, `free`).
    - It grows and shrinks during program execution.

3. **System Calls: `sbrk()` and `brk()`**
    - Used to expand or reduce the heap space.
    - These are the low-level functions your custom allocator will use.

4. **Memory Block Structure**
    - Each allocated block has a **header** containing metadata (pointer to next, size, magic number).
    - Example: `| HEADER | magic_number | user_data | magic_number |`

5. **Free List Management**
    - Keep a linked list of free blocks (sorted by address).
    - When freeing memory, add the block back to this list.

6. **Merging and Splitting Blocks**
    - Merge adjacent free blocks to reduce fragmentation.
    - Split larger blocks to satisfy smaller allocation requests.

7. **Magic Numbers**
    - Use a unique constant (e.g., `0x0123456789ABCDEFL`) before and after user data.
    - If changed, it indicates a **buffer overflow** or memory corruption.

## Project Objective
The goal of this project is to implement a **secure memory allocator** that replaces the `malloc` and `free` functions.  
This intelligent allocator will allow detection of memory corruptions such as **buffer overflows** and **improper deallocations**.
## Implementation Steps (Checkpoints)
## 1. Data Structure Setup
-  **Define the `HEADER` structure**
-  **Create the global free list**

---
## 2. Helper Functions
-  **Implement `align8(size_t size)`**
    - Align requested size to the next multiple of 8 bytes

- **Implement `get_header(void *ptr)`**
    - Convert a user pointer to its corresponding `HEADER` pointer

- **Implement `get_user_ptr(HEADER *h)`**
    - Convert a `HEADER` pointer back to the user memory pointer

##  3. Free List Management

- **Implement `insert_free_block(HEADER *block)`**
    - Insert a freed block into the free list in sorted order (by address)
    - Update `ptr_next` links correctly

- **Implement `merge_blocks()`**
    - Merge adjacent free blocks to reduce fragmentation

---

##  4. Allocation Logic – `malloc_3is(size_t size)`

- **Align requested size** using `align8()`
- **Search the free list** for a block large enough
- **If found:**
    - Remove it from the free list
    - Mark its magic numbers before and after the user area
- **If not found:**
    - Use `sbrk()` to expand the heap
    - Initialize the new block (`HEADER`, guards)
- **Return** a pointer to the usable memory region

---

## 5. Free Logic – `free_3is(void *ptr)`

- **Check for NULL pointer**
- **Retrieve the HEADER** using `get_header()`
- **Verify magic numbers**
    - If changed, print a corruption error message
- **Insert the block** back into the free list using `insert_free_block()`
- **Call `merge_blocks()`** to merge adjacent free memory

---