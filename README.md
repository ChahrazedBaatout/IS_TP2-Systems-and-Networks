# TP2 – Secure Memory Allocator Project
**3rd year IS – Systems and Networks**  
By HADJ SASSI MAHDI & CHAHRAZED BAATOUT
Instructor: C. Barès

## Project Objective
The goal of this project is to implement a **secure memory allocator** that replaces the `malloc` and `free` functions.  
This intelligent allocator will allow detection of memory corruptions such as **buffer overflows** and **improper deallocations**.
## Implementation Steps (Checkpoints)
## 1. Data Structure Setup
-  **Define the `HEADER` structure**
-  **Create the global free list**


##  2. Allocation Logic – `malloc_3is(size_t size)`

- **Search the free list** for a block large enough
- **If found:**
    - Remove it from the free list
- **If not found:**
    - Use `sbrk()` to expand the heap
    - Initialize the new block (`HEADER`, guards)
- **Return** a pointer to the usable memory region

---

## 3. Free Logic – `free_3is(void *ptr)`

- **Check for NULL pointer**
- **Verify magic numbers**
    - If changed, print a corruption error message
- **Insert the freed block into the free list, keeping the list sorted by memory address
- ** merge adjacent free memory

---