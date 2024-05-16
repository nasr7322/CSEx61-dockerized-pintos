#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);

/*================== files ======================*/
// struct lock file_lock;

// bool is_valid_pointer(const void *vaddr);
// bool is_valid_string(const char *str);
// bool is_valid_buffer(const void *buffer, unsigned size);

// struct file *get_file(int fd);

// void create(struct intr_frame *f);
// void remove(struct intr_frame *f);
// void open(struct intr_frame *f);
// void file_size(struct intr_frame *f);
// void read(struct intr_frame *f);
// void write(struct intr_frame *f);
// void seek(struct intr_frame *f);
// void tell(struct intr_frame *f);
// void close(struct intr_frame *f);

/*=================== files end ====================*/



#endif /* userprog/syscall.h */
