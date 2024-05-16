#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/off_t.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "list.h"


/*================== files ======================*/
struct lock file_lock;

bool is_valid_pointer(const void *vaddr);
bool is_valid_string(const char *str);
bool is_valid_buffer(const void *buffer, unsigned size);

struct file *get_file(int fd);

void create(struct intr_frame *f);
void remove(struct intr_frame *f);
void open(struct intr_frame *f);
void file_size(struct intr_frame *f);
void read(struct intr_frame *f);
void write(struct intr_frame *f);
void seek(struct intr_frame *f);
void tell(struct intr_frame *f);
void close(struct intr_frame *f);
/*=================== files end ====================*/

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /*============= files =====================*/
  lock_init(&file_lock);
  /*============= files end =====================*/
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call!\n");
  int syscall_num = *(int *)f->esp;

   /*=============wait=====================*/
  if(syscall_num == SYS_HALT)
    halt();
  else if(syscall_num == SYS_EXIT){
    int status = *((int *)f->esp + 1);
    Syscall_exit(status);
  }
     /*=============wait=====================*/
  else if(syscall_num == SYS_EXEC)
    f->eax = process_execute((const char *)*((int *)f->esp + 1));
    // printf("SYS_EXEC\n");
  else if(syscall_num == SYS_WAIT)
    f->eax = process_wait(*((int *)f->esp + 1));
    // printf("SYS_WAIT\n");

  /*================== files ======================*/
  else if(syscall_num == SYS_CREATE)
    // printf("SYS_CREATE\n");
    create(f);
  else if(syscall_num == SYS_REMOVE)
    // printf("SYS_REMOVE\n");
    remove(f);
  else if(syscall_num == SYS_OPEN)
    // handle_open(f);
    open(f);
  else if(syscall_num == SYS_FILESIZE)
    // printf("SYS_FILESIZE\n");
    file_size(f);
  else if(syscall_num == SYS_READ)
    // printf("SYS_READ\n");
    read(f);
  else if(syscall_num == SYS_WRITE)
    // handle_write(f);
    write(f);
  else if(syscall_num == SYS_SEEK)
    // printf("SYS_SEEK\n");
    seek(f);
  else if(syscall_num == SYS_TELL)
    // printf("SYS_TELL\n");
    tell(f);
  else if(syscall_num == SYS_CLOSE)
    // printf("SYS_CLOSE\n");
    close(f);
  /*=================== files end ====================*/
  else
    printf("Unknown system call %d\n", syscall_num);
  
  // printf("syscall finished!\n");
  // thread_exit ();
}

/*================== files ======================*/
bool is_valid_pointer(const void *vaddr){
  if(!is_user_vaddr(vaddr))
    return false;
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(ptr == NULL)
    return false;
  return true;
}

bool is_valid_string(const char *str){
  if(!is_valid_pointer(str))
    return false;
  while(*str != '\0'){
    str++;
    if(!is_valid_pointer(str))
      return false;
  }
  return true;
}

bool is_valid_buffer(const void *buffer, unsigned size){
  const char *ptr = buffer;
  for(unsigned i = 0; i < size; i++){
    if(!is_valid_pointer(ptr + i))
      return false;
  }
  return true;
}

struct file *get_file(int fd){
  struct thread *cur = thread_current();
  struct list_elem *e;
  for(e = list_begin(&cur->user_files); e != list_end(&cur->user_files); e = list_next(e)){
    struct thread_file *tf = list_entry(e, struct thread_file, elem);
    if(tf->fd == fd)
      return tf->file;
  }
  return NULL;
}

void create(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1) || !is_valid_pointer((void *)f->esp + 2)){
    Syscall_exit(-1);
    return;
  }
  const char *name = (const char *)*((int *)f->esp + 1);
  unsigned initial_size = *((unsigned *)f->esp + 2);
  if(!is_valid_string(name)){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  bool success = filesys_create(name, initial_size);
  lock_release(&file_lock);
  f->eax = success;
}

void remove(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1)){
    Syscall_exit(-1);
    return;
  }
  const char *name = (const char *)*((int *)f->esp + 1);
  if(!is_valid_string(name)){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  bool success = filesys_remove(name);
  lock_release(&file_lock);
  f->eax = success;
}

void open(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1)){
    Syscall_exit(-1);
    return;
  }
  const char *name = (const char *)*((int *)f->esp + 1);
  if(!is_valid_string(name)){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  struct file *file = filesys_open(name);
  lock_release(&file_lock);
  if(file == NULL)
    f->eax = -1;
  else{
    struct thread *cur = thread_current();
    struct thread_file *tf = malloc(sizeof(struct thread_file));
    tf->fd = cur->next_fd++;
    tf->file = file;
    list_push_back(&cur->user_files, &tf->elem);
    f->eax = tf->fd;
  }
}

void file_size(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  struct file *file = get_file(fd);
  if(file == NULL){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  int size = file_length(file);
  lock_release(&file_lock);
  f->eax = size;
}

void read(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1) || !is_valid_pointer((void *)f->esp + 2) || !is_valid_pointer((void *)f->esp + 3)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  void *buffer = (void *)*((int *)f->esp + 2);
  unsigned size = *((unsigned *)f->esp + 3);
  if(!is_valid_buffer(buffer, size)){
    Syscall_exit(-1);
    return;
  }
  if(fd == 0){
    for(unsigned i = 0; i < size; i++)
      *((uint8_t *)buffer + i) = input_getc();
    f->eax = size;
    return;
  }
  struct file *file = get_file(fd);
  if(file == NULL){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  int bytes_read = file_read(file, buffer, size);
  lock_release(&file_lock);
  f->eax = bytes_read;
}

void write(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1) || !is_valid_pointer((void *)f->esp + 2) || !is_valid_pointer((void *)f->esp + 3)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  const void *buffer = (const void *)*((int *)f->esp + 2);
  unsigned size = *((unsigned *)f->esp + 3);
  if(!is_valid_buffer(buffer, size)){
    Syscall_exit(-1);
    return;
  }
  if(fd == 1){
    putbuf(buffer, size);
    f->eax = size;
    return;
  }
  struct file *file = get_file(fd);
  if(file == NULL){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  int bytes_written = file_write(file, buffer, size);
  lock_release(&file_lock);
  f->eax = bytes_written;
}

void seek(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1) || !is_valid_pointer((void *)f->esp + 2)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  unsigned position = *((unsigned *)f->esp + 2);
  struct file *file = get_file(fd);
  if(file == NULL){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
}

void tell(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  struct file *file = get_file(fd);
  if(file == NULL){
    Syscall_exit(-1);
    return;
  }
  lock_acquire(&file_lock);
  unsigned position = file_tell(file);
  lock_release(&file_lock);
  f->eax = position;
}

void close(struct intr_frame *f){
  if(!is_valid_pointer((void *)f->esp + 1)){
    Syscall_exit(-1);
    return;
  }
  int fd = *((int *)f->esp + 1);
  struct thread *cur = thread_current();
  struct list_elem *e;
  for(e = list_begin(&cur->user_files); e != list_end(&cur->user_files); e = list_next(e)){
    struct thread_file *tf = list_entry(e, struct thread_file, elem);
    if(tf->fd == fd){
      lock_acquire(&file_lock);
      file_close(tf->file);
      lock_release(&file_lock);
      list_remove(e);
      free(tf);
      return;
    }
  }
  Syscall_exit(-1);
}

/*=================== files end ====================*/

   /*=============wait=====================*/
void halt (void){
  shutdown_power_off();
}

void Syscall_exit (int status){
  struct thread *cur = thread_current();
  char *save_ptr;
  char *executable = strtok_r(cur->name, " ", &save_ptr);
  if (status < -1) status = -1;
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit();
}
   /*=============wait=====================*/

