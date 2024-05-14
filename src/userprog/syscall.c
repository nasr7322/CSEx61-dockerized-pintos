#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"

int file_descriptor = 2;
static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  int syscall_num = *(int *)f->esp;
  
  

  if(syscall_num == SYS_HALT)
    halt();
  else if(syscall_num == SYS_EXIT){
    int status = *((int *)f->esp + 1);
    exit(status,f);
  }
  else if(syscall_num == SYS_EXEC)
    printf("SYS_EXEC\n");
  else if(syscall_num == SYS_WAIT)
    printf("SYS_WAIT\n");
  else if(syscall_num == SYS_CREATE)
    printf("SYS_CREATE\n");
  else if(syscall_num == SYS_REMOVE)
    printf("SYS_REMOVE\n");
  else if(syscall_num == SYS_OPEN)
    handle_open(f);
  else if(syscall_num == SYS_FILESIZE)
    printf("SYS_FILESIZE\n");
  else if(syscall_num == SYS_READ)
    printf("SYS_READ\n");
  else if(syscall_num == SYS_WRITE)
    handle_write(f);
  else if(syscall_num == SYS_SEEK)
    printf("SYS_SEEK\n");
  else if(syscall_num == SYS_TELL)
    printf("SYS_TELL\n");
  else if(syscall_num == SYS_CLOSE)
    printf("SYS_CLOSE\n");
  else
    printf("Unknown system call %d\n", syscall_num);
  
  printf("syscall finished!\n");
  // thread_exit ();
}

void handle_write(struct intr_frame *f){
  printf("handle_write\n");
  int *esp = f->esp;
  off_t size = *((off_t *)f->esp + 1);
  const void *buffer = *((const void **)f->esp + 2);
  int fd = *((int *)f->esp + 3);
  // display data for debugging
  printf("syscall_num: %d\n", *esp);
  printf("size: %d\n", size);
  printf("buffer: %s\n", buffer);
  printf("file: %d\n", fd);

// need to handle if write not to console

  printf("%s", buffer);
  f->eax = size;
}

void handle_open(struct intr_frame *f){
  printf("handle_open\n");
  struct inode *inode = *((struct inode **)f->esp + 1);
  // display data for debugging
  printf("syscall_num: %d\n", *(int *)f->esp);
  printf("inode: %s\n", inode);
  struct file *file = file_open(inode);
  if(file == NULL){
    f->eax = -1;
  }else{
    f->eax = file_descriptor;
    file_descriptor++;
  }
}

void halt (void){
  shutdown_power_off();
}

void exit (int status, struct intr_frame *f){
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);

  // handle parents
  
  // handle children

  // handle open files

  thread_exit();
}