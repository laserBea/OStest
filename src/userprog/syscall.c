#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <devices/shutdown.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>


#define max_syscall 20
static void (*syscalls[max_syscall])(struct intr_frame *f);


void sys_halt(struct intr_frame *f); /* sys halt */
void sys_exit(struct intr_frame *f); /* sys exit */
void sys_exec(struct intr_frame *f);
void sys_wait(struct intr_frame *f);

void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_open(struct intr_frame *f);
void sys_write(struct intr_frame *f);
void sys_seek(struct intr_frame *f);
void sys_tell(struct intr_frame *f);
void sys_close(struct intr_frame *f);
void sys_read(struct intr_frame *f);
void sys_filesize(struct intr_frame *f);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // 进程的系统调用
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
  // syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_WAIT] = &sys_wait;
  // 文件的系统调用
  // syscalls[SYS_CREATE] = &sys_create;
  // syscalls[SYS_REMOVE] = &sys_remove;
  // syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  // syscalls[SYS_SEEK] = &sys_seek;
  // syscalls[SYS_TELL] = &sys_tell;
  // syscalls[SYS_CLOSE] = &sys_close;
  // syscalls[SYS_READ] = &sys_read;
  // syscalls[SYS_FILESIZE] = &sys_filesize;
}

struct thread_file*
find_file_id(int file_id)
{
  struct list_elem *e;
  struct thread_file *thread_file_temp = NULL;
  struct list *files = &thread_current()->files;
  for(e=list_begin(files); e != list_end(files); e = list_next(e)){
    thread_file_temp = list_entry(e, struct thread_file, file_elem);
    if(file_id == thread_file_temp->fd)
      return thread_file_temp;
  }
  return false;
}

void 
exit_special(void)
{
  thread_current()->st_exit = -1;
  thread_exit();
}

void *
check_ptr(const void *vaddr){
  void *ptr = NULL;
  if(!is_user_vaddr(vaddr)||!(ptr == pagedir_get_page(thread_current()->pagedir, vaddr))){
    exit_special();
    return 0;
  }
  return ptr;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *p = f->esp;
  // check_ptr(p+1);
  int type = *(int *)f->esp;
  if(type <=0 || type >= max_syscall){
    exit_special();
  }
  syscalls[type](f);
}

void 
sys_halt (struct intr_frame *f){
  shutdown_power_off();
}

void 
sys_exit (struct intr_frame *f){
  uint32_t *user_ptr = f->esp;
  // check_ptr(user_ptr+1);
  *user_ptr++;
  thread_current()->st_exit = *user_ptr;
  thread_exit();
}

void 
sys_write (struct intr_frame *f){
  uint32_t *user_ptr = f->esp;
  // check_ptr(user_ptr+7);
   //check_ptr(*(user_ptr+6));
  *user_ptr++;
  int temp2 = *user_ptr;
  const char *buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if(temp2 == 1){
    putbuf(buffer, size);
    f->eax = size;
  }
  else{
    struct thread_file *thread_file_temp = find_file_id(*user_ptr);
    if(thread_file_temp){
      acquire_lock_f();
      f->eax = file_write(thread_file_temp->file, buffer, size);
      release_lock_f();
    }
    else{
      f->eax = 0;
    }
  }
}

void 
sys_wait(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  // check_ptr(user_ptr+1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}
