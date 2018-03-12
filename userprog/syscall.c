/*
 * This file is derived from source code for the Pintos
 * instructional operating system which is itself derived
 * from the Nachos instructional operating system. The
 * Nachos copyright notice is reproduced in full below.
 *
 * Copyright (C) 1992-1996 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose, without fee, and
 * without written agreement is hereby granted, provided that the
 * above copyright notice and the following two paragraphs appear
 * in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
 * ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
 * AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
 * BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * Modifications Copyright (C) 2017-2018 David C. Harrison.
 * All rights reserved.
 */

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/umem.h"

static void syscall_handler(struct intr_frame *);

static void write_handler(struct intr_frame *);
static void exit_handler(struct intr_frame *);
static void create_handler(struct intr_frame *);
static void open_handler(struct intr_frame *);
static void close_handler(struct intr_frame *);
static void read_handler(struct intr_frame *);
static void exec_handler(struct intr_frame *);
static void wait_handler(struct intr_frame *);
static void fsize_handler(struct intr_frame *);

struct fileStruct{
	struct list_elem pairElem;
	struct file *file;
	char *name;
	int handle;
};

struct list *openFiles;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&openFiles);
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall;
  ASSERT( sizeof(syscall) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  umem_read(f->esp, &syscall, sizeof(syscall));

  // Store the stack pointer esp, which is needed in the page fault handler.
  // Do NOT remove this line
  thread_current()->current_esp = f->esp;

  switch (syscall) {
  case SYS_HALT:
    shutdown_power_off();
    break;

  case SYS_EXIT:
    exit_handler(f);
    break;

  case SYS_WRITE:
    write_handler(f);
    break;

  case SYS_CREATE:
	create_handler(f);
	break;

  case SYS_OPEN:
  	open_handler(f);
  	break;

  case SYS_CLOSE:
	close_handler(f);
	break;

  case SYS_READ:
	read_handler(f);
	break;

  case SYS_FILESIZE:
	fsize_handler(f);
	break;

  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall);
    thread_exit();
    break;
  }
}

/****************** System Call Implementations ********************/

static bool sys_create(char* fname, int isize){
	bool success = filesys_create(fname, sizeof(isize), false);
	return success;
}

static void create_handler(struct intr_frame *f){
	int isize;
	char *fname;
	umem_read(f->esp + 4, &fname, sizeof(fname));
	umem_read(f->esp + 8, &isize, sizeof(isize));
	f->eax = sys_create(fname, isize);
}

static int sys_fsize(char *fname, int handle){
	struct list_elem *e;
	int ret;

	for (e = list_begin(&openFiles); e != list_end(&openFiles); e = list_next(e)){
		struct fileStruct *f = list_entry(e, struct fileStruct, pairElem);
		if(f->name == fname && f->handle == handle){
			ret = file_length(f->file);
		}
	}
	return ret;
}

static void fsize_handler(struct intr_frame *f){
	int isize;
	char *fname;
	umem_read(f->esp + 4, &fname, sizeof(fname));
	umem_read(f->esp + 8, &isize, sizeof(isize));
	f->eax = sys_fsize(fname, isize);
}

static int sys_open(char *fname, int isize){
	if(filesys_open(fname) == NULL){
		return -1;
	}
	struct fileStruct newPair;
	newPair.file = filesys_open(fname);
	newPair.name = fname;
	newPair.handle = isize;

	struct list_elem *e;
	for (e = list_begin(&openFiles); e != list_end(&openFiles); e = list_next(e)){
		struct fileStruct *f = list_entry(e, struct fileStruct, pairElem);
		if(f->name == fname && f->handle == isize){
			newPair.handle += isize;
		}
	 }
	list_push_back(&openFiles, &newPair.pairElem);

	return isize;
}

static void open_handler(struct intr_frame *f){
	int isize;
	char *fname;
	umem_read(f->esp + 4, &fname, sizeof(fname));
	umem_read(f->esp + 8, &isize, sizeof(isize));
	f->eax = sys_open(fname, isize);
}

static sys_close(char *fname, int handle){
	struct list_elem *e;
	for (e = list_begin(&openFiles); e != list_end(&openFiles); e = list_next(e)){
		struct fileStruct *f = list_entry(e, struct fileStruct, pairElem);
		if(f->name == fname && f->handle == handle){
			file_close(f->file);
			list_remove(e);
		}
	 }
}

static void close_handler(struct intr_frame *f){
	char *fname;
	int handle;
	umem_read(f->esp + 4, &fname, sizeof(fname));
	umem_read(f->esp + 8, &handle, sizeof(handle));
	f->eax = sys_close(fname, handle);
}

static uint32_t sys_read(int fd, const void *buffer, unsigned size){
	umem_check((const uint8_t*) buffer);
	umem_check((const uint8_t*) buffer + size - 1);

	uint32_t ret = -1;

	struct list_elem *e;
	for (e = list_begin(&openFiles); e != list_end(&openFiles); e = list_next(e)){
		struct fileStruct *f = list_entry(e, struct fileStruct, pairElem);
	  	if(f->handle == fd){
	  		ret = file_read(f->file, buffer, size);
	  	}
	}
	return ret;
}

static void read_handler(struct intr_frame *f){
	int fd;
	const void *buffer;
	unsigned size;

	umem_read(f->esp + 4, &fd, sizeof(fd));
	umem_read(f->esp + 8, &buffer, sizeof(buffer));
	umem_read(f->esp + 12, &size, sizeof(size));

	f->eax = sys_read(fd, buffer, size);
}


void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static void exit_handler(struct intr_frame *f)
{
  int exitcode;
  umem_read(f->esp + 4, &exitcode, sizeof(exitcode));

  sys_exit(exitcode);
}
/*
 * BUFFER+0 and BUFFER+size should be valid user adresses
 */
static uint32_t sys_write(int fd, const void *buffer, unsigned size)
{
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);

  int ret = -1;

  if (fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  struct list_elem *e;
  	for (e = list_begin(&openFiles); e != list_end(&openFiles); e = list_next(e)){
  		struct fileStruct *f = list_entry(e, struct fileStruct, pairElem);
  		if(f->handle == fd){
  			file_write(f->file, buffer, size);
  			ret = size;
  		}
  	 }
  return (uint32_t) ret;
}

static void write_handler(struct intr_frame *f)
{
    int fd;
    const void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));

    f->eax = sys_write(fd, buffer, size);
}

