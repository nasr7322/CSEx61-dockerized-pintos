/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/*=================== priority scheduler  ====================*/
void donate_priority(struct lock *lock, int priority);
static bool sema_priority_comparator (const struct list_elem *a_, const struct list_elem *b_,void *aux UNUSED);
static bool thread_priority_comparator (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED);                                        
/*=================== priority scheduler end ====================*/


/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
  /*=================== priority scheduler  ====================*/
  sema->sema_priority = -1;
  /*=================== priority scheduler end ====================*/
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  // printf(thread_current()->name);
  // printf(sema->value);
  // printf("---------------------\n");
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      // list_push_back (&sema->waiters, &thread_current ()->elem);

      /*=================== priority scheduler  ====================*/
        list_insert_ordered(&sema->waiters, &thread_current ()->elem, thread_priority_comparator, NULL);
        // list_sort(&sema->waiters, thread_priority_comparator, NULL);

      /*=================== priority scheduler end ====================*/
  
      thread_block ();
      // printf(thread_current()->name);
      // printf("-------------------------------------------------------------\n");
      
    }
  sema->value--;
  
  intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)) 
    thread_unblock (list_entry (list_pop_front (&sema->waiters),
                                struct thread, elem));
  
  sema->value++;

  /*=================== priority scheduler  ====================*/
  // intr_set_level (old_level);
      thread_yield ();
  /*=================== priority scheduler end ====================*/

  intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}

/*=================== priority scheduler  ====================*/
// we can adjust level by level parameter
void donate_priority(struct lock *lock, int donated_priority){
  // if(lock == NULL || lock->holder == NULL || lock->holder->priority >= donated_priority){
  if(lock == NULL || lock->holder == NULL || lock->holder->max_donated_priority > donated_priority){
    return;
  }
  lock->holder->max_donated_priority = donated_priority;

  if(lock->holder->max_donated_priority > lock->holder->priority)
    lock->holder->priority = lock->holder->max_donated_priority;


  // list_remove(&lock->holder->elem);
  // list_insert_ordered(&lock->holder->lock_waiting_for->semaphore.waiters, &lock->holder->elem, sema_priority_comparator, NULL);
  
  donate_priority(lock->holder->lock_waiting_for, donated_priority);
}
/*=================== priority scheduler end ====================*/


/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  /*=================== priority scheduler  ====================*/
  enum intr_level old_level;
  old_level = intr_disable ();
  if(lock->holder != NULL){
    thread_current ()->lock_waiting_for = lock;
    
    if(!thread_mlfqs)
      donate_priority(lock, thread_current ()->priority);

    thread_yield();
  }

  // if(lock->holder != NULL) -> priority donation
  
 // put it in intr_disable()
  
  //#################### // can we add priority donation in sema down? Nooooo (related to holder logic) ########################
  /*=================== priority scheduler end ====================*/
  
  sema_down (&lock->semaphore);
  lock->holder = thread_current ();

  /*=================== priority scheduler  ====================*/
  thread_current ()->lock_waiting_for = NULL;
  list_push_back(&thread_current ()->locks_held, &lock->elem);
  intr_set_level (old_level);
  /*=================== priority scheduler end ====================*/
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

void update_donated_priority(){
  // int max_priority = thread_current ()->basic_priority;
  int mx_donated = -1;
  if(!list_empty(&thread_current ()->locks_held)){
    struct list_elem *e;
    for(e = list_begin(&thread_current ()->locks_held); e != list_end(&thread_current ()->locks_held); e = list_next(e)){
      struct lock *lock = list_entry(e, struct lock, elem);
      if(!list_empty(&lock->semaphore.waiters)){
        struct thread *t = list_entry(list_front(&lock->semaphore.waiters), struct thread, elem);
        if(t->priority > mx_donated){
          mx_donated = t->priority;
        }
      }
    }
  }
  thread_current ()->max_donated_priority = mx_donated;
  if(thread_current ()->basic_priority > thread_current ()->max_donated_priority){
    thread_current ()->priority = thread_current ()->basic_priority;
  }else{
    thread_current ()->priority = thread_current ()->max_donated_priority;
  }
}
  

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  /*=================== priority scheduler  ====================*/
  
  enum intr_level old_level;
  old_level = intr_disable ();
    
  list_remove(&lock->elem);

    // list_sort(&lock->semaphore.waiters, thread_priority_comparator, NULL);
    if(!thread_mlfqs)
      update_donated_priority();
    

  // list_remove(&lock->elem);
  /*=================== priority scheduler end ====================*/

  lock->holder = NULL;
  sema_up (&lock->semaphore);

  
  /*=================== priority  }  ====================*/
  intr_set_level (old_level);
  /*=================== priority scheduler end ====================*/
  
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
  };

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  // list_push_back (&cond->waiters, &waiter.elem);
  /*=================== priority scheduler  ====================*/
  //  waiter.semaphore.sema_priority = thread_current ()->priority;
   waiter.semaphore.sema_priority = lock->holder->priority;
  list_insert_ordered(&cond->waiters, &waiter.elem, sema_priority_comparator, NULL);
  /*=================== priority scheduler end ====================*/

  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters))
    sema_up (&list_entry (list_pop_front (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
    
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
/*=================== priority scheduler  ====================*/
static bool
sema_priority_comparator (const struct list_elem *a_, const struct list_elem *b_,
                    void *aux UNUSED)
{
  ASSERT (a_ != NULL);
  ASSERT (b_ != NULL);

  const struct semaphore_elem *a = list_entry (a_, struct semaphore_elem,
                                               elem);
  const struct semaphore_elem *b = list_entry (b_, struct semaphore_elem,
                                               elem);

  return (a->semaphore.sema_priority > b->semaphore.sema_priority);
}
static bool 
thread_priority_comparator (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED)
{
  ASSERT (a_ != NULL);
  ASSERT (b_ != NULL);
  const struct thread *a = list_entry (a_, struct thread, elem);
  const struct thread *b = list_entry (b_, struct thread, elem);
  return a->priority > b->priority;
}
/*=================== priority scheduler end ====================*/

