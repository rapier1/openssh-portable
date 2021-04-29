/** \file
 * This file provides prototypes for an implementation of a pthread pool.
 * Based on pthread_pool by Jon Gjengset found at https://github.com/jonhoo/pthread_pool
 * This version is stripped down and makes use of _Atomic for inc/decrements
 * Author: Chris Rapier (rapier@psc.edu)
 * License: MIT License
 */

#ifndef __PTHREAD_POOL_H__
/**
 * Create a new thread pool.
 * 
 * New tasks should be enqueued with pool_enqueue. thread_func will be called
 * once per queued task with its sole argument being the argument given to
 * pool_enqueue.
 *
 * \param thread_func The function executed by each thread for each work item.
 * \param threads The number of threads in the pool.
 * \return A pointer to the thread pool.
 */
void * pool_start(void * (*thread_func)(void *), unsigned int threads);

/**
 * Enqueue a new task for the thread pool.
 *
 * \param pool A thread pool returned by start_pool.
 * \param arg The argument to pass to the thread worker function.
 * \param free If true, the argument will be freed after the task has completed.
 */
void pool_enqueue(void *pool, void *arg);

/** 
 * Returns a count of in process and outstanding jobs
 *
 * \param pool A thread pool returned by start_pool.
 * \return An int corresponding to the number of outstanding jobs. 
*/
int pool_count(void *pool);

#endif
