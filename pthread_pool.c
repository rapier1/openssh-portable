#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* activate extra prototypes for glibc */
#endif

#include "pthread_pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

struct pool_queue {
	void *arg;
	struct pool_queue *next;
};

struct pool {
	void *(*fn)(void *);
	_Atomic unsigned int remaining;
	struct pool_queue *q;
	struct pool_queue *end;
	pthread_mutex_t q_mtx;
	pthread_cond_t q_cnd;
	pthread_t threads[1];
};

static void * thread(void *arg);

void * pool_start(void * (*thread_func)(void *), unsigned int threads) {
	struct pool *p = (struct pool *) malloc(sizeof(struct pool) + (threads-1) * sizeof(pthread_t));
	u_int i;

/*if we have adaptive mutex then try to use it */
#ifdef _GNU_SOURCE
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&p->q_mtx, &attr);
#else
	pthread_mutex_init(&p->q_mtx, NULL);
#endif

	/* we don't need joinable threads for this */
	pthread_attr_t detached_attr;
	pthread_attr_init(&detached_attr);
	pthread_attr_setdetachstate(&detached_attr, PTHREAD_CREATE_DETACHED);

	pthread_cond_init(&p->q_cnd, NULL);
	
	p->fn = thread_func;
	p->remaining = 0;
	p->end = NULL;
	p->q = NULL;

	for (i = 0; i < threads; i++) {
		pthread_create(&p->threads[i], &detached_attr, &thread, p);
	}

	return p;
}

void pool_enqueue(void *pool, void *arg) {
	struct pool *p = (struct pool *) pool;
	struct pool_queue *q = (struct pool_queue *) malloc(sizeof(struct pool_queue));
	q->arg = arg;
	q->next = NULL;

	pthread_mutex_lock(&p->q_mtx);
	if (p->end != NULL) p->end->next = q;
	if (p->q == NULL) p->q = q;
	p->end = q;
	pthread_mutex_unlock(&p->q_mtx);
	p->remaining++;
	pthread_cond_signal(&p->q_cnd);
}

int pool_count(void *pool) {
	struct pool *p = (struct pool *) pool;
	return p->remaining;
}

static void * thread(void *arg) {
	struct pool_queue *q;
	struct pool *p = (struct pool *) arg;

	while (1) {
		pthread_mutex_lock(&p->q_mtx);
		while (p->q == NULL) {
			pthread_cond_wait(&p->q_cnd, &p->q_mtx);
		}
		q = p->q;
		p->q = q->next;
		p->end = (q == p->end ? NULL : p->end);
		pthread_mutex_unlock(&p->q_mtx);

		p->fn(q->arg);
		p->remaining--;
	}
	return NULL;
}
