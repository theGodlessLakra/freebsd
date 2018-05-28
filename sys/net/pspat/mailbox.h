#ifndef __PSPAT_MAILBOX_H
#define __PSPAT_MAILBOX_H

#ifdef _KERNEL
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/malloc.h>

#endif /* _KERNEL */

#define PSPAT_MB_NAMSZ	32

#define PSPAT_MB_DEBUG 1

struct list_head {
	struct list_head *next, *prev;
};

#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)

#define is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))

struct pspat_mailbox {
	/* shared (constant) fields */
	char			name[PSPAT_MB_NAMSZ];
	unsigned long		entry_mask;
	unsigned long		line_entries;
	unsigned long		line_mask;

	/* shared field, written by both */
	unsigned long		backpressure;
	int			dead; /* written by producer */
	u64			identifier;

	/* producer fields */
	unsigned long		prod_write __aligned(CACHE_LINE_SIZE);
	unsigned long		prod_check;

	/* consumer fields */
	unsigned long		cons_clear __aligned(CACHE_LINE_SIZE);
	unsigned long		cons_read;
	struct list_head	list;

	/* the queue */
	void *		q[0] __aligned(CACHE_LINE_SIZE);
};

static inline size_t pspat_mb_size(unsigned long entries)
{
	return roundup(sizeof(struct pspat_mailbox) + entries * sizeof(void *),
			CACHE_LINE_SIZE);
}

/**
 * pspat_mb_new - create a new mailbox
 * @name: an aritrary name for the mailbox (debug)
 * @entries: the number of entries
 * @line_size: the line size in bytes
 *
 * Both entries and line_size must be a power of 2.
 * Returned pointer must be checked with IS_ERR().
 */
int pspat_mb_new(const char *name, unsigned long entries,
		unsigned long line_size, struct pspat_mailbox **m);


/**
 * pspat_mb_init - initialize a pre-allocated mailbox
 * @m: the mailbox to be initialized
 * @name: an aritrary name for the mailbox (debug)
 * @entries: the number of entries
 * @line_size: the line size in bytes
 *
 * Both entries and line_size must be a power of 2.
 * Returns 0 on success, -errno on failure.
 */
int pspat_mb_init(struct pspat_mailbox *m, const char *name, unsigned long entries,
		unsigned long line_size);

/**
 * pspat_mb_delete - delete a mailbox
 * @m: the mailbox to be deleted
 */
void pspat_mb_delete(struct pspat_mailbox *m);

void pspat_mb_dump_state(struct pspat_mailbox *m);

/**
 * pspat_mb_insert - enqueue a new value
 * @m: the mailbox where to enqueue
 * @v: the value to be enqueued
 *
 * Returns 0 on success, -ENOBUFS on failure.
 */
static inline int pspat_mb_insert(struct pspat_mailbox *m, void *v)
{
	if (unlikely(m->prod_write == m->prod_check)) {
		/* Leave a cache line empty. */
		if (m->q[(m->prod_check + m->line_entries) & m->entry_mask])
			return -ENOBUFS;
		m->prod_check += m->line_entries;
		__builtin_prefetch(h + m->line_entries);
	}
	BUG_ON(((void *)v) & 0x1);
	m->q[m->prod_write & m->entry_mask] = v;
	m->prod_write++;
	return 0;
}

/**
 * pspat_mb_extract - extract a value
 * @m: the mailbox where to extract from
 * 
 * Returns the extracted value, NULL if the mailbox
 * is empty. It does not free up any entry, use
 * pspat_mb_clear/pspat_mb_cler_all for that
 */
static inline void *pspat_mb_extract(struct pspat_mailbox *m)
{
	void *v = m->q[m->cons_read & m->entry_mask];

	if (!v)
		return NULL;

	m->cons_read++;

	return v;
}


/**
 * pspat_mb_clear - clear the previously extracted entries
 * @m: the mailbox to be cleared
 *
 */
static inline void pspat_mb_clear(struct pspat_mailbox *m)
{
	unsigned next_clear = (m->cons_read & m->line_mask) - m->line_entries;

	while(m->cons_clear != next_clear) {
		m->q[m->cons_clear & m->entry_mask] = 0;
		m->cons_clear++;
	}
}

/**
 * pspat_mb_cancel - remove from the mailbox all instances of a value
 * @m: the mailbox
 * @v: the value to be removed
 */
void pspat_mb_cancel(struct pspat_mailbox *m, void *v);

static inline void pspat_mb_prefetch(struct pspat_mailbox *m)
{
	__builtin_prefetch((void *)m->q[m->cons_read & m->entry_mask]);
}

#endif /* __PSPAT_MAILBOX_H */
