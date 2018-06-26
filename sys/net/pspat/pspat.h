#ifndef __PSPAT_H__
#define __PSPAT_H__

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/kthread.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>

#include "mailbox.h"

MALLOC_DECLARE(M_PSPAT);

/* per-cpu data structure */
struct pspat_queue {
	/* Input queue, a mailbox of mailbox pointers.
	 * written by clients, read by the arbiter. */
	struct pspat_mailbox   *inq;

	/* client fields */
	u64			cli_last_mb __aligned(CACHE_LINE_SIZE);

	/* arbiter fields */
	u64			arb_extract_next __aligned(CACHE_LINE_SIZE);
	struct pspat_mailbox   *arb_last_mb;
	struct entry_list mb_to_clear;
};

struct pspat_dispatcher {
	struct pspat_mailbox	*mb;
};

struct pspat {
	struct thread	*arb_thread;
	struct thread	*snd_thread;

	/* list of dead mailboxes to be deleted at the first
	 * safe opportunity
	 */
	struct entry_list mb_to_delete;

	/* Statistics to evaluate the cost of an arbiter loop. */
	unsigned int		num_loops;
	unsigned int		num_reqs;
	u64			max_picos;
	u64			num_picos;
	u64			last_ts;

	/* mailboxes between the arbiter and the dispatchers
	 * (used with PSPAT_XMIT_MODE_DISPATCH) */
	struct pspat_dispatcher	dispatchers[1];

	/* mailboxes between clients and the arbiter */
	int			n_queues;
	struct pspat_queue	queues[0];
};

extern struct pspat *pspat_arb;

extern static struct rwlock pspat_rwlock;

int pspat_do_arbiter(struct pspat *arb);

int pspat_client_handler(struct mbuf *mbf,  struct ifnet *ifp);

void pspat_shutdown(struct pspat *arb);

int pspat_do_dispatcher(struct pspat_dispatcher *s);

void pspat_dispatcher_shutdown(struct pspat_dispatcher *s);

int pspat_create_client_queue(void);

extern int pspat_enable;
extern int pspat_debug_xmit;
#define PSPAT_XMIT_MODE_ARB		0 /* packets sent by the arbiter */
#define PSPAT_XMIT_MODE_DISPATCH	1 /* packets sent by dispatcher */
#define PSPAT_XMIT_MODE_MAX		2 /* packets dropped by the arbiter */
extern int pspat_xmit_mode;
extern u64 pspat_rate;
extern u64 pspat_arb_interval_ns;
extern u64 pspat_arb_backpressure_drop;
extern u64 pspat_arb_dispatch_drop;
extern u64 pspat_dispatch_deq;
extern u64 *pspat_rounds;
extern u64 pspat_arb_loop_avg_ns;
extern u64 pspat_arb_loop_max_ns;
extern u64 pspat_arb_loop_avg_reqs;
extern uint32_t pspat_arb_batch;
extern uint32_t pspat_dispatch_batch;
extern struct pspat_stats *pspat_stats;

struct pspat_stats {
	unsigned long inq_drop;
} __attribute__((aligned(32)));

#endif  /* __PSPAT_H__ */
