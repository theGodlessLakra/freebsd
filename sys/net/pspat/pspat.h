#ifndef __PSPAT_H__
#define __PSPAT_H__

#include <sys/systm.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/kthread.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/rwlock.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include <netpfil/ipfw/ip_fw_private.h>
#include <netpfil/ipfw/dn_heap.h>
#include <netpfil/ipfw/ip_dn_private.h>
#ifdef NEW_AQM
#include <netpfil/ipfw/dn_aqm.h>
#endif
#include <netpfil/ipfw/dn_sched.h>

#include "mailbox.h"

MALLOC_DECLARE(M_PSPAT);

/* per-cpu data structure */
struct pspat_queue {
	/* Input queue, a mailbox of mailbox pointers.
	 * written by clients, read by the arbiter. */
	struct pspat_mailbox   *inq;

	/* client fields */
	unsigned long		cli_last_mb __aligned(CACHE_LINE_SIZE);

	/* arbiter fields */
	unsigned long		arb_extract_next __aligned(CACHE_LINE_SIZE);
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

	struct dn_fsk		*fs;
	struct dn_sch_inst	*si;
	struct dn_queue		*q;

	/* Statistics to evaluate the cost of an arbiter loop. */
	unsigned int		num_loops;
	unsigned int		num_reqs;
	unsigned long		max_picos;
	unsigned long		num_picos;
	unsigned long		last_ts;

	/* mailboxes between the arbiter and the dispatchers
	 * (used with PSPAT_XMIT_MODE_DISPATCH) */
	struct pspat_dispatcher	dispatchers[1];

	/* mailboxes between clients and the arbiter */
	int			n_queues;
	struct pspat_queue	queues[0];
};

extern struct pspat *pspat_arb;

extern struct rwlock pspat_rwlock;

int pspat_do_arbiter(struct pspat *arb);

int pspat_client_handler(struct mbuf *mbf,  struct ip_fw_args *fwa);

void pspat_shutdown(struct pspat *arb);

int pspat_do_dispatcher(struct pspat_dispatcher *s);

void pspat_dispatcher_shutdown(struct pspat_dispatcher *s);

int pspat_create_client_queue(void);

extern void exit_pspat(void);

extern int pspat_enable;
extern int pspat_debug_xmit;
#define PSPAT_XMIT_MODE_ARB		0 /* packets sent by the arbiter */
#define PSPAT_XMIT_MODE_DISPATCH	1 /* packets sent by dispatcher */
#define PSPAT_XMIT_MODE_MAX		2 /* packets dropped by the arbiter */
extern int pspat_xmit_mode;
extern unsigned long pspat_rate;
extern unsigned long pspat_arb_interval_ns;
extern unsigned long pspat_arb_backpressure_drop;
extern unsigned long pspat_arb_dispatch_drop;
extern unsigned long pspat_dispatch_deq;
extern unsigned long *pspat_rounds;
extern unsigned long pspat_arb_loop_avg_ns;
extern unsigned long pspat_arb_loop_max_ns;
extern unsigned long pspat_arb_loop_avg_reqs;
extern uint32_t pspat_arb_batch;
extern uint32_t pspat_dispatch_batch;
extern struct pspat_stats *pspat_stats;

struct pspat_stats {
	unsigned long inq_drop;
} __attribute__((aligned(32)));

#endif  /* __PSPAT_H__ */
