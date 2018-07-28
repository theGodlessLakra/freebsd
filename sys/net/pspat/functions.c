#include <sys/types.h>
#include <machine/atomic.h>
#include <net/ethernet.h>

#include "mailbox.h"
#include "pspat.h"

#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>

#define	NSEC_PER_SEC	1000000000L
#define	PSPAT_ARB_STATS_LOOPS	0x1000

extern int pspat_enable;

extern void dummynet_send(struct mbuf *);

/* Pseudo-identifier for client mailboxes. It's used by pspat_cli_push()
 * to decide when to insert an entry in the CL. Way safer than the previous
 * approach, but there are still theoretical race conditions for an
 * identifier to be reused while a previous process with the same identifier
 * is still alive.
 */
static int mb_next_id = 0;

/* push a new packet to the client queue
 * returns -ENOBUFS if the queue is full
 */
static int
pspat_cli_push(struct pspat_queue *pq, struct mbuf *mbf)
{
	struct pspat_mailbox *m;
	int err;

	if (curthread->pspat_mb == NULL) {
		err = pspat_create_client_queue();
		if (err)
			return err;
		curthread->pspat_mb->identifier = atomic_fetchadd_int(&mb_next_id, 1);
	}
	m = curthread->pspat_mb;

	if (m->backpressure) {
		m->backpressure = 0;
		if (pspat_debug_xmit) {
			printf("mailbox %p backpressure\n", m);
		}
		return -ENOBUFS;
	}

	printf("pspat_client_push inserting packet %p to client queue on PQ %p\n", mbf, pq);
	err = pspat_mb_insert(m, mbf);
	if (err)
		return err;
	/* avoid duplicate notification */
	if (pq->cli_last_mb != m->identifier) {
		mb(); /* let the arbiter see the insert above */
		err = pspat_mb_insert(pq->inq, m);
		pq->cli_last_mb = m->identifier;
	}

	return 0;
}

static void
pspat_cli_delete(struct pspat *arb, struct pspat_mailbox *m)
{
	int i;
	struct pspat_queue *pq;

	/* remove m from all the client lists current-mb pointers */
	for (i = 0; i < arb->n_queues; i++) {
		pq = arb->queues + i;
		if (pq->arb_last_mb == m)
			pq->arb_last_mb = NULL;
	}
	/* insert into the list of mb to be delete */
	ENTRY_INIT(&m->entry);
	TAILQ_INSERT_TAIL(&arb->mb_to_delete, &m->entry, entries);
}

static struct pspat_mailbox *
pspat_arb_get_mb(struct pspat_queue *pq)
{
	struct pspat_mailbox *m = pq->arb_last_mb;

	if (m == NULL || pspat_mb_empty(m)) {
		m = pspat_mb_extract(pq->inq);
		if (m) {
			if (ENTRY_EMPTY(pq->inq->entry)) {
				TAILQ_INSERT_TAIL(&pq->mb_to_clear, &pq->inq->entry, entries);
			}
			pq->arb_last_mb = m;
			/* wait for previous updates in the new mailbox */
			mb();
		}
	}
	return m;
}

/* extract mbf from the local queue */
static struct mbuf *
pspat_arb_get_mbf(struct pspat *arb, struct pspat_queue *pq)
{
	struct pspat_mailbox *m;
	struct mbuf *mbf;

retry:
	/* first, get the current mailbox for this cpu */
	m = pspat_arb_get_mb(pq);
	if (m == NULL) {
		return NULL;
	}
	/* try to extract an mbf from the current mailbox */
	mbf = pspat_mb_extract(m);
	if (mbf) {
		/* let pspat_arb_ack() see this mailbox */
		ENTRY_INIT(&m->entry);
		TAILQ_INSERT_TAIL(&pq->mb_to_clear, &m->entry, entries);
	} else  if (m->dead) {
		/* possibily remove this mb from the ack list */
		if (!ENTRY_EMPTY(m->entry)) {
			TAILQ_REMOVE(&pq->mb_to_clear, &m->entry, entries);
		}
		/* the client is gone, the arbiter takes
		 * responsibility in deleting the mb
		 */
		pspat_cli_delete(arb, m);
		goto retry;
	}
	return mbf;
}

static inline void
pspat_arb_prefetch(struct pspat *arb, struct pspat_queue *pq)
{
	if (pq->arb_last_mb != NULL)
		pspat_mb_prefetch(pq->arb_last_mb);
}

/* move mbf to the a sender queue */
static int
pspat_arb_dispatch(struct pspat *arb, struct mbuf *mbf)
{
	struct pspat_dispatcher s = arb->dispatchers[0];
	int err;

	err = pspat_mb_insert(s.mb, mbf);
	if (err) {
		/* Drop this mbf and possibly set the backpressure
		 * flag for the last client on the per-CPU queue
		 * where this mbf was transmitted. */
		struct pspat_mailbox *cli_mb;
		struct pspat_queue *pq;

		pq = pspat_arb->queues + mbf->sender_cpu - 1;
		cli_mb = pq->arb_last_mb;

		if (cli_mb && !cli_mb->backpressure) {
			cli_mb->backpressure = 1;
		}
		pspat_arb_dispatch_drop ++;
		m_free(mbf);
	}

	return err;
}

/* Zero out the used mbfs in the client mailboxes and the
 * client lists. */
static void
pspat_arb_ack(struct pspat_queue *pq)
{
	struct pspat_mailbox *mb;
	struct list *mb_entry, *mb_entry_temp;

	TAILQ_FOREACH_SAFE(mb_entry, &pq->mb_to_clear, entries, mb_entry_temp) {
		mb = (struct pspat_mailbox *) mb_entry->mb;
		TAILQ_REMOVE(&pq->mb_to_clear, mb_entry, entries);
		ENTRY_INIT(&mb->entry);
		pspat_mb_clear(mb);
	}
}

/* delete all known dead mailboxes */
static void
pspat_arb_delete_dead_mbs(struct pspat *arb)
{
	struct pspat_mailbox *mb;
	struct list *mb_entry, *mb_entry_temp;

	TAILQ_FOREACH_SAFE(mb_entry, &arb->mb_to_delete, entries, mb_entry_temp) {
		mb = (struct pspat_mailbox *) mb_entry->mb;
		TAILQ_REMOVE(&arb->mb_to_delete, mb_entry, entries);
		ENTRY_INIT(mb_entry);
		pspat_mb_delete(mb);
	}
}

static void
pspat_arb_drain(struct pspat *arb, struct pspat_queue *pq)
{
	struct pspat_mailbox *m = pq->arb_last_mb;
	struct mbuf *mbf;
	int dropped = 0;

	while ( (mbf = pspat_arb_get_mbf(arb, pq)) ) {
		m_free(mbf);
		dropped++;
	}

	if (!m->backpressure) {
		m->backpressure = 1;
	}

	if (pspat_debug_xmit) {
		printf("PSPAT drained mailbox %s [%d mbfs]\n", m->name, dropped);
	}
	pspat_arb_backpressure_drop += dropped;
}

static void
pspat_txqs_flush(struct mbuf *m)
{
//	dummynet_send(m);
	printf("Snding packet %p out\n", m);
	struct ifnet *ifp = m->ifp;
	(*ifp->if_output)(ifp, m, m->gw, m->ro);
	printf("Sent packet %p out\n", m);
//	ether_output_frame(ifp, m);
//	ip_output(m, NULL, NULL, IP_FORWARDING, NULL, NULL);
}

extern struct dn_parms dn_cfg;
extern void *dn_ht_find(struct dn_ht *ht, uintptr_t key, int flags, void *arg);
extern struct dn_sch_inst *ipdn_si_find(struct dn_schk *s, struct ipfw_flow_id *id);
extern struct dn_queue *ipdn_q_find(struct dn_fsk *fs, struct dn_sch_inst *si,
		struct ipfw_flow_id *id);

/* Function implementing the arbiter. */
int
pspat_do_arbiter(struct pspat *arb)
{
	int i;
	struct timespec ts;
	nanotime(&ts);
	unsigned long now = ts.tv_nsec << 10, picos;
	unsigned long link_idle = 0;
	static unsigned long last_pspat_rate = 0;
	static unsigned long picos_per_byte = 1;
	unsigned int nreqs = 0;
//	static int first_packet = 1;

	/* number of empty client lists found in the last round
	 * (after a round with only empty CLs, we can safely
	 * delete the mbs in the mb_to_delete list)
	 */
	int empty_inqs = 0;

	if (pspat_rate != last_pspat_rate) {
		/* Avoid division in the dequeue stage below by
		 * precomputing the number of pseudo-picoseconds per byte.
		 * Recomputation is done only when needed. */
		last_pspat_rate = pspat_rate;
		picos_per_byte = (8 * (NSEC_PER_SEC << 10)) / last_pspat_rate;
	}

	/*
	 * bring in pending packets, arrived between link_idle
	 * and now (we assume they arrived at last_check)
	 */
	for (i = 0; i < arb->n_queues; i++) {
		struct pspat_queue *pq = arb->queues + i;
		struct mbuf *mbf;
		bool empty = true;
		pq->arb_extract_next = now + (pspat_arb_interval_ns << 10);

		pspat_arb_prefetch(arb, (i + 1 < arb->n_queues ? pq + 1 : arb->queues));

		printf("Arbiter checking PQ %p\n", pq);
		while ( (mbf = pspat_arb_get_mbf(arb, pq)) ) {

			printf("Arbiter picked packet %p from %p and sending to dispatcher queue\n", mbf, pq);
			pspat_arb_dispatch(arb, mbf);

			/* Enqueue to SA here */
//			if (first_packet) {
//				struct ip_fw_args *fwa = mbf->fwa;

//				int fs_id = (fwa->rule.info & IPFW_INFO_MASK) +
//				((fwa->rule.info & IPFW_IS_PIPE) ? 2*DN_MAX_ID : 0);
//				arb->fs = dn_ht_find(dn_cfg.fshash, fs_id, 0, NULL);
//				arb->si = ipdn_si_find(arb->fs->sched, &(fwa->f_id));

//				if (arb->fs->sched->fp->flags & DN_MULTIQUEUE)
//					arb->q = ipdn_q_find(arb->fs, arb->si, &(fwa->f_id));

//				arb->fs->sched->fp->enqueue(arb->si, arb->q, mbf);

//				first_packet = 0;

//			} else {
//				arb->fs->sched->fp->enqueue(arb->si, arb->q, mbf);
//			}

			empty = false;
			++nreqs;
		}

		if (empty) {
			++empty_inqs;
		}
	}
	if (empty_inqs == arb->n_queues) {
		pspat_arb_delete_dead_mbs(arb);
	}
	for (i = 0; i < arb->n_queues; i++) {
		struct pspat_queue *pq = arb->queues + i;
		pspat_arb_ack(pq);     /* to clients */
	}

	/* Dequeue from SA and send to dispatcher mailbox here */
//	if (arb->fs){
//		struct mbuf *mbf;
//		while ( (mbf = arb->fs->sched->fp->dequeue(arb->si)) ) {
//			pspat_arb_dispatch(arb, mbf);
//		}
//	}

	if (pspat_xmit_mode == PSPAT_XMIT_MODE_ARB) {
		unsigned int ndeq = 0;

		struct pspat_mailbox *m = arb->dispatchers[0].mb;
		struct mbuf *mbf;

		while (link_idle < now && ndeq < pspat_arb_batch) {
			if ((mbf = pspat_mb_extract(m)) != NULL) {
				link_idle += picos_per_byte * mbf->m_len;
				pspat_txqs_flush(mbf);
				ndeq ++;
			} else {
				link_idle = now;
			}
		}

		pspat_mb_clear(m);
	}

	/* Update statistics on avg/max cost of the arbiter loop and
	 * per-loop client mailbox processing. */
	picos = now - arb->last_ts;
	arb->last_ts = now;
	arb->num_picos += picos;
	arb->num_reqs += nreqs;
	arb->num_loops++;
	if (picos > arb->max_picos) {
		arb->max_picos = picos;
	}
	if (arb->num_loops & PSPAT_ARB_STATS_LOOPS) {
		pspat_arb_loop_avg_ns =
			(arb->num_picos / PSPAT_ARB_STATS_LOOPS) >> 10;
		pspat_arb_loop_max_ns = arb->max_picos >> 10;
		pspat_arb_loop_avg_reqs = arb->num_reqs / PSPAT_ARB_STATS_LOOPS;
		arb->num_loops = 0;
		arb->num_picos = 0;
		arb->max_picos = 0;
		arb->num_reqs = 0;
	}

	pause("Thread_pause", 100);
	return 0;
}

void
pspat_shutdown(struct pspat *arb)
{
	int n;
	int i;

	/* We need to drain all the client lists and client mailboxes
	 * to discover and free up all dead client mailboxes. */
	for (i = 0, n = 0; i < arb->n_queues; i++) {
		struct pspat_queue *pq = arb->queues + i;
		struct mbuf *mbf;

		while ( (mbf = pspat_arb_get_mbf(arb, pq)) ) {
			m_free(mbf);
			n ++;
		}
	}
	printf("%s: CMs drained, found %d mbfs\n", __func__, n);
}

//extern int pspat_client_handler(struct mbuf *mbuf, struct ip_fw_args *fwa);

extern int pspat_client_handler(struct mbuf *mbf,  struct ifnet *ifp,
		const struct sockaddr *gw, struct route *ro);
int
pspat_client_handler(struct mbuf *mbf,  struct ifnet *ifp,
		const struct sockaddr *gw, struct route *ro)
{
	static struct mbuf *ins_mbf;

	if(mbf == ins_mbf) {
		return -ENOTTY;
	} else {
		ins_mbf = mbf;
	}

	printf("PSPAT client handler received packet %p\n", mbf);

	int cpu, rc = 0;
	struct pspat_queue *pq;
	struct pspat *arb;

	rw_wlock(&pspat_rwlock);
	arb = pspat_arb;
	rw_wunlock(&pspat_rwlock);

	if (!pspat_enable || arb == NULL) {
		/* Not our business. */
		return -ENOTTY;
	}

	cpu = curthread->td_oncpu;
	mbf->sender_cpu = cpu;
//	mbf->fwa = fwa;
	mbf->ifp = ifp;
//	mbf->ifp = fwa->oif;
	mbf->gw = gw;
	mbf->ro = ro;

	pq = arb->queues + cpu;
	printf("PSPAT client handler sending packet %p to pspat_client_push()\n", mbf);
	if (pspat_cli_push(pq, mbf)) {
		pspat_stats[cpu].inq_drop++;
		rc = 1;
	}
	if (pspat_debug_xmit) {
		printf("cli_push(%p) --> %d\n", mbf, rc);
	}
	return rc;
}

extern void exit_pspat(void);

/* Called on thread exit() to clean-up PSPAT mailbox, if any. */
void
exit_pspat(void)
{
	struct pspat *arb;
	struct pspat_queue *pq;
	int cpu;

	if (curthread->pspat_mb == NULL)
		return;

	curthread->pspat_mb->dead = 1;

retry:
	rw_wlock(&pspat_rwlock);
	arb = pspat_arb;
	if (arb) {
		/* If the arbiter is running, we cannot delete the mailbox
		 * by ourselves. Instead, we set the "dead" flag and insert
		 * the mailbox in the client list.
		 */
		cpu = curthread->td_oncpu;
		pq = arb->queues + cpu;
		if (pspat_mb_insert(pq->inq, curthread->pspat_mb) == 0) {
			curthread->pspat_mb = NULL;
		}
	}
	rw_wunlock(&pspat_rwlock);
	if (curthread->pspat_mb) {
		/* the mailbox is still there */
		if (arb) {
			/* We failed to push PSPAT_LAST_SKB but the
			 * arbiter was running. We must try again.
			 */
			printf("PSPAT Try again to destroy mailbox\n");
			pause("Wait before retrying", 100);
			goto retry;
		} else {
			/* The arbiter is not running. Since
			 * pspat_shutdown() drains everything, any
			 * new arbiter will not see this mailbox.
			 * Therefore, we can safely free it up.
			 */
			pspat_mb_delete(curthread->pspat_mb);
			curthread->pspat_mb = NULL;
		}
	}
}

/* Body of the dispatcher. */
int
pspat_do_dispatcher(struct pspat_dispatcher *s)
{
	struct pspat_mailbox *m = s->mb;
	struct mbuf *mbf;
	int ndeq = 0;

	while (ndeq < pspat_dispatch_batch && ((mbf = pspat_mb_extract(m)) != NULL)) {
		pspat_txqs_flush(mbf);
		ndeq ++;
	}

	pspat_dispatch_deq += ndeq;
	pspat_mb_clear(m);

	if (pspat_debug_xmit && ndeq) {
		printf("PSPAT sender processed %d mbfs\n", ndeq);
	}

	return ndeq;
}

void
pspat_dispatcher_shutdown(struct pspat_dispatcher *s)
{
	struct mbuf *mbf;
	int n = 0;

	/* Drain the sender mailbox. */
	while ( (mbf = pspat_mb_extract(s->mb)) ) {
		m_free(mbf);
		n ++;
	}
	printf("%s: Sender MB drained, found %d mbfs\n", __func__, n);
}
