#include <machine/atomic.h>

#include "pspat.h"

#define	NSEC_PER_SEC	1000000000L

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

	if (unlikely(curthread->pspat_mb == NULL)) {
		err = pspat_create_client_queue();
		if (err)
			return err;
		curthread->pspat_mb->identifier = atomic_fetchadd(&mb_next_id, 1);
	}
	m = curthread->pspat_mb;

        /* The backpressure flag set tells us that the qdisc is being overrun.
         * We return an error to propagate the overrun to the client. */
	if (unlikely(m->backpressure)) {
		m->backpressure = 0;
		if (pspat_debug_xmit) {
			printf("mailbox %p backpressure\n", m);
		}
		return -ENOBUFS;
	}

	err = pspat_mb_insert(m, mbf);
	if (err)
		return err;
	/* avoid duplicate notification */
	if (pq->cli_last_mb != m->identifier) {
//		smp_mb(); /* let the arbiter see the insert above */
		err = pspat_mb_insert(pq->inq, m);
		BUG_ON(err);
		pq->cli_last_mb = m->identifier;
	}

	return 0;
}

static void
pspat_cli_delete(struct pspat *arb, struct pspat_mailbox *m)
{
	int i;
	/* remove m from all the client lists current-mb pointers */
	for (i = 0; i < arb->n_queues; i++) {
		struct pspat_queue *pq = arb->queues + i;
		if (pq->arb_last_mb == m)
			pq->arb_last_mb = NULL;
	}
	/* possibily remove this mb from the ack list */
	while (!TAILQ_EMPTY(&m->head)) {
		struct entry *entry1 = TAILQ_FIRST(&m->head);
		TAILQ_REMOVE(&m->head, entry1, entries);
	}

	/* insert into the list of mb to be delete */
	TAILQ_INSERT_TAIL(&arb->mb_to_delete, &m->list, entries);
}

static struct pspat_mailbox *
pspat_arb_get_mb(struct pspat_queue *pq)
{
	struct pspat_mailbox *m = pq->arb_last_mb;

	if (m == NULL || pspat_mb_empty(m)) {
		m = pspat_mb_extract(pq->inq);
		if (m) {
			if (TAILQ_EMPTY(&pq->inq->head)) {
				TAILQ_INSERT_TAIL(&pq->mb_to_clear, &pq->inq->list, entries);
			}
			pq->arb_last_mb = m;
			/* wait for previous updates in the new mailbox */
//			smp_mb();
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
		if (TAILQ_EMPTY(&m->head)) {
			TAILQ_INSERT_TAIL(&pq->mb_to_clear, &m->list, entries);
		}
	} else  if (unlikely(m->dead)) {
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

/* mark mbf as eligible for transmission on an ifnet, and
 * make sure this queue is part of the list of active queues */
static inline void
pspat_mark(struct tailhead *active_queues, struct mbuf *mbf)
{
	struct ifnet *txq = mbf->ifp;

//	BUG_ON(mbf->next);
	if (txq->pspat_markq_tail) {
		txq->pspat_markq_tail->next = mbf;
	} else {
		txq->pspat_markq_head = mbf;
	}
	txq->pspat_markq_tail = mbf;
	if (TAILQ_EMPTY(&txq->pspat_active)) {
		TAILQ_INSERT_TAIL(active_queues, &txq->pspat_active, entries);
	}
}

/* move mbf to the a sender queue */
static int
pspat_arb_dispatch(struct pspat *arb, struct mbuf *mbf)
{
	struct pspat_dispatcher *s = &arb->dispatchers[0];
	int err;

	err = pspat_mb_insert(s->mb, mbf);
	if (err) {
		/* Drop this mbf and possibly set the backpressure
		 * flag for the last client on the per-CPU queue
		 * where this mbf was transmitted. */
		struct pspat_mailbox *cli_mb;
		struct pspat_queue *pq;

//		BUG_ON(!mbf->sender_cpu);
//		pq = pspat_arb->queues + mbf->sender_cpu - 1;
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
	struct pspat_mailbox *mb_cursor, *mb_next;

//	list_for_each_entry_safe(mb_cursor, mb_next, &pq->mb_to_clear, list) {
		pspat_mb_clear(mb_cursor);
//		list_del_init(&mb_cursor->list);
//	}
}

/* delete all known dead mailboxes */
static void
pspat_arb_delete_dead_mbs(struct pspat *arb)
{
	struct pspat_mailbox *mb_cursor, *mb_next;

//	list_for_each_entry_safe(mb_cursor, mb_next, &arb->mb_to_delete, list) {
		while (!TAILQ_EMPTY(&mb_cursor->head)) {
			struct entry *entry1 = TAILQ_FIRST(&mb_cursor->head);
			TAILQ_REMOVE(&mb_cursor->head, entry1, entries);
		}
		pspat_mb_delete(mb_cursor);
//	}
}

static void
pspat_arb_drain(struct pspat *arb, struct pspat_queue *pq)
{
	struct pspat_mailbox *m = pq->arb_last_mb;
	struct mbuf *mbf;
	int dropped = 0;

	BUG_ON(!m);
	while ( (mbf = pspat_arb_get_mbf(arb, pq)) ) {
		m_free(mbf);
		dropped++;
	}

	if (!m->backpressure) {
		m->backpressure = 1;
	}

	if (unlikely(pspat_debug_xmit)) {
		printf("PSPAT drained mailbox %s [%d mbfs]\n", m->name, dropped);
	}
	pspat_arb_backpressure_drop += dropped;
}

/* Flush the markq associated to a device transmit queue. Returns 0 if all the
 * packets in the markq were transmitted. A non-zero return code means that the
 * markq has not been emptied. */
static inline int
pspat_txq_flush(struct ifnet *txq)
{
	int ret = NETDEV_TX_BUSY;
	struct mbuf *mbf;

	/* Validate all the mbfs in the markq. Some (or all) the mbfs may be
	 * dropped. The function may modify the markq head/tail pointers. */
//	txq->pspat_markq_head = validate_xmit_mbf_list(txq->pspat_markq_head,
//						dev, &txq->pspat_markq_tail);
	/* Append the markq to the validq (handling the case where the validq
	 * was empty and/or the markq is empty) and reset the markq. */
	if (txq->pspat_validq_head == NULL) {
		txq->pspat_validq_head = txq->pspat_markq_head;
		txq->pspat_validq_tail = txq->pspat_markq_tail;
	} else if (txq->pspat_markq_head) {
		txq->pspat_validq_tail->next = txq->pspat_markq_head;
		txq->pspat_validq_tail = txq->pspat_markq_tail;
	}
	txq->pspat_markq_head = txq->pspat_markq_tail = NULL;
	mbf = txq->pspat_validq_head;

//	HARD_TX_LOCK(dev, txq, smp_processor_id());
//	if (!netif_xmit_frozen_or_stopped(txq)) {
//		mbf = dev_hard_start_xmit(mbf, dev, txq, &ret);
//	}
//	HARD_TX_UNLOCK(dev, txq);

	/* The mbf pointer here is NULL if all packets were transmitted.
	 * Otherwise it points to a list of packets to be transmitted. */
	txq->pspat_validq_head = mbf;
	if (!mbf) {
		/* All packets were transmitted, we can just reset
		 * the validq tail (head was reset above). */
//		BUG_ON(!dev_xmit_complete(ret));
		txq->pspat_validq_tail = NULL;
		return 0;
	}

	return 1;
}

static void
pspat_txqs_flush(struct tailhead *txqs)
{
	struct ifnet *txq, *txq_next;

//	list_for_each_entry_safe(txq, txq_next, txqs, pspat_active) {
		if (pspat_txq_flush(txq) == 0) {
//			list_del_init(&txq->pspat_active);
		}
//	}
}

#define PSPAT_ARB_STATS_LOOPS	0x1000

/* Function implementing the arbiter. */
int
pspat_do_arbiter(struct pspat *arb)
{
	int i;
	struct timespec ts;
	nanotime(&ts);
	u64 now = ts->tv_nsec << 10, picos;
	static u64 last_pspat_rate = 0;
	static u64 picos_per_byte = 1;
	unsigned int nreqs = 0;
	/* number of empty client lists found in the last round
	 * (after a round with only empty CLs, we can safely
	 * delete the mbs in the mb_to_delete list)
	 */
	int empty_inqs = 0;

	if (unlikely(pspat_rate != last_pspat_rate)) {
		/* Avoid division in the dequeue stage below by
		 * precomputing the number of pseudo-picoseconds per byte.
		 * Recomputation is done only when needed. */
		last_pspat_rate = pspat_rate;
		picos_per_byte = (8 * (NSEC_PER_SEC << 10)) / last_pspat_rate;
	}

//	rcu_read_lock_bh();

	/*
	 * bring in pending packets, arrived between pspat_next_link_idle
	 * and now (we assume they arrived at last_check)
	 */

	for (i = 0; i < arb->n_queues; i++) {
		struct pspat_queue *pq = arb->queues + i;
		struct mbuf *to_free = NULL;
		struct mbuf *mbf;
		bool empty = true;

		if (now < pq->arb_extract_next) {
			continue;
		}
		pq->arb_extract_next = now + (pspat_arb_interval_ns << 10);

		pspat_arb_prefetch(arb, (i + 1 < arb->n_queues ? pq + 1 : arb->queues));

		while ( (mbf = pspat_arb_get_mbf(arb, pq)) ) {
			int rc;

			empty = false;
			++nreqs;

			/* ToDo : */


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
//	for (q = arb->qdiscs; q; q = q->pspat_next) {
//		u64 next_link_idle = q->pspat_next_link_idle;
		unsigned int ndeq = 0;

		while (next_link_idle <= now &&
			ndeq < pspat_arb_qdisc_batch)
		{
			struct mbuf *mbf = q->dequeue(q);

			if (mbf == NULL)
				break;
			ndeq++;
			if (unlikely(pspat_debug_xmit)) {
				printf("deq(%p)-->%p\n", q, mbf);
			}
			next_link_idle += picos_per_byte * mbf->len;

			switch (pspat_xmit_mode) {
			case PSPAT_XMIT_MODE_ARB:
				pspat_mark(&arb->active_txqs, mbf);
				break;
			case PSPAT_XMIT_MODE_DISPATCH:
				pspat_arb_dispatch(arb, mbf);
				break;
			default:
				m_free(mbf);
				break;
			}
		}
		pspat_arb_tc_deq += ndeq;

                /* If the traffic on this root qdisc is not enough to fill
                 * the link bandwidth, we need to move next_link_idle
                 * forward, in order to avoid accumulating credits. */
                if (next_link_idle <= now &&
			ndeq < pspat_arb_qdisc_batch) {
                    next_link_idle = now;
                }
//		q->pspat_next_link_idle = next_link_idle;
//	}

	if (pspat_xmit_mode == PSPAT_XMIT_MODE_ARB) {
		pspat_txqs_flush(&arb->active_txqs);
	}

//	rcu_read_unlock_bh();

	/* Update statistics on avg/max cost of the arbiter loop and
	 * per-loop client mailbox processing. */
	picos = now - arb->last_ts;
	arb->last_ts = now;
	arb->num_picos += picos;
	arb->num_reqs += nreqs;
	arb->num_loops++;
	if (unlikely(picos > arb->max_picos)) {
		arb->max_picos = picos;
	}
	if (unlikely(arb->num_loops & PSPAT_ARB_STATS_LOOPS)) {
		pspat_arb_loop_avg_ns =
			(arb->num_picos / PSPAT_ARB_STATS_LOOPS) >> 10;
		pspat_arb_loop_max_ns = arb->max_picos >> 10;
		pspat_arb_loop_avg_reqs = arb->num_reqs / PSPAT_ARB_STATS_LOOPS;
		arb->num_loops = 0;
		arb->num_picos = 0;
		arb->max_picos = 0;
		arb->num_reqs = 0;
	}

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

	/* Also drain the validq of all the active tx queues. */
	n = 0;
//	list_for_each_entry_safe(txq, txq_next, &arb->active_txqs, pspat_active) {
		/* We can't call kfree_mbf_list(), because this function does
		 * not unlink the mbfuffs from the list.
		 * Unlinking is important in case the refcount of some of the
		 * mbfuffs does not go to zero here, that would mean possible
		 * dangling pointers. */
		while (txq->pspat_validq_head != NULL) {
			struct mbuf *next = txq->pspat_validq_head->next;
			txq->pspat_validq_head->next = NULL;
			m_free(txq->pspat_validq_head);
			txq->pspat_validq_head = next;
			n ++;
		}
		txq->pspat_validq_tail = NULL;
//		list_del_init(&txq->pspat_active);
		BUG_ON(txq->pspat_markq_head != NULL ||
			txq->pspat_markq_tail != NULL);
//	}
	printf("%s: Arbiter validq lists drained, found %d mbfs\n", __func__, n);
}

int
pspat_client_handler(struct mbuf *mbf,  struct ifnet *ifp)
{
	int cpu, rc = 0;
	struct pspat_queue *pq;
	struct pspat *arb;

	mbuf->ifp = ifp;

	if (!pspat_enable || arb = pspat_arb == NULL) {
		/* Not our business. */
		return -ENOTTY;
	}

	cpu = curthread->td_oncpu;
	pq = arb->queues + cpu;
	if (pspat_cli_push(pq, mbf)) {
		pspat_stats[cpu].inq_drop++;
		rc = 1;
	}
	if (unlikely(pspat_debug_xmit)) {
		printf("cli_push(%p) --> %d\n", mbf, rc);
	}
	return rc;
}

/* Called on process exit() to clean-up PSPAT mailbox, if any. */
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
//	rcu_read_lock();
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
//	rcu_read_unlock();
	if (curthread->pspat_mb) {
		/* the mailbox is still there */
		if (arb) {
			/* We failed to push PSPAT_LAST_SKB but the
			 * arbiter was running. We must try again.
			 */
			printf("PSPAT Try again to destroy mailbox\n");
//			set_current_state(TASK_INTERRUPTIBLE);
//			schedule_timeout(100);
			kthread_suspend(curthread, 0);
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

	while (ndeq < pspat_dispatch_batch && (mbf = pspat_mb_extract(m)) != NULL) {
		pspat_mark(&s->active_txqs, mbf);
		ndeq ++;
	}

	pspat_dispatch_deq += ndeq;
	pspat_mb_clear(m);
	pspat_txqs_flush(&s->active_txqs);

	if (unlikely(pspat_debug_xmit && ndeq)) {
		printf("PSPAT sender processed %d mbfs\n", ndeq);
	}

	if (pspat_dispatch_sleep_us) {
//		usleep_range(pspat_dispatch_sleep_us, pspat_dispatch_sleep_us);
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

	/* Also drain the validq of all the active tx queues. */
	n = 0;
//	list_for_each_entry_safe(txq, txq_next, &s->active_txqs, pspat_active) {
		/* We can't call kfree_mbf_list(), because this function does
		 * not unlink the mbfuffs from the list.
		 * Unlinking is important in case the refcount of some of the
		 * mbfuffs does not go to zero here, that would mean possible
		 * dangling pointers. */
		while (txq->pspat_validq_head != NULL) {
			struct mbuf *next = txq->pspat_validq_head->next;
			txq->pspat_validq_head->next = NULL;
			m_free(txq->pspat_validq_head);
			txq->pspat_validq_head = next;
			n ++;
		}
		txq->pspat_validq_tail = NULL;
//		list_del_init(&txq->pspat_active);
		BUG_ON(txq->pspat_markq_head != NULL ||
			txq->pspat_markq_tail != NULL);
//	}
	printf("%s: Sender validq lists drained, found %d mbfs\n", __func__, n);
}
