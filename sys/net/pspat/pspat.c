#include <sys/types.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/lockmgr.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/smp.h>
#include <sys/proc.h>

#include "pspat.h"

MALLOC_DEFINE(M_PSPAT, "pspat", "PSPAT Networking Subsystem");

static struct mtx pspat_glock;
struct pspat *pspat_arb;  /* RCU-dereferenced */
static struct pspat *arbp; /* For internal usage */

int pspat_enable __read_mostly = 0;
int pspat_debug_xmit __read_mostly = 0;
int pspat_xmit_mode __read_mostly = PSPAT_XMIT_MODE_ARB;
int pspat_single_txq __read_mostly = 1; /* use only one hw queue */
int pspat_tc_bypass __read_mostly = 0;
u64 pspat_rate __read_mostly = 40000000000; // 40Gb/s
u64 pspat_arb_interval_ns __read_mostly = 1000;
u32 pspat_arb_qdisc_batch __read_mostly = 512;
u32 pspat_dispatch_batch __read_mostly = 256;
u32 pspat_dispatch_sleep_us __read_mostly = 0;
u64 pspat_arb_tc_enq_drop = 0;
u64 pspat_arb_backpressure_drop = 0;
u64 pspat_arb_tc_deq = 0;
u64 pspat_arb_dispatch_drop = 0;
u64 pspat_dispatch_deq = 0;
u64 pspat_arb_loop_avg_ns = 0;
u64 pspat_arb_loop_max_ns = 0;
u64 pspat_arb_loop_avg_reqs = 0;
u64 pspat_mailbox_entries = 512;
u64 pspat_mailbox_line_size = 128;
u64 *pspat_rounds; /* currently unused */
static int pspat_zero = 0;
static int pspat_one = 1;
static int pspat_two = 2;
static unsigned long pspat_ulongzero = 0UL;
static unsigned long pspat_ulongone = 1UL;
static unsigned long pspat_ulongmax = (unsigned long)-1;
static struct ctl_table_header *pspat_sysctl_hdr;
static unsigned long pspat_pages;


static int
pspat_enable_oid_handler(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret || !write || !pspat_enable || !arbp) {
		return ret;
	}

	wake_up_process(arbp->arb_thread);
	wake_up_process(arbp->snd_thread);

	return 0;
}

static int
pspat_xmit_mode_oid_handler(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret || !write || !pspat_enable || !arbp
			|| pspat_xmit_mode != PSPAT_XMIT_MODE_DISPATCH) {
		return ret;
	}

	wake_up_process(arbp->snd_thread);

	return 0;
}

static struct sysctl_oid pspat_static_ctl[] = {
	{
		.oid_name	= "cpu",
//		.mode		= 0444,
//		.child		= NULL, /* created at run-time */
	},
	{
		.oid_name	= "rounds",
		/* .maxlen	computed at runtime */
//		.mode		= 0444,
		/* .oid_arg1	computed at runtime */
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "enable",
//		.maxlen		= sizeof(int),
//		.mode		= 0644,
		.oid_arg1		= &pspat_enable,
		.oid_handler	= &pspat_enable_oid_handler,
//		.extra1		= &pspat_zero,
//		.extra2		= &pspat_one,
	},
	{
		.oid_name	= "debug_xmit",
//		.maxlen		= sizeof(int),
//		.mode		= 0644,
		.oid_arg1		= &pspat_debug_xmit,
		.oid_handler	= &proc_dointvec_minmax,
//		.extra1		= &pspat_zero,
//		.extra2		= &pspat_one,
	},
	{
		.oid_name	= "xmit_mode",
//		.maxlen		= sizeof(int),
//		.mode		= 0644,
		.oid_arg1		= &pspat_xmit_mode,
		.oid_handler	= &pspat_xmit_mode_oid_handler,
//		.extra1		= &pspat_zero,
//		.extra2		= &pspat_two,
	},
	{
		.oid_name	= "single_txq",
//		.maxlen		= sizeof(int),
//		.mode		= 0644,
		.oid_arg1		= &pspat_single_txq,
		.oid_handler	= &proc_dointvec_minmax,
//		.extra1		= &pspat_zero,
//		.extra2		= &pspat_two,
	},
	{
		.oid_name	= "tc_bypass",
//		.maxlen		= sizeof(int),
//		.mode		= 0644,
		.oid_arg1		= &pspat_tc_bypass,
		.oid_handler	= &proc_dointvec_minmax,
//		.extra1		= &pspat_zero,
//		.extra2		= &pspat_one,
	},
	{
		.oid_name	= "arb_interval_ns",
//		.maxlen		= sizeof(u64),
//		.mode		= 0644,
		.oid_arg1		= &pspat_arb_interval_ns,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_qdisc_batch",
//		.maxlen		= sizeof(u32),
//		.mode		= 0644,
		.oid_arg1		= &pspat_arb_qdisc_batch,
		.oid_handler	= &proc_dointvec,
	},
	{
		.oid_name	= "dispatch_batch",
//		.maxlen		= sizeof(u32),
//		.mode		= 0644,
		.oid_arg1		= &pspat_dispatch_batch,
		.oid_handler	= &proc_dointvec,
	},
	{
		.oid_name	= "dispatch_sleep_us",
//		.maxlen		= sizeof(u32),
//		.mode		= 0644,
		.oid_arg1		= &pspat_dispatch_sleep_us,
		.oid_handler	= &proc_dointvec,
	},
	{
		.oid_name	= "rate",
//		.maxlen		= sizeof(u64),
//		.mode		= 0644,
		.oid_arg1		= &pspat_rate,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongone,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_tc_enq_drop",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_tc_enq_drop,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_backpressure_drop",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_backpressure_drop,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_tc_deq",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_tc_deq,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_dispatch_drop",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_dispatch_drop,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "dispatch_deq",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_dispatch_deq,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_loop_avg_ns",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_loop_avg_ns,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_loop_max_ns",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_loop_max_ns,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "arb_loop_avg_reqs",
//		.maxlen		= sizeof(u64),
//		.mode		= 0444,
		.oid_arg1		= &pspat_arb_loop_avg_reqs,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "mailbox_entries",
//		.maxlen		= sizeof(u64),
//		.mode		= 0644,
		.oid_arg1		= &pspat_mailbox_entries,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{
		.oid_name	= "mailbox_line_size",
//		.maxlen		= sizeof(u64),
//		.mode		= 0644,
		.oid_arg1		= &pspat_mailbox_line_size,
		.oid_handler	= &proc_doulongvec_minmax,
//		.extra1		= &pspat_ulongzero,
//		.extra2		= &pspat_ulongmax,
	},
	{}
};

static struct sysctl_oid pspat_root[] = {
	{
		.oid_name	= "pspat",
//		.mode		= 0444,
//		.child		= pspat_static_ctl,
	},
	{}
};

static struct sysctl_oid pspat_parent[] = {
	{
		.oid_name	= "net",
//		.mode		= 0444,
//		.child		= pspat_root,
	},
	{}
};

struct pspat_stats *pspat_stats;

static int
pspat_sysctl_init(void)
{
	int cpus = mp_ncpus, i, n;
	int rc = -ENOMEM;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *t, *leaves;
	void *buf;
	char *name;
	size_t size, extra_size;

	pspat_stats = (struct pspat_stats*)malloc(PAGE_SIZE, M_PSPAT, M_WAITOK | M_ZERO); // XXX max 4096/32 cpus
	if (pspat_stats == NULL) {
		printf(KERN_WARNING "pspat: unable to allocate stats page");
		goto out;
	}

	size = (cpus + 1) * sizeof(u64);
	pspat_rounds = malloc(size, M_PSPAT, M_WAITOK);
	if (pspat_rounds == NULL) {
		printf(KERN_WARNING "pspat: unable to allocate rounds counter array\n");
		goto free_stats;
	}
	pspat_static_ctl[1].oid_arg1 = pspat_rounds;
//	pspat_static_ctl[1].maxlen = size;

    extra_size = cpus * 16 /* space for the syctl names */,
	size = extra_size + sizeof(struct sysctl_oid) * (cpus + 1);
	buf = malloc(size, M_PSPAT, M_WAITOK);
	if (buf == NULL) {
		printf(KERN_WARNING "pspat: unable to allocate sysctls");
		goto free_rounds;
	}
	name = buf;
	leaves = buf + extra_size;

	for (i = 0; i < cpus; i++) {
		t = leaves + i;

		n = snprintf(name, extra_size, "inq-drop-%d", i);
		if (n >= extra_size) { /* truncated */
			printf(KERN_WARNING "pspat: not enough space for per-cpu sysctl names");
			goto free_leaves;
		}
		t->oid_name	= name;
		name += n + 1;
		extra_size -= n + 1;

//		t->maxlen	= sizeof(unsigned long);
//		t->mode		= 0644;
		t->oid_arg1		= &pspat_stats[i].inq_drop;
		t->oid_handler	= &proc_doulongvec_minmax;
//		t->extra1	= &pspat_ulongzero;
//		t->extra2	= &pspat_ulongmax;
	}
//	pspat_static_ctl[0].child = leaves;
//	pspat_sysctl_hdr = register_sysctl_table(pspat_parent);

	return 0;

free_leaves:
	free(buf, M_PSPAT);
free_rounds:
	free(pspat_rounds, M_PSPAT);
free_stats:
	free((unsigned long)pspat_stats, M_PSPAT);
out:
	return rc;
}

static void
pspat_sysctl_fini(void)
{
	if (pspat_sysctl_hdr)
//		unregister_sysctl_table(pspat_sysctl_hdr);
	if (pspat_static_ctl[0].child)
		free(pspat_static_ctl[0].child);
	if (pspat_rounds)
		free(pspat_rounds, M_PSPAT);
	if (pspat_stats)
		free((unsigned long)pspat_stats, M_PSPAT);
}

/* Hook exported by net/core/dev.c */
extern int (*pspat_handler)(struct sk_buff *, struct Qdisc *,
			    struct net_device *,
			    struct netdev_queue *);

static int
arb_worker_func(void *data)
{
	struct pspat *arb = (struct pspat *)data;
	bool arb_registered = false;

	while (!kthread_should_stop()) {
		if (!pspat_enable) {
			if (arb_registered) {
                                /* PSPAT is disabled but arbiter is still
                                 * registered: we need to unregister. */
				mtx_lock(&pspat_glock);
				pspat_shutdown(arb);
				rcu_assign_pointer(pspat_arb, NULL);
				synchronize_rcu();
				mtx_unlock(&pspat_glock);
				arb_registered = false;
				printf("PSPAT arbiter unregistered\n");
			}

			set_current_state(TASK_INTERRUPTIBLE);
			schedule();

		} else {
			if (!arb_registered) {
				/* PSPAT is enabled but arbiter is not
                                 * registered: we need to register. */
				mtx_lock(&pspat_glock);
				rcu_assign_pointer(pspat_arb, arb);
				synchronize_rcu();
				mtx_unlock(&pspat_glock);
				arb_registered = true;
				printf("PSPAT arbiter registered\n");
				arb->last_ts = ktime_get_ns() << 10;
				arb->num_loops = 0;
				arb->num_picos = 0;
				arb->max_picos = 0;
			}

			pspat_do_arbiter(arb);
			if (need_resched()) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(1);
			}
		}
	}

	return 0;
}

static int
snd_worker_func(void *data)
{
	struct pspat_dispatcher *s = (struct pspat_dispatcher *)data;

	while (!kthread_should_stop()) {
		if (pspat_xmit_mode != PSPAT_XMIT_MODE_DISPATCH
						|| !pspat_enable) {
			printf("PSPAT dispatcher deactivated\n");
			pspat_dispatcher_shutdown(s);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			printf("PSPAT dispatcher activated\n");

		} else {
			pspat_do_dispatcher(s);
			if (need_resched()) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(1);
			}
		}
	}

	return 0;
}

static int
pspat_destroy(void)
{
	mtx_lock(&pspat_glock);
	BUG_ON(arbp == NULL);

	/* Unregister the arbiter. */
	rcu_assign_pointer(pspat_arb, NULL);
	synchronize_rcu();

	if (arbp->arb_thread) {
		kthread_stop(arbp->arb_thread);
		arbp->arb_thread = NULL;
	}
	if (arbp->snd_thread) {
		kthread_stop(arbp->snd_thread);
		arbp->snd_thread = NULL;
	}

	pspat_dispatcher_shutdown(&arbp->dispatchers[0]);
	pspat_shutdown(arbp);
	free_pages((unsigned long)arbp, order_base_2(pspat_pages));
	arbp = NULL;

	printf("PSPAT arbiter destroyed\n");
	mtx_unlock(&pspat_glock);

	return 0;
}

int
pspat_create_client_queue(void)
{
	struct pspat_mailbox *m;
	char name[PSPAT_MB_NAMSZ];
	int err;

	if (current->pspat_mb)
		return 0;

	snprintf(name, PSPAT_MB_NAMSZ, "CM-%d", current->pid);

	err = pspat_mb_new(name, pspat_mailbox_entries, pspat_mailbox_line_size, &m);
	if (err)
		return err;
	if (m == NULL)
		return -ENOMEM;
	current->pspat_mb = m;
	return 0;
}

static int
pspat_bypass_enqueue(struct sk_buff *skb, struct Qdisc *q, struct sk_buff **to_free)
{
	return qdisc_enqueue_tail(skb, q);
}

static struct sk_buff *
pspat_bypass_dequeue(struct Qdisc *q)
{
	return qdisc_dequeue_head(q);
}

static struct lock_class_key qdisc_tx_busylock;
static struct lock_class_key qdisc_running_key;

static int
pspat_create(void)
{
	int cpus = mp_ncpus, i;
	int dispatchers = 1;
	struct pspat_mailbox *m;
	unsigned long mb_entries, mb_line_size;
	size_t mb_size, arb_size;
	int ret;

	/* get the current value of the mailbox parameters */
	mb_entries = pspat_mailbox_entries;
	mb_line_size = pspat_mailbox_line_size;
	mb_size = pspat_mb_size(mb_entries);

	mtx_lock(&pspat_glock);
	BUG_ON(arbp != NULL);

	arb_size = roundup(sizeof(*arbp) + cpus * sizeof(*arbp->queues),
				INTERNODE_CACHE_BYTES);
	pspat_pages = DIV_ROUND_UP(arb_size + mb_size * (cpus + dispatchers),
				PAGE_SIZE);

	arbp = (struct pspat *)__get_free_pages(GFP_KERNEL, order_base_2(pspat_pages));
	if (!arbp) {
		mtx_unlock(&pspat_glock);
		return -ENOMEM;
	}
	memset(arbp, 0, PAGE_SIZE * pspat_pages);
	arbp->n_queues = cpus;

	/* initialize all mailboxes */
	m = (void *)arbp + arb_size;
	for (i = 0; i < cpus; i++) {
		char name[PSPAT_MB_NAMSZ];
		snprintf(name, PSPAT_MB_NAMSZ, "CL-%d", i);
		ret = pspat_mb_init(m, name, mb_entries, mb_line_size);
		if (ret ) {
			goto fail;
		}
		arbp->queues[i].inq = m;
		INIT_LIST_HEAD(&arbp->queues[i].mb_to_clear);
		m = (void *)m + mb_size;
	}
	INIT_LIST_HEAD(&arbp->mb_to_delete);
	INIT_LIST_HEAD(&arbp->active_txqs);

	for (i = 0; i < dispatchers; i++) {
		char name[PSPAT_MB_NAMSZ];
		snprintf(name, PSPAT_MB_NAMSZ, "T-%d", i);
		ret = pspat_mb_init(m, name, mb_entries, mb_line_size);
		if (ret ) {
			goto fail;
		}
		arbp->dispatchers[i].mb = m;
		INIT_LIST_HEAD(&arbp->dispatchers[i].active_txqs);
		m = (void *)m + mb_size;
	}

	/* Initialize bypass qdisc. */
	arbp->bypass_qdisc.enqueue = pspat_bypass_enqueue;
	arbp->bypass_qdisc.dequeue = pspat_bypass_dequeue;
	qdisc_skb_head_init(&arbp->bypass_qdisc.q);
	spin_lock_init(&arbp->bypass_qdisc.q.lock);
	spin_lock_init(&arbp->bypass_qdisc.busylock);
	lockdep_set_class(&arbp->bypass_qdisc.busylock, &qdisc_tx_busylock);
	seqcount_init(&arbp->bypass_qdisc.running);
	lockdep_set_class(&arbp->bypass_qdisc.running, &qdisc_running_key);
	refcount_set(&arbp->bypass_qdisc.refcnt, 1);
	arbp->bypass_qdisc.pspat_owned = 0;
	arbp->bypass_qdisc.state = 0;

	arbp->arb_thread = kthread_create(arb_worker_func, arbp, "pspat-arb");
	if (IS_ERR(arbp->arb_thread)) {
		ret = -PTR_ERR(arbp->arb_thread);
		goto fail;
	}

	arbp->snd_thread = kthread_create(snd_worker_func, &arbp->dispatchers[0],
					"pspat-snd");
	if (IS_ERR(arbp->snd_thread)) {
		ret = -PTR_ERR(arbp->snd_thread);
		goto fail2;
	}

	printf("PSPAT arbiter created with %d per-core queues\n",
	       arbp->n_queues);

	mtx_unlock(&pspat_glock);

	wake_up_process(arbp->arb_thread);
	wake_up_process(arbp->snd_thread);

	return 0;
fail2:
	kthread_stop(arbp->arb_thread);
	arbp->arb_thread = NULL;
fail:
	free_pages((unsigned long)arbp, order_base_2(pspat_pages));
	mtx_unlock(&pspat_glock);

	return ret;
}

static int __init
pspat_init(void)
{
	int ret;

	mtx_init(&pspat_glock, "pspat_glock", NULL, MTX_DEF);

	ret = pspat_sysctl_init();
	if (ret) {
		printf("pspat_sysctl_init() failed\n");
		return ret;
	}

	ret = pspat_create();
	if (ret) {
		printf("Failed to create arbiter\n");
		goto err1;
	}

	return 0;
err1:
	pspat_sysctl_fini();

	return ret;
}

static void __exit
pspat_fini(void)
{
	pspat_destroy();
	pspat_sysctl_fini();
	mtx_destroy(&pspat_glock);
}

module_init(pspat_init);
module_exit(pspat_fini);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Giuseppe Lettieri <g.lettieri@iet.unipi.it");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
MODULE_AUTHOR("Luigi Rizzo <rizzo@iet.unipi.it>");
