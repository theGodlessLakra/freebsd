#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/smp.h>

#include "pspat.h"

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1 ) / (d))

MALLOC_DEFINE(M_PSPAT, "pspat", "PSPAT Networking Subsystem");

SYSCTL_DECL(_net);

struct pspat *pspat_arb;
static struct pspat *arbp; /* For internal usage */

int pspat_enable __read_mostly = 0;
int pspat_debug_xmit __read_mostly = 0;
int pspat_xmit_mode __read_mostly = PSPAT_XMIT_MODE_ARB;
int arb_thread_stop __read_mostly = 0;
int snd_thread_stop __read_mostly = 0;
unsigned long pspat_rate __read_mostly = 40000000000; // 40Gb/s
unsigned long pspat_arb_interval_ns __read_mostly = 1000;
unsigned int pspat_arb_batch __read_mostly = 512;
unsigned int pspat_dispatch_batch __read_mostly = 256;
unsigned long pspat_arb_backpressure_drop = 0;
unsigned long pspat_arb_dispatch_drop = 0;
unsigned long pspat_dispatch_deq = 0;
unsigned long pspat_arb_loop_avg_ns = 0;
unsigned long pspat_arb_loop_max_ns = 0;
unsigned long pspat_arb_loop_avg_reqs = 0;
unsigned long pspat_mailbox_entries = 512;
unsigned long pspat_mailbox_line_size = 128;
unsigned long *pspat_rounds; /* currently unused */
static unsigned long pspat_pages;

static struct mtx pspat_glock;
static struct sysctl_ctx_list clist;

int (*orig_oid_hanlder)(SYSCTL_HANDLER_ARGS);


static int
pspat_enable_oid_handler(struct sysctl_oid *oidp, void *arg1,
			  intmax_t arg2, struct sysctl_req *req)
{
	int ret = orig_oid_hanlder(oidp, arg1, arg2, req);

	if (ret || !pspat_enable || !arbp) {
		return ret;
	}

	kthread_resume(arbp->arb_thread);
	kthread_resume(arbp->snd_thread);

	return 0;
}

static int
pspat_xmit_mode_oid_handler(struct sysctl_oid *oidp, void *arg1,
			     intmax_t arg2, struct sysctl_req *req)
{
	int ret = orig_oid_hanlder(oidp, arg1, arg2, req);

	if (ret || !pspat_enable || !arbp
			|| pspat_xmit_mode != PSPAT_XMIT_MODE_DISPATCH) {
		return ret;
	}

	kthread_resume(arbp->snd_thread);

	return 0;
}

struct pspat_stats *pspat_stats;

static int
pspat_sysctl_init(void)
{
	int cpus = mp_ncpus, i, n;
	int rc = -ENOMEM;
	void *buf;
	char *name;
	size_t size;

	struct sysctl_oid *pspat_oid;
	struct sysctl_oid *pspat_cpu_oid;
	struct sysctl_oid *oidp, *t;

	pspat_stats = (struct pspat_stats*)malloc(PAGE_SIZE, M_PSPAT, M_WAITOK | M_ZERO); // XXX max 4096/32 cpus
	if (pspat_stats == NULL) {
		printf("pspat: unable to allocate stats page");
		goto out;
	}

	size = (cpus + 1) * sizeof(unsigned long);
	pspat_rounds = malloc(size, M_PSPAT, M_WAITOK);
	if (pspat_rounds == NULL) {
		printf("pspat: unable to allocate rounds counter array\n");
		goto free_stats;
	}

	sysctl_ctx_init(&clist);

	pspat_oid = SYSCTL_ADD_NODE(&clist, SYSCTL_STATIC_CHILDREN(_net),
	    OID_AUTO, "pspat", CTLFLAG_RD, 0, "pspat under net");

	pspat_cpu_oid = SYSCTL_ADD_NODE(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "cpu", CTLFLAG_RD, 0,	"cpu under pspat");

	oidp = SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "enable", CTLFLAG_RW, &pspat_enable, 0,	"enable under pspat");
	orig_oid_hanlder = oidp->oid_handler;
	oidp->oid_handler = &pspat_enable_oid_handler;

	oidp = SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "xmit_mode", CTLFLAG_RW, &pspat_xmit_mode,
	    PSPAT_XMIT_MODE_ARB,	"xmit_mode under pspat");
	oidp->oid_handler = &pspat_xmit_mode_oid_handler;

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "rounds", CTLFLAG_RD, pspat_rounds, 0,
	    "rounds under pspat");

	oidp = SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "debug_xmit", CTLFLAG_RW, &pspat_debug_xmit, 0,
	    "debug_xmit under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_interval_ns", CTLFLAG_RW, &pspat_arb_interval_ns, 1000,
	    "arb_interval_ns under pspat");

	oidp = SYSCTL_ADD_U32(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "dispatch_batch", CTLFLAG_RW, &pspat_dispatch_batch, 256,
	    "dispatch_batch under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "rate", CTLFLAG_RW, &pspat_rate, 40000000000,
	    "rate under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_backpressure_drop", CTLFLAG_RD, &pspat_arb_backpressure_drop, 0,
	    "arb_backpressure_drop under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_dispatch_drop", CTLFLAG_RD, &pspat_arb_dispatch_drop, 0,
	    "arb_dispatch_drop under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "dispatch_deq", CTLFLAG_RD, &pspat_dispatch_deq, 0,
	    "dispatch_deq under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_loop_avg_ns", CTLFLAG_RD, &pspat_arb_loop_avg_ns, 0,
	    "arb_loop_avg_ns under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_loop_max_ns", CTLFLAG_RD, &pspat_arb_loop_max_ns, 0,
	    "arb_loop_max_ns under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "arb_loop_avg_reqs", CTLFLAG_RD, &pspat_arb_loop_avg_reqs, 0,
	    "arb_loop_avg_reqs under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "mailbox_entries", CTLFLAG_RW, &pspat_mailbox_entries, 512,
	    "mailbox_entries under pspat");

	oidp = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_oid),
	    OID_AUTO, "mailbox_line_size", CTLFLAG_RW, &pspat_mailbox_line_size, 128,
	    "mailbox_line_size under pspat");

	size = cpus * 16;  /* space for the syctl names */
	buf = malloc(size, M_PSPAT, M_WAITOK);
	if (buf == NULL) { 
		printf("pspat: not enough space for per-cpu sysctl names");
		goto free_rounds;
	}

	name = buf;

	for (i = 0; i < cpus; i++) {
		n = snprintf(name, 16, "inq-drop-%d", i);

		t = SYSCTL_ADD_U64(&clist, SYSCTL_CHILDREN(pspat_cpu_oid), OID_AUTO, name,
			CTLFLAG_RW, &pspat_stats[i].inq_drop, 0, name);

		name += n + 1;
	}

	return 0;

free_rounds:
	sysctl_ctx_free(&clist);
	free(pspat_rounds, M_PSPAT);
free_stats:
	free((void *)pspat_stats, M_PSPAT);
out:
	return rc;
}

static void
pspat_sysctl_fini(void)
{
	sysctl_ctx_free(&clist);
	if (pspat_rounds)
		free(pspat_rounds, M_PSPAT);
	if (pspat_stats)
		free((void *)pspat_stats, M_PSPAT);
}

static void
arb_worker_func(void *data)
{
	struct pspat *arb = (struct pspat *)data;
	struct timespec ts;
	bool arb_registered = false;

	while (!arb_thread_stop) {
		if (!pspat_enable) {
			if (arb_registered) {
                                /* PSPAT is disabled but arbiter is still
                                 * registered: we need to unregister. */
				mtx_lock(&pspat_glock);
				pspat_shutdown(arb);
				rw_wlock(&pspat_rwlock);
				pspat_arb = NULL;
				rw_wunlock(&pspat_rwlock);
				mtx_unlock(&pspat_glock);
				arb_registered = false;
				printf("PSPAT arbiter unregistered\n");
			}

			kthread_suspend(curthread, 0);

		} else {
			if (!arb_registered) {
				/* PSPAT is enabled but arbiter is not
                                 * registered: we need to register. */
				mtx_lock(&pspat_glock);
				rw_wlock(&pspat_rwlock);
				pspat_arb = arb;
				rw_wunlock(&pspat_rwlock);
				mtx_unlock(&pspat_glock);
				arb_registered = true;
				printf("PSPAT arbiter registered\n");
				nanotime(&ts);
				arb->last_ts = ts.tv_nsec << 10;
				arb->num_loops = 0;
				arb->num_picos = 0;
				arb->max_picos = 0;
			}

			pspat_do_arbiter(arb);
		}
	}

	kthread_exit();
}

static void
snd_worker_func(void *data)
{
	struct pspat_dispatcher *s = (struct pspat_dispatcher *)data;

	while (!snd_thread_stop) {
		if (pspat_xmit_mode != PSPAT_XMIT_MODE_DISPATCH
						|| !pspat_enable) {
			printf("PSPAT dispatcher deactivated\n");
			pspat_dispatcher_shutdown(s);
			kthread_suspend(curthread, 0);
			printf("PSPAT dispatcher activated\n");

		} else
			pspat_do_dispatcher(s);
	}

	kthread_exit();
}

static int
pspat_destroy(void)
{
	mtx_lock(&pspat_glock);
//	BUG_ON(arbp == NULL);

	rw_wlock(&pspat_rwlock);
	pspat_arb = NULL;
	rw_wunlock(&pspat_rwlock);

	if (arbp->arb_thread) {
		arb_thread_stop = 1;
		arbp->arb_thread = NULL;
	}
	if (arbp->snd_thread) {
		snd_thread_stop = 1;
		arbp->snd_thread = NULL;
	}

	pspat_dispatcher_shutdown(&arbp->dispatchers[0]);
	pspat_shutdown(arbp);
	free((void *)arbp, M_PSPAT);
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

	if (curthread->pspat_mb)
		return 0;

	snprintf(name, PSPAT_MB_NAMSZ, "CM-%d", curthread->td_tid);

	err = pspat_mb_new(name, pspat_mailbox_entries, pspat_mailbox_line_size, &m);
	if (err)
		return err;
	if (m == NULL)
		return -ENOMEM;
	curthread->pspat_mb = m;
	return 0;
}

static int
pspat_create(void)
{
	int cpus = mp_ncpus, i;
	int dispatchers = 1;
	struct pspat_mailbox *m;
	unsigned long mb_entries, mb_line_size;
	size_t mb_size, arb_size;
	int ret;

	/* get the curthread-> value of the mailbox parameters */
	mb_entries = pspat_mailbox_entries;
	mb_line_size = pspat_mailbox_line_size;
	mb_size = pspat_mb_size(mb_entries);

	mtx_lock(&pspat_glock);
//	BUG_ON(arbp != NULL);

	arb_size = roundup(sizeof(*arbp) + cpus * sizeof(*arbp->queues),
				CACHE_LINE_SIZE);
	pspat_pages = DIV_ROUND_UP(arb_size + mb_size * (cpus + dispatchers),
				PAGE_SIZE);

	arbp = (struct pspat *)malloc(pspat_pages, M_PSPAT, M_WAITOK | M_ZERO);
	if (!arbp) {
		mtx_unlock(&pspat_glock);
		return -ENOMEM;
	}
	memset(arbp, 0, PAGE_SIZE * pspat_pages);
	arbp->n_queues = cpus;

	/* initialize all mailboxes */
	m = (struct pspat_mailbox *) ((char *)arbp + arb_size);
	for (i = 0; i < cpus; i++) {
		char name[PSPAT_MB_NAMSZ];
		snprintf(name, PSPAT_MB_NAMSZ, "CL-%d", i);
		ret = pspat_mb_init(m, name, mb_entries, mb_line_size);
		if (ret ) {
			goto fail;
		}
		arbp->queues[i].inq = m;
		TAILQ_INIT(&arbp->queues[i].mb_to_clear);
		m = (struct pspat_mailbox *) ((char *)m + mb_size);
	}
	TAILQ_INIT(&arbp->mb_to_delete);

	for (i = 0; i < dispatchers; i++) {
		char name[PSPAT_MB_NAMSZ];
		snprintf(name, PSPAT_MB_NAMSZ, "T-%d", i);
		ret = pspat_mb_init(m, name, mb_entries, mb_line_size);
		if (ret ) {
			goto fail;
		}
		arbp->dispatchers[i].mb = m;
		m = (struct pspat_mailbox *) ((char *)m + mb_size);
	}

	ret = kthread_add(arb_worker_func, arbp, NULL,
		&arbp->arb_thread, 0, 0, "pspat_arbiter_thread");
	if (ret) {
		goto fail;
	}

	ret = kthread_add(snd_worker_func, &arbp->dispatchers[0], NULL,
		&arbp->snd_thread, 0, 0, "pspat_dispatcher_thread");
	if (ret) {
		goto fail2;
	}

	printf("PSPAT arbiter created with %d per-core queues\n",
	       arbp->n_queues);

	mtx_unlock(&pspat_glock);

	kthread_resume(arbp->arb_thread);
	kthread_resume(arbp->snd_thread);

	return 0;
fail2:
	arb_thread_stop = 1;
	arbp->arb_thread = NULL;
fail:
	free((void *)arbp, M_PSPAT);
	mtx_unlock(&pspat_glock);

	return ret;
}

static int
pspat_init(void)
{
	int ret;

	mtx_init(&pspat_glock, "pspat_glock", NULL, MTX_DEF);
	rw_init(&pspat_rwlock,	"pspat_rwlock");

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

static void
pspat_fini(void)
{
	pspat_destroy();
	pspat_sysctl_fini();
	rw_destroy(&pspat_rwlock);
	mtx_destroy(&pspat_glock);
}

static int pspat_module_handler(struct module *module, int event, void *arg) {
        int err = 0;

        switch (event) {
	        case MOD_LOAD:
	                pspat_init();
	                break;
	        case MOD_UNLOAD:
	                pspat_fini();
	                break;
	        default:
	                err = EOPNOTSUPP;
	                break;
        }
        return err;
}

static moduledata_t pspat_data = {
    "pspat",
     pspat_module_handler,
     NULL
};

DECLARE_MODULE(pspat, pspat_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
