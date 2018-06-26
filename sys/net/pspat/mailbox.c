#include "mailbox.h"

#define is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))

MALLOC_DEFINE(M_MB, "mailbox", "IFFQ Mailbox Implementation");

int
pspat_mb_new(const char *name, unsigned long entries, unsigned long line_size,
		struct pspat_mailbox **m)
{
	int err;

	*m = malloc(pspat_mb_size(entries), M_MB, M_WAITOK);
	if (*m == NULL)
		return -ENOMEM;

	err = pspat_mb_init(m, name, entries, line_size);
	if (err) {
		free(*m, M_MB);
		return err;
	}

	return 0;
}

int
pspat_mb_init(struct pspat_mailbox *m, const char *name,
		unsigned long entries, unsigned long line_size)
{
	unsigned long entries_per_line;

	if (!is_power_of_2(entries) || !is_power_of_2(line_size) ||
			entries * sizeof(void *) <= 2 * line_size || line_size < sizeof(void *))
		return -EINVAL;

	strncpy(m->name, name, PSPAT_MB_NAMSZ);
	m->name[PSPAT_MB_NAMSZ - 1 ] = '\0';

	entries_per_line = line_size / sizeof(void *);

	m->line_entries = entries_per_line;
	m->line_mask = ~(entries_per_line - 1);
	m->entry_mask = entries - 1;

#ifdef PSPAT_MB_DEBUG
	printf("PSPAT: mb %p %s: line_entries %lu line_mask %lx entry_mask %lx\n",
		m, m->name, m->line_entries, m->line_mask, m->entry_mask);
#endif

	m->cons_clear = 0;
	m->cons_read = m->line_entries;
	m->prod_write = m->line_entries;
	m->prod_check = 2 * m->line_entries;

	unsigned initial_clear = m->cons_clear;
	/* Fill the first cacheline with a garbage value */
	while(initial_clear != m->cons_read) {
		m->q[initial_clear & m->entry_mask] = 0x1;
		initial_clear++;
	}

	/* Initialize the TAILQ list entry */
	ENTRY_INIT(&m->entry);
	m->entry.mb = m;

	return 0;
}

void
pspat_mb_delete(struct pspat_mailbox *m)
{
#ifdef PSPAT_MB_DEBUG
	printf("PSPAT: deleting mb %s\n", m->name);
#endif
	free(m, M_MB);
}


void
pspat_mb_dump_state(struct pspat_mailbox *m)
{
	printf("%s: cc %lu, cr %lu, pw %lu, pc %lu\n", m->name,
		m->cons_clear, m->cons_read, m->prod_write, m->prod_check);
}
