/*
 * Copyright 2014 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): Peter Jones <pjones@redhat.com>
 */

#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>
#include <err.h>

#include "eslhtable.h"
#include "iter.h"
#include "util.h"

size_t
esl_htable_hash(const struct esl_hash_entry *elem)
{
	const struct esl_hash_entry *hep = (struct esl_hash_entry *)elem;

	size_t base = 0;
	base = hash((uint8_t *)&hep->type, sizeof(hep->type), base);
	base = hash(hep->data, hep->datalen, base);
	return base;
}

bool
esl_htable_eq(const void *l, void *r)
{
	const struct esl_hash_entry *le = l, *re = r;

	int ret;
	ret = efi_guid_cmp(&le->type, &re->type);
	if (ret != 0)
		return 1;

	if (le->datalen != re->datalen)
		return 1;

	return memcmp(le->data, re->data, re->datalen) == 0;
}

size_t
esl_htable_rehash(const void *elem, void *priv)
{
	return esl_htable_hash(elem);
}

int
esl_htable_create(struct htable *ht, uint8_t *dbx_buf, size_t dbx_len)
{
	esd_iter *iter = NULL;
	int rc;
	int ret = 0;

	if (dbx_len == 0) {
		htable_init(ht, esl_htable_rehash, NULL);
		return 0;
	}

	rc = esd_iter_new(&iter, dbx_buf, dbx_len);
	if (rc < 0)
		err(1, NULL);

	htable_init(ht, esl_htable_rehash, NULL);
	while (1) {
		struct esl_hash_entry *ehp;

		ehp = calloc(1, sizeof (*ehp));
		if (!ehp)
			err(1, NULL);

		rc = esd_iter_next(iter, &ehp->type, &ehp->owner,
					&ehp->data, &ehp->datalen);
		if (rc < 0)
			err(1, NULL);
		if (rc == 0) {
			free(ehp);
			break;
		}

		htable_add(ht, esl_htable_hash(ehp), ehp);
	}

	esd_iter_end(iter);
	return ret;
}

void
esl_htable_destroy(struct htable *ht)
{
	struct htable_iter i;
	struct esl_hash_entry *ehp = NULL;

	ehp = htable_first(ht, &i);
	while (ehp) {
		free(ehp);
		ehp = htable_next(ht, &i);
	}
	htable_clear(ht);
}
