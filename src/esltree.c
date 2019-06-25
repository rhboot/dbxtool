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

#include "fix_coverity.h"

#include <err.h>
#include <search.h>
#include <sys/param.h>

#include "esltree.h"
#include "util.h"

int
esl_cmp(const void *l, const void *r)
{
	const struct esl_tree_entry *le = l, *re = r;
	int ret;

	ret = efi_guid_cmp(&le->type, &re->type);
	if (ret != 0)
		return ret;

	ret = memcmp2(le->data, le->datalen, re->data, re->datalen);
	return ret;
}

int
esl_tree_create(void **rootp, uint8_t *dbx_buf, size_t dbx_len)
{
	efi_secdb_iter *iter = NULL;
	int rc;
	int ret = 0;

	if (dbx_len == 0) {
		esl_tree_destroy(rootp);
		return 0;
	}

	rc = efi_secdb_iter_new(&iter, dbx_buf, dbx_len);
	if (rc < 0)
		err(1, NULL);

	while (1) {
		struct esl_tree_entry *ehp;

		ehp = calloc(1, sizeof (*ehp));
		if (!ehp)
			err(1, NULL);

		rc = efi_secdb_iter_next(iter, &ehp->type, &ehp->owner,
					&ehp->data, &ehp->datalen);
		if (rc < 0)
			err(1, NULL);
		if (rc == 0) {
			free(ehp);
			break;
		}

		tsearch(ehp, rootp, esl_cmp);
	}

	efi_secdb_iter_end(iter);
	return ret;
}

static void
esl_tree_destroy_node(void *nodep)
{
	struct esl_tree_entry *ehp = (struct esl_tree_entry *)nodep;

	free(ehp);
}

void
esl_tree_destroy(void **rootp)
{
	tdestroy(*rootp, esl_tree_destroy_node);
	*rootp = NULL;
}
