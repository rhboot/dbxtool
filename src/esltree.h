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
#ifndef DBXTOOL_ESLTREE_H
#define DBXTOOL_ESLTREE_H 1

#include <efivar.h>

extern int esl_tree_create(void **rootp, uint8_t *dbx_buf, size_t dbx_len);
extern void esl_tree_destroy(void **rootp);
extern int esl_cmp(const void *l, const void *r);

struct esl_tree_entry {
	efi_guid_t type;
	efi_guid_t owner;
	uint8_t *data;
	size_t datalen;
};

#endif /* DBXTOOL_ESLTREE_H */
