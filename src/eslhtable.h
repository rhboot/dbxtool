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
#ifndef DBXTOOL_ESLHTABLE_H
#define DBXTOOL_ESLHTABLE_H 1

#include <ccan/htable/htable.h>
#include <efivar.h>

extern int esl_htable_create(struct htable *ht, uint8_t *dbx_buf, size_t dbx_len);
extern void esl_htable_destroy(struct htable *ht);

struct esl_hash_entry {
	efi_guid_t type;
	efi_guid_t owner;
	uint8_t *data;
	size_t datalen;
};

extern size_t esl_htable_hash(const struct esl_hash_entry *elem);
extern bool esl_htable_eq(const void *l, void *r);

#endif /* DBXTOOL_ESLHTABLE_H */
