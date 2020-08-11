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
#ifndef DBXTOOL_ITER_H
#define DBXTOOL_ITER_H 1

#include <efivar.h>
#include <stdint.h>
#include <unistd.h>

#include "esl.h"

typedef struct esd_iter esd_iter;

extern int esd_iter_new(esd_iter **iter, uint8_t *buf, size_t len);
extern int esd_iter_end(esd_iter *iter);
extern int esd_iter_next(esd_iter *iter, efi_guid_t *type,
	efi_guid_t *owner, uint8_t **data, size_t *len);
extern int esd_iter_get_line(esd_iter *iter);

typedef struct esl_iter esl_iter;
extern int esl_iter_new(esl_iter **iter, uint8_t *buf, size_t len);
extern int esl_iter_end(esl_iter *iter);
extern int esl_iter_next(esl_iter *iter, efi_guid_t *type,
	EFI_SIGNATURE_DATA **data, size_t *len);
extern int esl_list_size(esl_iter *iter, size_t *sls);
extern int esl_header_size(esl_iter *iter, size_t *slh);
extern int esl_sig_size(esl_iter *iter, size_t *ss);
extern int esl_get_type(esl_iter *iter, efi_guid_t *type);

#endif /* DBXTOOL_ITER_H */
