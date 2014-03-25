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

#include <err.h>
#include <errno.h>
#include <stdlib.h>

#include "esl.h"
#include "iter.h"

struct esd_iter {
	uint8_t *buf;
	size_t len;

	off_t offset;
	int line;

	EFI_SIGNATURE_LIST *esl;
	EFI_SIGNATURE_DATA *esd;
	size_t nmemb;
	int i;
};

int
esd_iter_new(esd_iter **iter, uint8_t *buf, size_t len)
{
	if (len < sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA)) {
		errno = EINVAL;
		return -1;
	}

	*iter = calloc(1, sizeof (esd_iter));
	if (!*iter)
		err(1, NULL);

	(*iter)->buf = buf;
	(*iter)->len = len;
	(*iter)->i = -1;

	return 0;
}

int
esd_iter_end(esd_iter *iter)
{
	if (!iter) {
		errno = EINVAL;
		return -1;
	}
	free(iter);
	return 0;
}

int
esd_iter_next(esd_iter *iter, efi_guid_t *type, efi_guid_t *owner,
		uint8_t **data, size_t *len)
{
	if (!iter)
		return -EINVAL;
	if (iter->offset >= iter->len)
		return -EINVAL;

	iter->i += 1;
	iter->line += 1;
	if (!iter->esl) {
		iter->esl = (EFI_SIGNATURE_LIST *)iter->buf;
		iter->i = 0;

		iter->nmemb = (iter->esl->SignatureListSize
			       - sizeof (EFI_SIGNATURE_LIST)
			       - iter->esl->SignatureHeaderSize)
			      / iter->esl->SignatureSize;

		iter->esd = (EFI_SIGNATURE_DATA *)((intptr_t)iter->esl
			     + sizeof (EFI_SIGNATURE_LIST)
			     + iter->esl->SignatureHeaderSize);
	} else if (iter->i == iter->nmemb) {
		iter->offset += iter->esl->SignatureListSize;
		if (iter->offset >= iter->len)
			return 1;
		iter->esl = (EFI_SIGNATURE_LIST *)((intptr_t)iter->buf
						+ iter->offset);
		iter->i = 0;
		iter->nmemb = (iter->esl->SignatureListSize
			       - sizeof (EFI_SIGNATURE_LIST)
			       - iter->esl->SignatureHeaderSize)
			      / iter->esl->SignatureSize;
		iter->esd = (EFI_SIGNATURE_DATA *)((intptr_t)iter->esl
			     + sizeof (EFI_SIGNATURE_LIST)
			     + iter->esl->SignatureHeaderSize);
	} else {
		iter->offset += iter->esl->SignatureSize;
		iter->esd = (void *)((intptr_t)iter->esd
				+ iter->esl->SignatureSize);
	}

	*type = iter->esl->SignatureType;
	*owner = iter->esd->SignatureOwner;
	*data = iter->esd->SignatureData;
	*len = iter->esl->SignatureSize - sizeof (iter->esd->SignatureOwner);

	return 0;
}

int
esd_iter_get_line(esd_iter *iter)
{
	if (!iter) {
err:
		errno = EINVAL;
		return -1;
	}

	if (!iter->esl)
		goto err;

	return iter->line;
}

struct esl_iter {
	uint8_t *buf;
	size_t len;

	off_t offset;

	EFI_SIGNATURE_LIST *esl;
};

int esl_iter_new(esl_iter **iter, uint8_t *buf, size_t len)
{
	if (len < sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA)) {
		errno = EINVAL;
		return -1;
	}

	*iter = calloc(1, sizeof (esl_iter));
	if (!*iter)
		err(1, NULL);

	(*iter)->buf = buf;
	(*iter)->len = len;

	return 0;
}

int esl_iter_end(esl_iter *iter)
{
	if (!iter) {
		errno = EINVAL;
		return -1;
	}
	free(iter);
	return 0;
}

int esl_iter_next(esl_iter *iter, efi_guid_t *type,
		EFI_SIGNATURE_DATA **data, size_t *len)
{
	if (!iter)
		return -EINVAL;
	if (iter->offset >= iter->len)
		return -EINVAL;

	if (!iter->esl) {
		iter->esl = (EFI_SIGNATURE_LIST *)iter->buf;
	} else {
		iter->offset += iter->esl->SignatureListSize;
		if (iter->offset >= iter->len)
			return 1;
		iter->esl = (EFI_SIGNATURE_LIST *)((intptr_t)iter->buf
						+ iter->offset);

	}
	*type = iter->esl->SignatureType;
	*data = (EFI_SIGNATURE_DATA *)((intptr_t)iter->esl
			+ sizeof (EFI_SIGNATURE_LIST)
			+ iter->esl->SignatureHeaderSize);
	*len = iter->esl->SignatureListSize - sizeof (EFI_SIGNATURE_LIST);

	return 0;
}
