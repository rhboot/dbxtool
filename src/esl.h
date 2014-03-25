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
#ifndef ESL_H
#define ESL_H 1

#include <efivar.h>

typedef struct {
	efi_guid_t	SignatureOwner;
	uint8_t		SignatureData[0];
} EFI_SIGNATURE_DATA;

typedef struct {
	efi_guid_t	SignatureType;
	uint32_t	SignatureListSize;
	uint32_t	SignatureHeaderSize;
	uint32_t	SignatureSize;
} EFI_SIGNATURE_LIST;

#endif /* ESL_H */
