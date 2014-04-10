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

typedef struct {
	uint16_t	Year;	/* 1998-20xx */
	uint8_t		Month;	/* 1-12 */
	uint8_t		Day;	/* 1-31 */
	uint8_t		Hour;	/* 0-23 */
	uint8_t		Minute;	/* 0-59 */
	uint8_t		Second;	/* 0-59 */
	uint8_t		pad1;
	uint32_t	Nanosecond;	/* 0 - 999999999 */
	int16_t		TimeZone;	/* -1440 to 1440 or 0x7ff */
	uint8_t		Daylight;	/* bitmask, see below */
	uint8_t		pad2;
} __attribute__((aligned (1))) EFI_TIME;

#define EFI_TIME_ADJUST_DAYLIGHT	0x01
#define EFI_TIME_IN_DAYLIGHT		0x02

#define EFI_UNSPECIFIED_TIMEZONE	0x07ff

typedef struct _EFI_CERT_BLOCK_RSA_2048_SHA256 {
	efi_guid_t	HashType;
	uint8_t		PublicKey[256];
	uint8_t		Signature[256];
} __attribute__((aligned (1))) EFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct {
	uint32_t	dwLength;
	uint16_t	wRevision;
	uint16_t	wCertificateType;
	uint8_t		bCertificate[0];
} __attribute__((aligned (1))) WIN_CERTIFICATE;

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
#define WIN_CERT_TYPE_EFI_PKCS115	0x0ef0
#define WIN_CERT_TYPE_EFI_GUID		0x0ef1

typedef struct {
	WIN_CERTIFICATE	Hdr;
	efi_guid_t	CertType;
	// uint8_t CertData[0];
} __attribute__((aligned (1))) WIN_CERTIFICATE_UEFI_GUID;

typedef struct {
	uint64_t			MonotonicCount;
	WIN_CERTIFICATE_UEFI_GUID	AuthInfo;
} __attribute__((aligned (1))) EFI_VARIABLE_AUTHENTICATION;

typedef struct {
	EFI_TIME			TimeStamp;
	WIN_CERTIFICATE_UEFI_GUID	AuthInfo;
} __attribute__((aligned (1))) EFI_VARIABLE_AUTHENTICATION_2;

#endif /* ESL_H */
