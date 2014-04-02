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

#include <efivar.h>
#include <err.h>
#include <fcntl.h>
#include <popt.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "esl.h"
#include "iter.h"
#include "util.h"

#define ACTION_LIST	0x1

typedef struct {
	char *dbx_file;
	int action;
} dbxtool_ctx;

static void
print_hex(uint8_t *data, size_t len)
{
	char hex[] = "0123456789abcdef";
	for (int i = 0; i < len; i++)
		printf("%c%c", hex[(data[i] & 0xf0) >> 4],
			       hex[(data[i] & 0x0f) >> 0]);
}

int
dump_dbx(uint8_t *buf, size_t len)
{
	int rc;
	esd_iter *iter = NULL;

	rc = esd_iter_new(&iter, buf, len);
	if (rc < 0)
		err(1, NULL);

	while (1) {
		efi_guid_t type;
		efi_guid_t owner;
		uint8_t *data;
		size_t datalen;

		rc = esd_iter_next(iter, &type, &owner, &data, &datalen);
		if (rc < 0)
			err(1, NULL);
		if (rc == 0)
			break;


		char *typestr = NULL;
		int rc = efi_guid_to_symbol(&type, &typestr);
		if (rc < 0)
			err(1, "bad type guid");

		char *ownerstr;
		rc = efi_guid_to_symbol(&owner, &ownerstr);
		if (rc < 0)
			err(1, "bad owner guid");

		printf("%4d: %s %s ", esd_iter_get_line(iter),
						ownerstr, typestr);
		print_hex(data, datalen);
		printf("\n");

		free(typestr);
		free(ownerstr);
	}

	esd_iter_end(iter);
	return 0;
}

typedef enum {
	ft_unknown,
	ft_dbx,
	ft_dbx_noattr,
	ft_append_timestamp,
	ft_append_monotonic
} filetype;

static inline int
is_empty_guid(efi_guid_t *guid)
{
	if (memcmp(guid,&efi_guid_empty,sizeof (efi_guid_t)) == 0)
		return 1;
	return 0;
}

static inline int
guidcmp(efi_guid_t *a, efi_guid_t *b)
{
	return memcmp(a, b, sizeof (efi_guid_t));
}

static filetype
guess_file_type(uint8_t *buf, size_t buflen)
{
	EFI_VARIABLE_AUTHENTICATION_2 va2;
	EFI_VARIABLE_AUTHENTICATION va;

	efi_guid_t guids[] = {
		efi_guid_pkcs7_cert,
		efi_guid_rsa2048_sha256_cert,
		efi_guid_empty
	};

	efi_guid_t esl_guids[] = {
		efi_guid_sha256,
		efi_guid_rsa2048,
		efi_guid_rsa2048_sha256,
		efi_guid_sha1,
		efi_guid_x509_cert,
		efi_guid_sha224,
		efi_guid_sha384,
		efi_guid_sha512,
		efi_guid_x509_sha256,
		efi_guid_empty
	};

	if (buflen >= sizeof (va2)) {
		memcpy(&va2, buf, sizeof(va2));
		for (int i = 0; is_empty_guid(&guids[i]) == 0; i++) {
			if (!guidcmp(&guids[i], &va2.AuthInfo.CertType)) {
				//printf("Found EFI_AUTHENTICATION_2\n");
#if 0
				printf("time is %4d-%02d-%02d %d:%d:%d\n",
					va2.TimeStamp.Year,
					va2.TimeStamp.Month,
					va2.TimeStamp.Day,
					va2.TimeStamp.Hour,
					va2.TimeStamp.Minute,
					va2.TimeStamp.Second);
#endif
				return ft_append_timestamp;
			}
		}
	}

	if (buflen >= sizeof (va)) {
		memcpy(&va, buf, sizeof(va));
		for (int i = 0; is_empty_guid(&guids[i]) == 0; i++) {
			if (!guidcmp(&guids[i], &va2.AuthInfo.CertType)) {
				//printf("Found EFI_AUTHENTICATION\n");
				return ft_append_monotonic;
			}
		}
	}

	/* if we get a file that's just dd-ed from sysfs,
	 * it'll have some attribute bits at the beginning */
	if ((buf[0] &
			~(EFI_VARIABLE_NON_VOLATILE|
			  EFI_VARIABLE_BOOTSERVICE_ACCESS|
			  EFI_VARIABLE_RUNTIME_ACCESS|
			  EFI_VARIABLE_HARDWARE_ERROR_RECORD|
			  EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS|
			  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|
			  EFI_VARIABLE_APPEND_WRITE)) == 0 &&
			buf[1] == 0 &&
			buf[2] == 0 &&
			buf[3] == 0 &&
			buflen > (4 + sizeof (EFI_SIGNATURE_LIST))) {
		EFI_SIGNATURE_LIST esl;
		memcpy(&esl, buf + 4, sizeof (EFI_SIGNATURE_LIST));
		for (int i = 0; is_empty_guid(&guids[i]) == 0; i++) {
			if (!guidcmp(&esl_guids[i], &esl.SignatureType)) {
				//printf("Found EFI_SIGNATURE_LIST from sysfs\n");
				return ft_dbx;
			}
		}
	}

	EFI_SIGNATURE_LIST esl;
	memcpy(&esl, buf, sizeof (EFI_SIGNATURE_LIST));
	for (int i = 0; is_empty_guid(&guids[i]) == 0; i++) {
		if (!guidcmp(&esl_guids[i], &esl.SignatureType)) {
			//printf("Found EFI_SIGNATURE_LIST not from sysfs\n");
			return ft_dbx_noattr;
		}
	}

	//printf("what the hell\n");
	return ft_unknown;
}

int
main(int argc, char *argv[])
{
	int rc;
	uint32_t action = 0;

	dbxtool_ctx ctx = { 0 };
	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "dbxtool" },
		{"dbx", 'd', POPT_ARG_STRING,
			&ctx.dbx_file, 0, "specify dbx database file",
			"<dbxfile>"},
		{"list", 'l', POPT_ARG_VAL|POPT_ARGFLAG_OR,
			&action, ACTION_LIST,
			"list entries in dbx", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("dbxtool", argc, (const char **)argv,
				options, 0);

	rc = poptReadDefaultConfig(optCon, 0);
        if (rc < 0)
		errx(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "Invalid argument: \"%s\": %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "Invalid argument: \"%s\"",
			poptPeekArg(optCon));

	poptFreeContext(optCon);

	uint8_t *dbx_buffer = NULL;
	size_t dbx_len = 0;
	uint32_t attributes = 0;
	if (ctx.dbx_file != NULL) {
		int fd = open(ctx.dbx_file, O_RDONLY);
		if (fd < 0)
			err(1, "Could not open file \"%s\"", ctx.dbx_file);

		rc = read_file(fd, (char **)&dbx_buffer, &dbx_len);
		if (rc < 0)
			err(1, "Could not read file \"%s\"", ctx.dbx_file);

		close(fd);

		filetype ft = guess_file_type(dbx_buffer, dbx_len);
		switch (ft) {
			case ft_unknown:
				err(1, "Unknown file type");
				break;
			case ft_dbx:
				attributes = dbx_buffer[0];
				uint8_t *tmp = malloc(dbx_len - 4);
				if (!tmp)
					err(1, "%m");

				memmove(tmp, dbx_buffer + 4, dbx_len - 4);
				free(dbx_buffer);
				dbx_buffer = tmp;
				dbx_len -= 4;
				break;
			case ft_dbx_noattr:
				attributes =
					EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS |
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_NON_VOLATILE;
				break;
			default:
				errno = EINVAL;
				err(1, "Sorry, can't handle this yet");
				break;
		}
#if 0

		/* if we get a file that's just dd-ed from sysfs,
		 * it'll have some attribute bits at the beginning */
		if ((dbx_buffer[0] &
				~(EFI_VARIABLE_NON_VOLATILE|
				  EFI_VARIABLE_BOOTSERVICE_ACCESS|
				  EFI_VARIABLE_RUNTIME_ACCESS|
				  EFI_VARIABLE_HARDWARE_ERROR_RECORD|
				  EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS|
				  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|
				  EFI_VARIABLE_APPEND_WRITE)) == 0 &&
				dbx_buffer[1] == 0 &&
				dbx_buffer[2] == 0 &&
				dbx_buffer[3] == 0 &&
				dbx_len > 4) {
		}
#endif
	} else {
		if (!efi_variables_supported())
			errx(1, "EFI variables are not supported on this "
				"machine, and no dbx file was specified");

		efi_guid_t security_guid;

		rc = efi_name_to_guid("EFI Security Database", &security_guid);
		if (rc < 0)
			err(1, "Could not get dbx variable name");

		rc = efi_get_variable(security_guid, "dbx", &dbx_buffer,
					&dbx_len, &attributes);
		if (rc < 0)
			err(1, "Could not get dbx variable");
	}

	int ret = 0;
	if (action == 0) {
		fprintf(stderr, "No action specified");
		ret = 1;
		goto end;
	}

	if (action & ACTION_LIST) {
		dump_dbx(dbx_buffer, dbx_len);
		action &= ~ACTION_LIST;
	}

end:
	if (dbx_buffer)
		free(dbx_buffer);
	if (ctx.dbx_file) {
		free(ctx.dbx_file);
	}

	return ret;
}
