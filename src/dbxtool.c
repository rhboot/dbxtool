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
		if (rc)
			break;


		char *typestr = NULL;
		int rc = efi_guid_to_name(&type, &typestr);
		if (rc < 0)
			err(1, "bad type guid");

		char *ownerstr;
		rc = efi_guid_to_name(&owner, &ownerstr);
		if (rc < 0)
			err(1, "bad owner guid");

		printf("%4d: \"%s\" \"%s\" ", esd_iter_get_line(iter),
						ownerstr, typestr);
		print_hex(data, datalen);
		printf("\n");

		free(typestr);
		free(ownerstr);
	}

	esd_iter_end(iter);
	return 0;
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
		attributes = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|
				EFI_VARIABLE_RUNTIME_ACCESS |
				EFI_VARIABLE_BOOTSERVICE_ACCESS |
				EFI_VARIABLE_NON_VOLATILE;

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
			attributes = dbx_buffer[0];
			uint8_t *tmp = malloc(dbx_len - 4);
			if (!tmp)
				err(1, "%m");

			memmove(tmp, dbx_buffer + 4, dbx_len - 4);
			free(dbx_buffer);
			dbx_buffer = tmp;
			dbx_len -= 4;
		}
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

	if (action == 0)
		errx(1, "No action specified");

	if (action & ACTION_LIST) {
		dump_dbx(dbx_buffer, dbx_len);
		action &= ~ACTION_LIST;
	}

	if (ctx.dbx_file == NULL) {
		if (dbx_buffer)
			free(dbx_buffer);
	}

	return 0;
}
