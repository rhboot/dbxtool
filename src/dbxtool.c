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

#include "util.h"

int
main(int argc, char *argv[])
{
	int rc;
	char *dbx_file = NULL;
	int do_list = 0;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "dbxtool" },
		{"dbx", 'd', POPT_ARG_STRING,
			&dbx_file, 0, "specify dbx database file", "<dbxfile>"},
		{"list", 'l', POPT_ARG_VAL, &do_list, 1,
			"list entries in dbx", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("dbxtool", argc, (const char **)argv,
				options, 0);

	rc = poptReadDefaultConfig(optCon, 0);
        if (rc < 0)
		err(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));
	
	while ((rc = poptGetNextOpt(optCon)) > 0)
		;
	
	if (rc < -1)
		err(1, "Invalid argument: \"%s\": %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
	
	if (poptPeekArg(optCon))
		err(1, "Invalid argument: \"%s\"\n",
			poptPeekArg(optCon));
	
	poptFreeContext(optCon);

	uint8_t *dbx_buffer = NULL;
	size_t len = 0;
	uint32_t attributes = 0;
	if (dbx_file != NULL) {
		int fd = open(dbx_file, O_RDONLY);
		if (fd < 0)
			err(1, "Could not open file \"%s\": %m\n", dbx_file);

		rc = read_file(fd, (char **)&dbx_buffer, &len);
		if (rc < 0)
			err(1, "Could not read file \"%s\": %m\n", dbx_file);

		close(fd);
		attributes = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|
				EFI_VARIABLE_RUNTIME_ACCESS |
				EFI_VARIABLE_BOOTSERVICE_ACCESS |
				EFI_VARIABLE_NON_VOLATILE;

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
				len > 4) {
			attributes = dbx_buffer[0];
			uint8_t *tmp = malloc(len - 4);
			if (!tmp)
				err(1, "%m");

			memmove(tmp, dbx_buffer + 4, len - 4);
			free(dbx_buffer);
			dbx_buffer = tmp;
			len -= 4;
		}
	} else {
		if (!efi_variables_supported())
			err(1, "EFI variables are not supported on this "
				"machine, and no dbx file was specified\n");

		efi_guid_t security_guid = EFI_GUID(0xd719b2cb, 0x3d3a, 0x4596,
			0xa3bc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f);
		
		rc = efi_get_variable(security_guid, "dbx", &dbx_buffer, &len,
					&attributes);
		if (rc < 0)
			err(1, "Could not get dbx variable: %m\n");
	}

	printf("dbx was %zd bytes\n", len);

	return 0;
}
