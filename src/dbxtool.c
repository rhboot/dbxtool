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

#include <dirent.h>
#include <efivar.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <popt.h>
#include <search.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include "error.h"
#include "esl.h"
#include "esltree.h"
#include "iter.h"
#include "util.h"

#define ACTION_LIST	0x1
#define ACTION_APPLY	0x2

int verbose = 0;

typedef struct {
	char *dbx_file;
	int action;
	bool force;
	bool quiet;
} dbxtool_ctx;

struct db_update_file {
	const char *name;
	void *base;
	size_t len;
};

static inline int
print_time(FILE *f, EFI_TIME *t)
{
	return fprintf(f, "%4d-%d-%d %d:%d:%d",
		t->Year, t->Month, t->Day, t->Hour, t->Minute, t->Second);
}

static inline int
is_time_sane(EFI_TIME *t)
{
	if (t->Second >= 60)
		return 0;
	if (t->Minute >= 60)
		return 0;
	if (t->Hour >= 24)
		return 0;
	int mlen = 0;
	switch (t->Month) {
		case 1:
		case 3:
		case 5:
		case 7:
		case 8:
		case 10:
		case 12:
			mlen = 31;
			break;
		case 2:
			mlen = 28;
			break;
		case 4:
		case 6:
		case 9:
		case 11:
			mlen = 30;
			break;
		default:
			return 0;
	}
	if (t->Day == 0 || t->Day > mlen)
		return 0;
	if (t->Year < 1998)
		return 0;
	return 1;
}

int
dump_dbx(uint8_t *buf, size_t len)
{
	int rc;
	esd_iter *iter = NULL;

	if (len == 0)
		return 0;

	rc = esd_iter_new(&iter, buf, len);
	if (rc < 0)
		error(1, NULL);

	while (1) {
		efi_guid_t type;
		efi_guid_t owner;
		uint8_t *data;
		size_t datalen;

		rc = esd_iter_next(iter, &type, &owner, &data, &datalen);
		if (rc < 0)
			error(1, NULL);
		if (rc == 0)
			break;


		char *typestr = NULL;
		int rc = efi_guid_to_id_guid(&type, &typestr);
		if (rc < 0)
			error(1, "bad type guid");

		char *ownerstr = NULL;
		rc = efi_guid_to_id_guid(&owner, &ownerstr);
		if (rc < 0)
			error(1, "bad owner guid");

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

	vprintf("Attempting to identify filetype: ");

	while (buflen >= sizeof (va2)) {
		char *guidname = NULL;

		memcpy(&va2, buf, sizeof(va2));
		efi_guid_to_id_guid(&va2.AuthInfo.CertType, &guidname);
		vprintf("va2 guid is %s ", guidname);
		free(guidname);
		guidname = NULL;
		if (efi_guid_is_empty(&va2.AuthInfo.CertType)) {
			vprintf("cannot be va2 data\n");
			break;
		} else {
			vprintf("\n");
		}

		for (int i = 0; efi_guid_is_empty(&guids[i]) == 0; i++) {
			efi_guid_to_id_guid(&guids[i], &guidname);
			vprintf("guid table guid is %s\n", guidname);
			free(guidname);
			guidname = NULL;
			if (!efi_guid_cmp(&guids[i], &va2.AuthInfo.CertType)) {
				vprintf("ft_append_timestamp is "
					"%4d-%02d-%02d %d:%d:%d\n",
					va2.TimeStamp.Year,
					va2.TimeStamp.Month,
					va2.TimeStamp.Day,
					va2.TimeStamp.Hour,
					va2.TimeStamp.Minute,
					va2.TimeStamp.Second);
				return ft_append_timestamp;
			}
		}
		break;
	}

	while (buflen >= sizeof (va)) {
		char *guidname = NULL;

		memcpy(&va, buf, sizeof(va));
		efi_guid_to_id_guid(&va.AuthInfo.CertType, &guidname);
		vprintf("va guid is %s ", guidname);
		free(guidname);
		guidname = NULL;
		if (efi_guid_is_empty(&va.AuthInfo.CertType)) {
			vprintf("cannot be va data\n");
			break;
		} else {
			vprintf("\n");
		}

		for (int i = 0; efi_guid_is_empty(&guids[i]) == 0; i++) {
			if (!efi_guid_cmp(&guids[i], &va.AuthInfo.CertType)) {
				vprintf("ft_append_monotonic\n");
				return ft_append_monotonic;
			}
		}
		break;
	}

	/* if we get a file that's just dd-ed from sysfs,
	 * it'll have some attribute bits at the beginning */
	vprintf("buf[0] is 0x%02x\n", buf[0]);
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
		for (int i = 0; efi_guid_is_empty(&esl_guids[i]) == 0; i++) {
			if (!efi_guid_cmp(&esl_guids[i], &esl.SignatureType)) {
				vprintf("ft_dbx\n");
				return ft_dbx;
			}
		}
	}

	EFI_SIGNATURE_LIST esl;
	memcpy(&esl, buf, sizeof (EFI_SIGNATURE_LIST));
	for (int i = 0; efi_guid_is_empty(&esl_guids[i]) == 0; i++) {
		if (!efi_guid_cmp(&esl_guids[i], &esl.SignatureType)) {
			vprintf("ft_dbx_noattr\n");
			return ft_dbx_noattr;
		}
	}

	vprintf("ft_unknown\n");
	return ft_unknown;
}

static ssize_t
get_cert_type_size(efi_guid_t *guid)
{
	struct {
		efi_guid_t guid;
		ssize_t size;
	} sizes[] = {
		{efi_guid_sha256, 32 },
		{efi_guid_empty, 0 }
	};
	for (int i = 0; efi_guid_cmp(&sizes[i].guid, &efi_guid_empty); i++) {
		if (!efi_guid_cmp(&sizes[i].guid, guid))
			return sizes[i].size;
	}
	errno = ENOENT;
	efi_error("could not determine cert type size");
	return -1;
}

static int update_cmp(const void *p, const void *q)
{
	struct db_update_file *piov = (struct db_update_file *)p;
	struct db_update_file *qiov = (struct db_update_file *)q;

	EFI_VARIABLE_AUTHENTICATION_2 *vap =
		(EFI_VARIABLE_AUTHENTICATION_2 *)piov->base;
	EFI_VARIABLE_AUTHENTICATION_2 *vaq =
		(EFI_VARIABLE_AUTHENTICATION_2 *)qiov->base;

	return timecmp(&vap->TimeStamp, &vaq->TimeStamp);
}

static inline void
sort_updates(struct db_update_file *updates, size_t num_updates)
{
	vprintf("Sorting updates list\n");
	qsort(updates, num_updates, sizeof (struct db_update_file),
		update_cmp);
}

static void print_update_name(const void *base)
{
	EFI_VARIABLE_AUTHENTICATION_2 *va =
		(EFI_VARIABLE_AUTHENTICATION_2 *)base;
	print_time(stdout, &va->TimeStamp);
}

static void apply_update(struct db_update_file *update, uint32_t attributes)
{
	int rc = 0;
	rc = efi_append_variable(efi_guid_security, "dbx",
		update->base, update->len, attributes);
	if (rc < 0) {
		error(1, "Could not apply database update \"%s\": %m\n"
		         "Cannot Continue.", update->name);
	}
}

static int
is_update_applied(struct db_update_file *update, void **dbx)
{
	/* this function is a bit of a lie.  We can't actually tell if an
	 * update itself is installed, because to do that we'd need the
	 * timestamp as well as the data.  We also don't know what the
	 * most recent timestamp applied *is* (or any other time stamp),
	 * so the only thing we actually know is if all the list entries
	 * in the update are present, then applying it doesn't accomplish
	 * anything.
	 *
	 * So we can use that as a proxy for the update itself being applied,
	 * but that means we may try to process an update with a newer
	 * date than the unknown previous date, which will then fail.
	 */
	int rc;
	int ret = 1;

	EFI_VARIABLE_AUTHENTICATION_2 *va =
					(EFI_VARIABLE_AUTHENTICATION_2 *)
					update->base;
	size_t esllen = update->len
			- sizeof (va->TimeStamp)
			- va->AuthInfo.Hdr.dwLength;
	uint8_t *eslbuf = (uint8_t *)
			((intptr_t)&va->AuthInfo.Hdr.bCertificate
				+ va->AuthInfo.Hdr.dwLength
				- sizeof (va->AuthInfo.Hdr));

	esd_iter *esdi = NULL;
	rc = esd_iter_new(&esdi, eslbuf, esllen);
	if (rc < 0)
		error(1, "Couldn't iterate contents of update");

	while (1) {
		struct esl_tree_entry ehe;
		struct esl_tree_entry *ehep;

		rc = esd_iter_next(esdi, &ehe.type, &ehe.owner,
					&ehe.data, &ehe.datalen);
		if (rc < 0)
			error(1, NULL);
		if (rc == 0)
			break;

		ehep = tfind(&ehe, dbx, esl_cmp);
		if (!ehep) {
			vprintf("Update entry is not applied.\n");
			ret = 0;
			break;
		} else {
			vprintf("Update entry is already applied.\n");
		}
	}
	esd_iter_end(esdi);

	return ret;
}

static int
endswith(char *str, char *suffix)
{
	if (!str || !suffix || !*str || !*suffix)
		return 0;

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);
	if (str_len < suffix_len)
		return 0;

	return !strcmp(str + (str_len - suffix_len), suffix);
}

static void
load_update_file(struct db_update_file *update_ret, const char *path, int infd)
{
	int fd = infd >= 0 ? infd : open(path, O_RDONLY);
	struct db_update_file update;
	int rc;

	if (fd < 0)
		error(1, "1 Could not read file \"%s\"", path);

	update.name = path;
	rc = read_file(fd, (char **)&update.base, &update.len);
	if (rc < 0)
		error(1, "2 Could not read file \"%s\"", path);

	if (infd < 0)
		close(fd);

	filetype ft = guess_file_type(update.base, update.len);
	if (ft != ft_append_timestamp)
		errorx(1, "dbxtool only supports timestamped updates\n");

	EFI_VARIABLE_AUTHENTICATION_2 *va =
			(EFI_VARIABLE_AUTHENTICATION_2 *)update.base;

	if (!is_time_sane(&va->TimeStamp)) {
		fprintf(stderr,
			"\"%s\" contains a time stamp that is invalid: ",
			path);
		print_time(stderr, &va->TimeStamp);
		fprintf(stderr, "\n");
		exit(1);
	}

	memcpy(update_ret, &update, sizeof (update));
}

static void
get_apply_files_from_dir(const char *dirname,
			struct db_update_file **updates_ret,
			int *num_updates_ret)
{
	int rc;
	DIR *dir;
	struct db_update_file *updates = NULL;
	int num_updates = 0;

	dir = opendir(dirname);
	if (!dir)
		error(1, "Couldn't open directory \"%s\"", dirname);

	int dfd = dirfd(dir);
	if (dfd < 0)
		error(1, "Couldn't get directory \"%s\"", dirname);
	while (1) {
		struct dirent *d;

		errno = 0;
		if (!(d = readdir(dir))) {
			if (errno)
				error(1, "Couldn't read directory \"%s\"",
					dirname);
			break;
		}

		if (!endswith(d->d_name, ".bin"))
			continue;

		struct stat sb;
		rc = fstatat(dfd, d->d_name, &sb, 0);
		if (rc < 0)
			error(1, "Could not stat \"%s\"", d->d_name);

		if (!S_ISREG(sb.st_mode)) {
			vprintf("Skipping non regular file \"%s\"",
				d->d_name);
			continue;
		}
		num_updates++;

		struct db_update_file *new_updates = realloc(updates,
					num_updates * sizeof (*updates));
		if (!new_updates)
			error(1, "Could not process updates");
		updates = new_updates;

		int fd = openat(dfd, d->d_name, O_RDONLY);
		if (fd < 0)
			error(1, "Couldn't open update \"%s\"", d->d_name);

		load_update_file(&new_updates[num_updates-1], d->d_name, fd);
		close(fd);
	}
	*updates_ret = updates;
	*num_updates_ret = num_updates;
}

static void
check_pk_and_kek(bool force, bool quiet)
{
	struct {
		char *name;
		efi_guid_t guid;
	} guids[] = {
		{ "PK", efi_guid_global },
		{ "KEK", efi_guid_global },
		{ NULL, efi_guid_zero },
	};
	bool all_found = true;

	for (int i = 0; guids[i].name != NULL; i++) {
		int rc;
		size_t datasize = 0;
		errno = 0;
		rc = efi_get_variable_size(guids[i].guid, guids[i].name,
					   &datasize);
		if (rc < 0 && errno == ENOENT) {
			if (!quiet)
				warnx("%s is not set on this system.",
				      guids[i].name);
			all_found = false;
		}
	}
	if (!all_found) {
		if (!quiet) {
			if (!force)
				errx(1, "Not attempting to apply updates.");
			warnx("attempting to apply updates anyway.");
		}
		if (!force)
			exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int rc;
	uint32_t action = 0;

	const char **apply_files = NULL;

	dbxtool_ctx ctx = { 0 };
	poptContext optCon;
	int force = 0, quiet = 0;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "dbxtool", 0, NULL, NULL },
		{"dbx", 'd', POPT_ARG_STRING,
			&ctx.dbx_file, 0, "specify dbx database file",
			"<dbxfile>"},
		{"list", 'l', POPT_ARG_VAL|POPT_ARGFLAG_OR,
			&action, ACTION_LIST,
			"list entries in dbx", NULL },
		{"apply", 'a', POPT_ARG_VAL|POPT_ARGFLAG_OR,
			&action, ACTION_APPLY,
			"apply update files", NULL },
		{"force", 'f', POPT_ARG_VAL,
			&force, 1,
			"apply updates even if PK and KEK are not set",
			NULL },
		{"quiet", 'q', POPT_ARG_VAL,
			&quiet, 1,
			"do not show warnings if PK and KEK are not set",
			NULL },
		{"verbose", 'v', POPT_ARG_VAL,
			&verbose, 1,
			"be verbose about everything", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	int num_updates = 0;

	optCon = poptGetContext("dbxtool", argc, (const char **)argv,
				options, 0);

	rc = poptReadDefaultConfig(optCon, 0);
        if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errorx(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (action & ACTION_APPLY) {
		if (rc >= 0)
			errorx(1, "--apply was specified with no files given");

		apply_files = poptGetArgs(optCon);
		if (apply_files == NULL)
			errorx(1, "--apply was specified with no files given: "
				"\"%s\": %s",
				poptBadOption(optCon, 0), poptStrerror(rc));
		for (int i = 0; apply_files[i] != NULL; i++, num_updates++) {
			poptGetArg(optCon);
			if (access(apply_files[i], R_OK))
				error(1, "Could not open \"%s\"",
				      apply_files[i]);
		}
		rc = 0;
	}

	if (rc < -1)
		errorx(1, "Invalid argument: \"%s\": %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errorx(1, "Invalid argument: \"%s\"",
			poptPeekArg(optCon));

	ctx.force = force;
	ctx.quiet = quiet;

	uint8_t *orig_dbx_buffer = NULL;
	uint8_t *dbx_buffer = NULL;
	size_t dbx_len = 0;
	uint32_t attributes = 0;
	if (ctx.dbx_file != NULL) {
		vprintf("Loading dbx from \"%s\"\n", ctx.dbx_file);
		int fd = open(ctx.dbx_file, O_RDONLY);
		if (fd < 0)
			error(1, "Could not open file \"%s\"", ctx.dbx_file);

		rc = read_file(fd, (char **)&dbx_buffer, &dbx_len);
		if (rc < 0)
			error(1, "4 Could not read file \"%s\"", ctx.dbx_file);

		close(fd);

		filetype ft = guess_file_type(dbx_buffer, dbx_len);
		switch (ft) {
			case ft_unknown:
				error(1, "Unknown file type");
				break;
			case ft_dbx:
				vprintf("dbx file type is dbx\n");
				attributes = dbx_buffer[0];
				uint8_t *tmp = malloc(dbx_len - 4);
				if (!tmp)
					error(1, "%m");

				memmove(tmp, dbx_buffer + 4, dbx_len - 4);
				free(dbx_buffer);
				dbx_buffer = tmp;
				dbx_len -= 4;
				break;
			case ft_dbx_noattr:
				vprintf("dbx file type is dbx_noattr\n");
				attributes =
					EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS |
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_NON_VOLATILE;
				break;
			case ft_append_timestamp: {
				vprintf("dbx file type is append_timesrtamp\n");
				EFI_VARIABLE_AUTHENTICATION_2 *va =
					(void *)dbx_buffer;
				orig_dbx_buffer = dbx_buffer;
				off_t offset = va->AuthInfo.Hdr.dwLength
						+ sizeof (efi_guid_t);
				dbx_buffer = (void *)((intptr_t)va + offset);
				dbx_len -= offset;
				break;
			}
			default:
				errno = EINVAL;
				error(1, "Sorry, can't handle this yet");
				break;
		}
	} else {
		if (!efi_variables_supported())
			errorx(1, "EFI variables are not supported on this "
				"machine, and no dbx file was specified");

		rc = efi_get_variable(efi_guid_security, "dbx", &dbx_buffer,
					&dbx_len, &attributes);
		if (rc < 0) {
			/* a missing dbx variable is okay as long as "apply"
			 * is among the requested actions */
			if (errno != ENOENT || !(action & ACTION_APPLY)) {
				error(1, "Could not get dbx variable");
			}

			assert(dbx_buffer == NULL);
			assert(dbx_len == 0);
			attributes =
				EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
				EFI_VARIABLE_RUNTIME_ACCESS |
				EFI_VARIABLE_BOOTSERVICE_ACCESS |
				EFI_VARIABLE_NON_VOLATILE;
		}
	}

	struct db_update_file *updates = NULL;
	if ((action & ACTION_APPLY) && num_updates != 0) {
		void *dbxtree = NULL;

		check_pk_and_kek(ctx.force, ctx.quiet);

		rc = esl_tree_create(&dbxtree, dbx_buffer, dbx_len);
		if (rc < 0)
			error(1, NULL);

		if (num_updates == 1) {
			struct stat sb;
			rc = stat(apply_files[0], &sb);
			if (rc < 0)
				error(1, "Couldn't access \"%s\"",
					apply_files[0]);

			const char *dirname = apply_files[0];
			if (S_ISDIR(sb.st_mode)) {
				int new_num_updates = 0;
				get_apply_files_from_dir(dirname,
						&updates,
						&new_num_updates);
				num_updates = new_num_updates;
			}
		}
		if (updates == NULL) {
			updates = calloc(num_updates,
				sizeof (struct db_update_file));
			if (updates == NULL)
				error(1, "Couldn't allocate buffers");
			for (int i = 0;
			     apply_files != NULL && apply_files[i] != NULL;
			     i++) {
				vprintf("Loading update file \"%s\"\n",
					apply_files[i]);
				load_update_file(&updates[i],
						apply_files[i], -1);
			}
		}

		vprintf("Attempting to apply %d updates\n", num_updates);
		sort_updates(updates, num_updates);

		int first_unapplied = -1;
		int applied = 0;
		for (int i = 0; i < num_updates; i++) {
			vprintf("Checking if \"%s\" has been applied.\n",
				updates[i].name);
			rc = is_update_applied(&updates[i], &dbxtree);
			if (rc < 0)
				error(1, NULL);
			if (rc == 0) {
				if (applied == 1) {
					fprintf(stderr,
						"Update set contains applied "
						"updates older than unapplied "
						"updates.\n");
					fprintf(stderr,
						"There's nothing reasonable to "
						"do here, aborting.\n");
					exit(1);
				}
				vprintf("Update \"%s\" is not applied\n",
					updates[i].name);
				if (first_unapplied == -1)
					first_unapplied = i;
				continue;
			}
			vprintf("Update \"%s\" is already applied\n",
					updates[i].name);
			applied = 1;
		}
		if (first_unapplied != -1) {
			printf("Applying %d updates\n",
				num_updates - first_unapplied);

			for (int i = first_unapplied; i < num_updates; i++) {
				printf("Applying \"%s\" ", updates[i].name);
				print_update_name(updates[i].base);
				printf("\n");
				apply_update(&updates[i], attributes);
			}
		}

		esl_tree_destroy(&dbxtree);
	}

	int ret = 0;
	if (action == 0) {
		fprintf(stderr, "No action specified\n");
		ret = 1;
		goto end;
	}

	if (action & ACTION_LIST) {
		dump_dbx(dbx_buffer, dbx_len);
		action &= ~ACTION_LIST;
	}

end:
	if (updates) {
		for (int i = 0; i < num_updates; i++)
			free(updates[i].base);
		free(updates);
	}
	free(orig_dbx_buffer ? orig_dbx_buffer : dbx_buffer);
	free(ctx.dbx_file);

	poptFreeContext(optCon);

	return ret;
}
