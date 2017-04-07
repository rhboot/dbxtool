/*
 * Copyright 2011-2014 Red Hat, Inc.
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
#ifndef DBXTOOL_UTIL_H
#define DBXTOOL_UTIL_H 1

#include <efivar.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>

#define save_errno(x)					\
	({						\
		typeof (errno) __saved_errno = errno;	\
		x;					\
		errno = __saved_errno;			\
	})

extern int verbose;
#define vprintf(fmt, args...) ({					\
		if (verbose)						\
			printf(fmt, ##args);				\
	})

static inline int
__attribute__ ((unused))
read_file(int fd, char **bufp, size_t *lenptr) {
    int alloced = 0, size = 0, i = 0;
    char * buf = NULL;

    do {
	size += i;
	if ((size + 1024) > alloced) {
	    alloced += 4096;
	    buf = realloc(buf, alloced + 1);
	}
    } while ((i = read(fd, buf + size, 1024)) > 0);

    if (i < 0) {
        free(buf);
	return -1;
    }

    *bufp = buf;
    *lenptr = size;

    return 0;
}

static int
__attribute__ ((unused))
timecmp(EFI_TIME *a, EFI_TIME *b)
{
	if (a->Year != b->Year)
		return a->Year - b->Year;
	if (a->Month != b->Month)
		return a->Month - b->Month;
	if (a->Day != b->Day)
		return a->Day - b->Day;
	if (a->Hour != b->Hour)
		return a->Hour - b->Hour;
	if (a->Minute != b->Minute)
		return a->Minute - b->Minute;
	if (a->Second != b->Second)
		return a->Second - b->Second;
	return 0;
}

static void
__attribute__ ((unused))
print_hex(uint8_t *data, size_t len)
{
	char hex[] = "0123456789abcdef";
	for (int i = 0; i < len; i++)
		printf("%c%c", hex[(data[i] & 0xf0) >> 4],
			       hex[(data[i] & 0x0f) >> 0]);
}

static int
__attribute__ ((unused))
memcmp2(const void *l, const ssize_t ll, const void *r, const ssize_t rl)
{
	int ret;

	ret = memcmp(l, r, MIN(ll, rl));
	if (ret != 0 || ll == rl)
		return ret;

	return ll < rl ? -1 : 1;
}

#endif /* DBXTOOL_UTIL_H */
