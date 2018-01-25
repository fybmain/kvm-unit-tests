/*
 * gtests/lib/test_util.c
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#define _GNU_SOURCE /* for getline(3) and strchrnul(3)*/

#include <test_util.h>

#include <assert.h>
#include <ctype.h>
#include <execinfo.h>
#include <float.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <bits/endian.h>

#include <linux/elf.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* The function sgnif relies on the floating point formats having
 * an exponent radix of 2.
 */
#if FLT_RADIX != 2
#error "FLT_RADIX != 2.  This implementation only supports FLT_RADIX == 2."
#endif

#define INF  ((uint64_t)0 - 1) /* For test_symb_infinity. */

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define CONST_STRLEN(str) (ARRAY_SIZE(str) - 1)
#define GOTO_ERROR(val) do { \
		rv = val; \
		goto error; \
	} while (0)
#define HEX_PREFIX "0x"

#define MOUNTS_PATH "/proc/mounts"
#define DEBUGFS_TYPE "debugfs"

/* We use a uint64_t to store addresses, thus
 * the need for a defined maximum nibble count.
 */
#define TEST_PG_MAX_NIBBLES ((sizeof(uint64_t) * CHAR_BIT) / 4)

static const unsigned int nsecs_per_sec = 1000000000;

const struct test_symb test_symb_infinity[] = {
	{"INF", INF},
	{"INFINITY", INF},
	{"Inf", INF},
	{"Infinity", INF},
	{"inf", INF},
	{"infinity", INF},
	{NULL}, /* End of list marker */
};

/* Convenience Macros */
#define CEIL_BYTES_TO_PAGES(x) (((x) + (getpagesize() - 1)) / getpagesize())
#define PTR_ADD(ptr, num) (void *)((uintptr_t)(ptr) + (num))
#define TS_VALIDATE(t) do { \
	TEST_ASSERT((t)->tv_sec >= 0, "%s " #t " negative secs, " \
		#t "->tv_sec: %li", __func__, (t)->tv_sec); \
	TEST_ASSERT((t)->tv_nsec >= 0, "%s " #t " negative nsecs, " \
		#t "->tv_nsec: %li", __func__, (t)->tv_nsec); \
	TEST_ASSERT((t)->tv_nsec < nsecs_per_sec, "%s " #t "too many nsecs, " \
		#t "->tv_nsec: %li", __func__, (t)->tv_nsec); \
} while (0)

#define TEST_MALLOC_MAGIC_NUM 0xBACC821F
#define TEST_MALLOC_RED_ZONE_SIZE 128

const struct test_symb test_known_errno[] = {
	{"EPERM", EPERM},
	{"ENOENT", ENOENT},
	{"ESRCH", ESRCH},
	{"EINTR", EINTR},
	{"EIO", EIO},
	{"ENXIO", ENXIO},
	{"E2BIG", E2BIG},
	{"ENOEXEC", ENOEXEC},
	{"EBADF", EBADF},
	{"ECHILD", ECHILD},
	{"EAGAIN", EAGAIN},
	{"ENOMEM", ENOMEM},
	{"EACCES", EACCES},
	{"EFAULT", EFAULT},
	{"ENOTBLK", ENOTBLK},
	{"EBUSY", EBUSY},
	{"EEXIST", EEXIST},
	{"EXDEV", EXDEV},
	{"ENODEV", ENODEV},
	{"ENOTDIR", ENOTDIR},
	{"EISDIR", EISDIR},
	{"EINVAL", EINVAL},
	{"ENFILE", ENFILE},
	{"EMFILE", EMFILE},
	{"ENOTTY", ENOTTY},
	{"ETXTBSY", ETXTBSY},
	{"EFBIG", EFBIG},
	{"ENOSPC", ENOSPC},
	{"ESPIPE", ESPIPE},
	{"EROFS", EROFS},
	{"EMLINK", EMLINK},
	{"EPIPE", EPIPE},
	{"EDOM", EDOM},
	{"ERANGE", ERANGE},
	{NULL} /* End of list marker */
};

const struct test_symb test_known_sig[] = {
	{"SIGHUP", SIGHUP},
	{"SIGINT", SIGINT},
	{"SIGQUIT", SIGQUIT},
	{"SIGILL", SIGILL},
	{"SIGTRAP", SIGTRAP},
	{"SIGABRT", SIGABRT},
	{"SIGBUS", SIGBUS},
	{"SIGFPE", SIGFPE},
	{"SIGKILL", SIGKILL},
	{"SIGUSR1", SIGUSR1},
	{"SIGSEGV", SIGSEGV},
	{"SIGUSR2", SIGUSR2},
	{"SIGPIPE", SIGPIPE},
	{"SIGALRM", SIGALRM},
	{"SIGTERM", SIGTERM},
	{"SIGCHLD", SIGCHLD},
	{"SIGCONT", SIGCONT},
	{"SIGSTOP", SIGSTOP},
	{"SIGPROF", SIGPROF},
	{"SIGIO", SIGIO},
	{"SIGPOLL", SIGPOLL},
	{"SIGPWR", SIGPWR},
	{NULL} /* End of list marker */
};

/* test_malloc keeps track of its allocations by building a
 * singly linked list of test_malloc_alloc structs (lookup
 * efficiency is not a prioirty).
 */
struct test_malloc_alloc {
	struct test_malloc_alloc *next;

	/* User payload's starting address. */
	void *user_addr;

	/* Starting address of the entire allocation. */
	void *start_addr;

	/* The user payload's size. */
	size_t user_size;

	/* The size of the entire allocation. */
	size_t alloc_size;

	/* The flags with which this memory was test_malloc-ed. */
	uint32_t flags;

	/* Whether this memory is mmap-ed. */
	bool mmaped;
};

struct test_malloc_alloc *alloc_list;

/* Local function prototypes */
static float sgnif(long double expected, long double actual,
	unsigned int mant_dig, long double min_normalized);
static bool has_infinity(unsigned int num, const float weights[]);
static void parse_perm(const char *perm, int *prot, bool *shared);
static int proc_maps_max_nibbles(const char *map);
static size_t line_len(const char *str);
static void malloc_create(struct test_malloc_alloc *allocp,
	size_t size, uint32_t flags, size_t align_bytes, int fd, off_t offset);
static struct test_malloc_alloc *malloc_query(const void *addr, bool unlink);
static void test_init(void);

/* Obtain the complete command-line argument, even in cases where the
 * argument spans more than a single argv[] pointer.  Within the returned
 * string, the arguments are joined with a space between each pair of
 * arguments.
 *
 * ARGS:
 *   arg1 - pointer to first string that is part of the flags
 *   args[] - remainder of argv array starting with pointer after
 *            that for arg1. The array is required to be NULL
 *            terminated.
 *
 * Side Effects:
 *   + optind is incremented to point to the next argument beyond
 *     those parsed.
 *
 * Returns:
 *   A pointer to a dynamically allocated string that is a concatenation
 *   of arg1 plus all the strings from args[] that make up the argument.
 *   Note, the caller is responble for freeing the memory of the returned
 *   string.
 */
char *test_get_opt_str(const char *arg1, char *args[])
{
	char *str;

	str = test_dyn_sprintf("%s", arg1);

	/* Append additional arguments until an arg starting with - */
	while ((*args != NULL) && (**args != '-')) {
		char *prev_str = str;
		str = test_dyn_sprintf("%s %s", str, *args);
		free(prev_str);

		args++;
		optind++;
	}

	return str;
}

/* parse_i64
 *
 * Parse the decimal or hexadecimal value provided in the string pointed
 * to by str. Parsed value returned in location pointed to by val. Maximum
 * and Minimum parsed values given by max and min respectively. When symb
 * pointer is non-NULL, it points to a NULL-terminated array of symbolic
 * values. Each of these symbolic values has a string and value that it
 * represents. Note that the symbolic value is allowed to be outside the
 * range [min:max].
 *
 * ARGS:
 *   str - Pointer to null-terminated string to be parsed.
 *   val - Pointer to where the parsed or symbolic value is returned.
 *   min - Minimum allowed parsed value. Symbolic values are allowed
 *         to be outside min boundary.
 *   max - Maximum allowed parsed value.  Symbolic values are allowed
 *         to exceed max.
 *   symb - Pointer to null-terminated array of symbolic values. A symb
 *         of value of NULL means there is no array of symbolic values.
 *
 * Returns:
 *   TEST_UTIL_SUCCESS - on parsing a value within range [min:max]
 *			 or finding a matching symbolic entry.
 *   TEST_UTIL_VALUE_ERR - Parsed value outside range [min:max].
 *   TEST_UTIL_SYNTAX_ERR - String contains invalid syntax
 *   TEST_ASSERT          - test_assert if min > max
 *
 */
int test_parse_i64(const char *str,  int64_t *val,
	int64_t min, int64_t max, const struct test_symbi symb[])
{
	const char *chptr;
	unsigned long long int tmp;

	/* test_assert if min value provided by user is greater than max */
	if (symb == NULL)
		TEST_ASSERT(min < max, " min can not be greater than max , "
		"min:= %"PRIi64" max: %"PRIi64"\n", min, max);

	/* Skip leading white space */
	for (chptr = str; *chptr != '\0' && isspace(*chptr); chptr++)
		;

	/* Empty or string of only whitespace considered a syntax error */
	if (*chptr == '\0')
		return TEST_UTIL_SYNTAX_ERR;

	bool negative_num = false;
	if ((*chptr == '+') || (*chptr == '-')) {
		if (*chptr == '-')
			negative_num = true;

		chptr = chptr + 1;
	}

	/* Is there a matching symbol entry.
	 * In case of multiple matching symbols, use the longest
	 */
	const struct test_symbi *symb_match = NULL;
	for (const struct test_symbi *symb_entry = symb; (symb_entry != NULL)
		&& (symb_entry->name != NULL); symb_entry++) {
		if (strncmp(str, symb_entry->name, strlen(symb_entry->name))
			== 0) {
			if ((symb_match == NULL)
				|| (strlen(symb_entry->name)
					> strlen(symb_match->name)))
				symb_match = symb_entry;
		}
	}

	char *endptr;
	if (symb_match != NULL) {
		endptr = (char *) (str + strlen(symb_match->name));
		*val = symb_match->val;
		/* Skip trailing whitespace */
		for (chptr = endptr; *chptr != '\0' && isspace(*chptr); chptr++)
			;

		/* Syntax error if anything left to parse */
		if (*chptr != '\0')
			return TEST_UTIL_SYNTAX_ERR;
		else
			return TEST_UTIL_SUCCESS;
	}

	if (!isdigit(*chptr))
		return TEST_UTIL_SYNTAX_ERR;

	if (strncasecmp(chptr, HEX_PREFIX,
		CONST_STRLEN(HEX_PREFIX)) == 0) {
		chptr += CONST_STRLEN(HEX_PREFIX);

		/* Whitespace after hex prefix not allowed */
		if (isspace(*chptr))
			return TEST_UTIL_SYNTAX_ERR;

		/* Negative or positive sign after hex prefix not allowed */
		if ((*chptr == '-') || (*chptr == '+'))
			return TEST_UTIL_SYNTAX_ERR;

		/* In case of multiple 0x in the string, which is not allowed */
		if (strncasecmp(chptr, HEX_PREFIX,
			CONST_STRLEN(HEX_PREFIX)) == 0)
			return TEST_UTIL_SYNTAX_ERR;

		tmp = strtoull(chptr, &endptr, 16);
	} else
		tmp = strtoull(chptr, &endptr, 10);

	/* Syntax error if nothing was parsed by call to strtoull. */
	if (chptr == endptr)
		return TEST_UTIL_SYNTAX_ERR;

	/* Skip trailing whitespace */
	for (chptr = endptr; *chptr != '\0' && isspace(*chptr); chptr++)
		;

	/* Syntax error if anything left to parse */
	if (*chptr != '\0')
		return TEST_UTIL_SYNTAX_ERR;

	if (tmp > max) {
		if (tmp != min)
			return TEST_UTIL_VALUE_ERR;
	}

	*val = tmp;

	/* If strtoull returns a positive value and not wrapped around */
	if ((negative_num) && (*val > 0))
		*val = *val * (-1);

	/* In case of wrap around */
	if ((!negative_num) && (*val == min))
		return TEST_UTIL_VALUE_ERR;

	/* In case the value provided by user is out of range */
	if ((*val >  max) || (*val <  min))
		return TEST_UTIL_VALUE_ERR;

	return TEST_UTIL_SUCCESS;
}

/* Parse u32
 *
 * Parse the decimal value provided in the string pointed to by str.
 * Parsed value returned in location pointed to by val.  Maximum parsed
 * value given by max.  When symb pointer is non-NULL, it points to a
 * NULL-terminated array of symbolic values.  Each of these symbolic
 * values has a string and value that it represents.  Note that the
 * symbolic value is allowed to exceed max.
 *
 * ARGS:
 *   str - Pointer to null-terminated string to be parsed.
 *   val - Pointer to where the parsed or symbolic value is returned.
 *   max - Maximum allowed parsed value.  Symbolic values are allowed
 *         to exceed max.
 *   symb - Pointer to null-terminated array of symbolic values.
 *
 * Returns:
 *   TEST_UTIL_SUCCESS - on parsing a value at or below max or finding
 *     a matching symbolic entry.
 *   TEST_UTIL_VALUE_ERR - Parsed value greater than max.
 *   TEST_UTIL_SYNTAX_ERR - String contains invalid syntax
 */
int test_parse_u32(const char *str, uint32_t *val, uint32_t max,
	const struct test_symb symb[])
{
	int rv;
	uint64_t tmp;

	rv = test_parse_u64(str, &tmp, max, symb);

	if (rv != TEST_UTIL_SUCCESS)
		return rv;

	*val = (uint32_t)tmp;

	TEST_ASSERT(tmp <= UINT32_MAX,
		"Value of val greater than expected,"
			"tmp: 0x%" PRIx64 " max: 0x%" PRIx32 "", tmp, max);

	return TEST_UTIL_SUCCESS;
}

/* Parse u64
 *
 * Parse the decimal value provided in the string pointed to by str.
 * Parsed value returned in location pointed to by val.  Maximum parsed
 * value given by max.  When symb pointer is non-NULL, it points to a
 * NULL-terminated array of symbolic values.  Each of these symbolic
 * values has a string and value that it represents.  Note that the
 * symbolic value is allowed to exceed max.
 *
 * ARGS:
 *   str - Pointer to null-terminated string to be parsed.
 *   val - Pointer to where the parsed or symbolic value is returned.
 *   max - Maximum allowed parsed value.  Symbolic values are allowed
 *         to exceed max.
 *   symb - Pointer to null-terminated array of symbolic values.
 *
 * Returns:
 *   TEST_UTIL_SUCCESS - on parsing a value at or below max or finding
 *     a matching symbolic entry.
 *   TEST_UTIL_VALUE_ERR - Parsed value greater than max.
 *   TEST_UTIL_SYNTAX_ERR - String contains invalid syntax
 */
int test_parse_u64(const char *str, uint64_t *val, uint64_t max,
	const struct test_symb symb[])
{
	const char *chptr;
	uint64_t tmp;

	/* Skip leading white space */
	for (chptr = str; *chptr != '\0' && isspace(*chptr); chptr++)
		;

	/* Empty or string of only whitespace considered a syntax error */
	if (*chptr == '\0')
		return TEST_UTIL_SYNTAX_ERR;

	/* Positive sign prefix a value allowed */
	if ((*chptr == '+') || (*chptr == '-')) {
		/* Negative values not allowed */
		if (*chptr == '-')
			return TEST_UTIL_SYNTAX_ERR;
		if (*chptr == '+')
			chptr = chptr + 1;
	}

	/* Is there a matching symbol entry.
	 * In case of multiple matching symbols, use the longest
	 */
	const struct test_symb *symb_match = NULL;
	for (const struct test_symb *symb_entry = symb; (symb_entry != NULL)
		&& (symb_entry->name != NULL); symb_entry++) {
		if (strncmp(str, symb_entry->name, strlen(symb_entry->name))
			== 0) {
			if ((symb_match == NULL)
				|| (strlen(symb_entry->name)
					> strlen(symb_match->name)))
				symb_match = symb_entry;
		}
	}

	char *endptr;
	if (symb_match != NULL) {
		*val = symb_match->val;
		endptr = (char *) (str + strlen(symb_match->name));

		/* Skip trailing whitespace */
		for (chptr = endptr; *chptr != '\0' && isspace(*chptr); chptr++)
			;

		/* Syntax error if anything left to parse */
		if (*chptr != '\0')
			return TEST_UTIL_SYNTAX_ERR;

		return TEST_UTIL_SUCCESS;

	}

	if (!isdigit(*chptr))
		return TEST_UTIL_SYNTAX_ERR;

	errno = 0;
	if (strncasecmp(chptr, HEX_PREFIX,
		CONST_STRLEN(HEX_PREFIX)) == 0) {
		chptr += CONST_STRLEN(HEX_PREFIX);

		/* Whitespace after hex prefix not allowed */
		if (isspace(*chptr))
			return TEST_UTIL_SYNTAX_ERR;

		/* Negative values not allowed */
		if (*chptr == '-')
			return TEST_UTIL_SYNTAX_ERR;

		tmp = strtoull(chptr, &endptr, 16);
	} else {
		/* Negative values not allowed */
		if (*chptr == '-')
			return TEST_UTIL_SYNTAX_ERR;

		tmp = strtoull(chptr, &endptr, 10);
	}

	if (chptr == endptr)
		return TEST_UTIL_SYNTAX_ERR;

	/* Skip trailing whitespace */
	for (chptr = endptr; *chptr != '\0' && isspace(*chptr); chptr++)
		;

	/* Syntax error if anything left to parse */
	if (*chptr != '\0')
		return TEST_UTIL_SYNTAX_ERR;

	if (errno != 0) {

		/* strtoull sets errno to ENOSPC for
		 * any value greater than UINT64_MAX
		 */
		if ((tmp == ULLONG_MAX) || (errno == ERANGE))
			return TEST_UTIL_VALUE_ERR;

		TEST_ASSERT(errno == ERANGE,
				"Wrong input to strtoull\n");
	} else {
		if (tmp > max)
			return TEST_UTIL_VALUE_ERR;
	}

	*val = tmp;
	tmp = 4321; /* set to a magic number */
	return TEST_UTIL_SUCCESS;
}

int test_parse_float(const char *str, float *val)
{
	float tmp;
	char *chptr;

	tmp = strtof(str, &chptr);
	if (*chptr != '\0')
		return TEST_UTIL_SYNTAX_ERR;

	if (!isfinite(tmp))
		return TEST_UTIL_VALUE_ERR;

	*val = tmp;

	return TEST_UTIL_SUCCESS;
}

/* test_parse_rngs
 *
 * Parses out zero or more ranges provided by str.  Each range contains one or
 * two values separated by a colon.  When just one value is provided, the low
 * and high values of the range are set equal to that value.  In the case
 * where colon separated values are provided, low gets set to the value before
 * the colon, while high is set equal to the value after the colon.  Two or
 * more ranges are specified by separating the ranges with a comma.  For
 * example, the following string:
 *
 *   1:5, 54, 0x20,35
 *
 * is a specification for the following ranges:
 *
 *   range 0 low:  1 high:  5
 *   range 1 low: 54 high: 54
 *   range 2 low: 32 high: 35
 *
 * Max is used to specify the maximum value permitted in a range.  While
 * symb when non-NULL points to an array of symbolic strings and their
 * equivalent value.  Note that it is valid for the symbol array to contain
 * entries with values greater than max.
 *
 * Results are returned in a dynamically allocated array pointed to by **rngs,
 * while the length of the results is specified by *num.  On entry these
 * results are unconditionally free.  Note, **rngs must always equal NULL
 * or point to dynamically allocated memory.
 *
 * Return Value:
 *   TEST_UTIL_SUCCESS - str parsed with no errors
 *   TEST_UTIL_SYNTAX_ERR - str does not have a valid syntax
 *   TEST_UTIL_VALUE_ERR - str has a value > max or one of the ranges
 *                         has low > high.
 */

int test_parse_rngs(const char *str, struct test_rng **rngs, unsigned int *num,
	uint64_t max, const struct test_symb symb[])
{
	int rv;
	const char *chptr1, *chptr2;
	struct test_rng tmp_rng;

	TEST_ASSERT(str != NULL, " ");
	TEST_ASSERT(rngs != NULL, " ");
	TEST_ASSERT(num != NULL, " ");

	/* Clear Result */
	free(*rngs);
	*rngs = NULL;
	*num = 0;

	size_t len1 = 0, len2 = 0, pos = 0;

	/* Skip leading white space */
	for (chptr1 = str; *chptr1 != '\0' && isspace(*chptr1); chptr1++)
		;

	for (; *chptr1 != '\0'; chptr1 = chptr2) {
		pos = strcspn(chptr1, ":,");
		len1 = (pos == 0) ? strlen(chptr1) : pos;
		chptr2 = chptr1 + len1;

		if ((chptr2 != NULL) && (*chptr2 == ':')) {
			/* Range of values. */
			char *tmp_parse_one = test_dyn_sprintf("%.*s",
						 len1, chptr1);
			rv = test_parse_u64(tmp_parse_one,
					&tmp_rng.low, max, symb);
			free(tmp_parse_one);
			if (rv)
				GOTO_ERROR(rv);

			chptr1 = chptr2 + 1;

			chptr2 = strchr(chptr1, ',');
			len2 = (chptr2 == NULL) ?
				strlen(chptr1) : chptr2 - chptr1;

			char *tmp_parse_two = test_dyn_sprintf("%.*s",
						len2, chptr1);
			rv = test_parse_u64(tmp_parse_two, &tmp_rng.high,
				max, symb);
			free(tmp_parse_two);
			if (rv)
				GOTO_ERROR(rv);
		} else {  /* Single value. */
			char *tmp_parse_one = test_dyn_sprintf("%.*s",
						len1, chptr1);
			rv = test_parse_u64(tmp_parse_one,
						&tmp_rng.low, max, symb);
			free(tmp_parse_one);
			if (rv)
				GOTO_ERROR(rv);

			/* No high part, so set high equal to low */
			tmp_rng.high = tmp_rng.low;
		}

		/* Is low > high */
		if (tmp_rng.low > tmp_rng.high)
			GOTO_ERROR(TEST_UTIL_VALUE_ERR);

		/* Add tmp_rng to results */
		*rngs = realloc(*rngs, (*num + 1) * sizeof(**rngs));
		TEST_ASSERT(*rngs != NULL, "Insufficient Memory");
		memcpy(*rngs + *num, &tmp_rng, sizeof(**rngs));
		(*num)++;

		/* Skip trailing white space */
		while ((chptr2 != NULL) && isspace(*chptr2))
			chptr2++;

		/* If not at end, then there should be a comma to
		 * seperate the ranges.
		 */

		if ((chptr2 != NULL) && (*chptr2 != '\0')) {
			if (*chptr2 != ',')
				GOTO_ERROR(TEST_UTIL_SYNTAX_ERR);
			chptr2++;
		} else
			break;

		/* Syntax error if only whitespace after comma */
		while ((chptr2 != NULL) && (isspace(*chptr2)))
			chptr2++;

		if ((chptr2 != NULL) && (*chptr2 == '\0'))
			GOTO_ERROR(TEST_UTIL_SYNTAX_ERR);
	}

	return 0;

error:
	free(*rngs);
	*rngs = NULL;
	*num = 0;
	return rv;
}

char *test_rngs2str(const struct test_rng *rngs, unsigned int num,
	unsigned int radix)
{
	char *str, *next_str;
	const char *seperator;
	const char *format;
	const struct test_rng *rng;

	TEST_ASSERT((radix == 0) || (radix == 10) || (radix == 16),
		"Unsupported radix, radix: %u", radix);

	str = test_dyn_sprintf("");

	/* For each of the ranges */
	for (rng = rngs; rng < (rngs + num); rng++) {
		seperator = (rng == rngs) ? "" : ", ";

		if (rng->low == rng->high)
			format = (radix == 0) || (radix == 16)
				? "%s%s0x%llx" : "%s%s%llu";
		else
			format = (radix == 0) || (radix == 16)
				? "%s%s0x%llx:0x%llx" : "%s%s%llu:%llu";
		next_str = test_dyn_sprintf(format, str, seperator,
			rng->low, rng->high);

		free(str);
		str = next_str;
	}

	return str;
}

/*
 * Test Ranges Index Is Set
 *
 * Determines whether any range within a given range includes a specified
 * index.
 *
 * Input Args:
 *   idx - Index to check against
 *   rngs - Pointer to start of ranges
 *   num - Number of ranges
 *
 * Return:
 *   True if any of the ranges specified by rngs and num include the index
 *   given by idx, false otherwise.
 */
bool test_rngs_idx_isset(unsigned long long idx, const struct test_rng *rngs,
	unsigned int num)
{
	const struct test_rng *rng;

	/* For each of the ranges */
	for (rng = rngs; rng < (rngs + num); rng++) {
		if ((idx >= rng->low) && (idx <= rng->high))
			return true;
	}

	/* Not found in any of the ranges. */
	return false;
}

/*
 * Test Ranges Index Set
 *
 * If not already set, sets the given index within a specified set of ranges.
 * When the index is adjacent to an existing range, will expand the existing
 * range to included the index, otherwise it creates a new range that
 * contains just the index and adds it to the array of ranges.
 *
 * Input Args:
 *   idx - Index to be set
 *
 * Input/Output Args:
 *   rngs - Pointer to pointer to start of ranges
 *   num - Pointer to number of ranges
 *
 * Return: None
 */
void test_rngs_idx_set(unsigned long long idx, struct test_rng **rngs,
	unsigned int *num)
{
	/* All done if the index is already set. */
	if (test_rngs_idx_isset(idx, *rngs, *num))
		return;

	/* Is index adjacent to the boundary of an existing range? */
	for (struct test_rng *rng = *rngs; rng < (*rngs + *num); rng++) {
		if ((rng->low > 0) && (idx == rng->low - 1)) {
			/* Is adjacent to lower index.  Set the index,
			 * by decreasing the lower bound by 1.
			 */
			rng->low = idx;
			return;
		}
		if (((rng->high + 1) > rng->high) && (rng->high + 1 == idx)) {
			/* Is adjacent to high index.  Set the index,
			 * by increasing the upper bound.
			 */
			rng->high = idx;
			return;
		}
	}

	/*
	 * Isn't within or adjacent to any of the existing ranges.
	 * Need to add a new range, that specifies just the given
	 * index.
	 */
	struct test_rng tmp_rng;
	memset(&tmp_rng, 0, sizeof(tmp_rng));
	tmp_rng.low = tmp_rng.high = idx;
	*rngs = realloc(*rngs, (*num + 1) * sizeof(**rngs));
	TEST_ASSERT(*rngs != NULL, "Insufficient Memory");
	memcpy(*rngs + *num, &tmp_rng, sizeof(**rngs));
	(*num)++;
}

/* Dumps the current stack trace to stderr. */
static void __attribute__((noinline)) test_dump_stack(void);
static void test_dump_stack(void)
{
	/*
	 * Build and run this command:
	 *
	 *	addr2line -s -e /proc/$PPID/exe -fpai {backtrace addresses} | \
	 *		grep -v test_dump_stack | cat -n 1>&2
	 *
	 * Note that the spacing is different and there's no newline.
	 */
	size_t i;
	size_t n = 20;
	void *stack[n];
	const char *addr2line = "addr2line -s -e /proc/$PPID/exe -fpai";
	const char *pipeline = "|cat -n 1>&2";
	char cmd[strlen(addr2line) + strlen(pipeline) +
		 /* N bytes per addr * 2 digits per byte + 1 space per addr: */
		 n * (((sizeof(void *)) * 2) + 1) +
		 /* Null terminator: */
		 1];
	char *c;

	n = backtrace(stack, n);
	c = &cmd[0];
	c += sprintf(c, "%s", addr2line);
	/*
	 * Skip the first 3 frames: backtrace, test_dump_stack, and
	 * test_assert. We hope that backtrace isn't inlined and the other two
	 * we've declared noinline.
	 */
	for (i = 2; i < n; i++)
		c += sprintf(c, " %lx", ((unsigned long) stack[i]) - 1);
	c += sprintf(c, "%s", pipeline);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	system(cmd);
#pragma GCC diagnostic pop
}

int test_printk(const char *fmt, ...)
{
	va_list ap;
	int r;
	FILE *fp;

	fp = fopen("/dev/kmsg", "w");
	if (!fp)
		return -1;

	va_start(ap, fmt);
	r = vfprintf(fp, fmt, ap);
	va_end(ap);
	if (fclose(fp))
		r = -1;

	return r;
}

static pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

void test_assert(bool exp, const char *exp_str,
	const char *file, unsigned int line, const char *fmt, ...)
{
	va_list ap;

	if (!(exp)) {
		va_start(ap, fmt);

		fprintf(stderr, "==== Test Assertion Failure ====\n"
			"  %s:%u: %s\n"
			"  pid=%d tid=%d\n",
			file, line, exp_str, getpid(), gettid());
		test_dump_stack();
		if (fmt) {
			fputs("  ", stderr);
			vfprintf(stderr, fmt, ap);
			fputs("\n", stderr);
		}
		va_end(ap);

		exit(254);
	}

	return;
}

/* Version of sprintf() that dynamically allocates and uses a buffer
 * of the required size.  Returns a pointer to the allocated buffer.
 * Caller is responsible for freeing the allocated buffer.
 */
char *test_dyn_sprintf(const char *fmt, ...)
{
	int rv;
	int len;
	va_list ap;
	char *buf;

	/* Determine required size of buffer */
	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	len += CONST_STRLEN("\0");

	/* Allocate buffer and redo the vsnprintf, this time with
	 * a buffer that should have sufficient space.
	 */
	buf = malloc(len);
	TEST_ASSERT(buf != NULL, "Insufficient Memory");
	va_start(ap, fmt);
	rv = vsnprintf(buf, len, fmt, ap);
	va_end(ap);
	TEST_ASSERT(rv < len, "dyn_sprintf insufficient buffer length, "
		"rv: %i len: %i fmt: %s", rv, len, fmt);

	return buf;
}

/*
 * Random
 *
 * Returns a pseudo random number in the range [0:2^32-1].
 */
uint32_t test_rand32(void)
{
	uint32_t val;

	/* Use lrand48() to obtain 31 bits worth of randomness. */
	val = lrand48();

	/* Make an additional lrand48() call and merge
	 * the randomness into the most significant bits.
	 */
	val ^= lrand48() << 1;

	return val;
}

/*
 * Random Boolean
 *
 * Pseudo randomly returns true or false.
 */
bool test_rand_bool(void)
{
	return test_rand32_mod(2);
}

/*
 * Random Modulus
 *
 * Pseudo randomly returns unsigned integer in the range [0, mod).
 */
uint32_t test_rand32_mod(uint32_t mod)
{
	uint32_t val;

	/* Obtain the random value
	 * Use lrand48() when it would produce a sufficient
	 * number of random bits, otherwise use test_rand32().
	 */
	const uint32_t lrand48maxVal = ((uint32_t) 1 << 31) - 1;
	val = (mod <= lrand48maxVal)
		? (uint32_t) lrand48() : test_rand32();

	/*
	 * The contents of individual bits tend to be less than random
	 * across different seeds.  For example, srand48(x) and
	 * srand48(x + n * 4) cause lrand48() to return the same sequence of
	 * least significant bits.  For small mod values this can produce
	 * noticably non-random sequnces.  For mod values of less than 2
	 * bytes, will use the randomness from all the bytes.
	 */
	if (mod <= 0x10000) {
		val = (val & 0xffff) ^ (val >> 16);

		/* If mod less than a byte, can further combine down to
		 * a single byte.
		 */
		if (mod <= 0x100)
			val = (val & 0xff) ^ (val >> 8);
	}

	return val % mod;
}

/* Choose random choice from weights
 *
 * Given an array of float weights, pseudorandomly select an index
 * corresponding to a weight. The probability that the ith index will
 * be selected depends upon its weight -- if an index has weight W, and
 * the sum of all weights equals D, then it has a W/D chance of
 * being selected.
 *
 * If a weight equals INFINITY, then test_rand_choice guarantees that it will
 * select that weight's corresponding index. If multiple weights equal
 * INFINITY, then a TEST_ASSERT is triggered. NAN weights also trigger
 * TEST_ASSERTs.
 *
 * Args:
 *   num     - The number of weights
 *   weights - The weights for each choice. The cumulutaive sum must be
 *             greater than 0. A weight of 0.0 never gets chosen.
 * Return:
 *   On success, returns a choice with range [0, len). TEST_ASSERTs triggered
 *   on errors.
 */
unsigned int test_rand_choice(unsigned int num, const float weights[])
{
	unsigned int i;
	double denom;
	double total;
	float value;
	unsigned int prev_non_zero;

	TEST_ASSERT(num > 0, "%s Need at least one weight, "
		"num: %u", __func__, num);

	/* Calculate the denom and check validity of inputs.
	 * Weights cannot be negative. If a weight with value
	 * INFINITY is encountered, then that weight's index is
	 * immediately returned (provided that it's the only
	 * weight with that value).
	 */
	denom = 0;
	for (i = 0; i < num; i++) {
		value = weights[i];
		TEST_ASSERT(!signbit(value), "%s Encountered negative "
			"weight, index: %u value: %g",
			__func__, i, value);
		TEST_ASSERT(!isnan(value), "%s Encountered NaN"
			" weight, index: %u value: %g",
			__func__, i, value);
		if (isinf(value)) {
			if (has_infinity(num - i - 1, weights + i + 1))
				TEST_ASSERT(false, "%s weights has multiple"
					" infinities", __func__);
			else
				return i;
		}
		denom += value;
	}
	TEST_ASSERT(denom > 0, "%s Cumulative weights sum must be "
		"greater than 0, sum: %g", __func__, denom);

	/* Choose the index to return. */
	value = drand48();
	total = 0.0;
	prev_non_zero = 0;
	for (i = 0; i < num; i++) {
		if (weights[i] != 0.0)
			prev_non_zero = i;
		total += weights[i];
		if (value < total / denom)
			break;
	}

	/* If we went through the entire array without
	 * selecting an index, we might have had bad luck with floating
	 * point rounding -- if that's the case, then return the index
	 * of the highest non-zero weight.
	 */
	return i < num ? i : prev_non_zero;
}

/* Check for INFINITY values.
 *
 * If the weights array has at least one INFINITY value, return true;
 * else, return false.
 */
static bool has_infinity(unsigned int num, const float weights[])
{
	unsigned int i;
	for (i = 0; i < num; i++) {
		if (isinf(weights[i]))
			return true;
	}
	return false;

}
void test_delay(double amt)
{
	struct timespec amt_ts;

	amt_ts = test_double2ts(amt);

	test_delay_ts(&amt_ts);
}

void test_delay_ts(const struct timespec *amt)
{
	int rv;
	struct timespec start, end;

	TS_VALIDATE(amt);

	/* Get the time at which we started */
	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Calculate the time to delay until */
	test_ts_sum(&end, &start, amt);

	/* Delay until that time */
	rv = test_delay_until(&end, 0);
	TEST_ASSERT(rv == 0, "test_delay_ts call to test_delay_until "
		"unexpected rv, rv: %i", rv);
}

/* test_delay_until
 *
 * Waits until after the time given by time or when pid is non-zero, until
 * the process specified by pid completes.
 * Returns:
 *   0 - return due to time expired
 *   1 - return due to pid process completed
 */
int test_delay_until(const struct timespec *end, pid_t pid)
{
	int rv;
	siginfo_t status;
	struct timespec current, remaining;
	struct timespec poll_delta = { 0, 300000000ULL }; /* 0.3 secs */

	TS_VALIDATE(end);

	for (;;) {
		/* All done if beyond end time */
		clock_gettime(CLOCK_MONOTONIC, &current);
		if (test_ts_cmp(&current, end) >= 0)
			break;

		/* Wait the smaller of remaining or poll time */
		/* Calculate the amount of time remaining */
		remaining = test_ts_delta(&current, end);

		/* Reduce remaining time to the poll time, when it
		 * is greater than the poll time and there is a need
		 * to poll for process completion.
		 */
		if ((test_ts_cmp(&remaining, &poll_delta) > 0)
			&& (pid != 0))
			remaining = poll_delta;

		/* Sleep */
		(void) nanosleep(&remaining, NULL);

		/* All done if process specified by pid exited.
		 * Note, waitid call made with WNOWAIT, so that the
		 * exit status is still available.  This leaves the process
		 * as a zombie.
		 */
		if (pid != 0) {
			rv = waitid(P_PID, pid, &status,
				WEXITED | WNOHANG | WNOWAIT);
			TEST_ASSERT(rv == 0, "test_delay_until waitid failed, "
				"rv: %i errno: %i", rv, errno);
			if (status.si_pid == pid)
				return 1;
		}
	}

	return 0;
}

double test_ts2double(const struct timespec *val)
{
	double rv;

	rv = val->tv_sec;
	rv += (double) val->tv_nsec / nsecs_per_sec;

	return rv;
}

struct timespec test_double2ts(double amt)
{
	struct timespec rv;

	rv.tv_sec = floor(amt);
	rv.tv_nsec = (amt - rv.tv_sec) * nsecs_per_sec;
	/* TODO: Handle cases where amt is negative */
	while ((unsigned) rv.tv_nsec >= nsecs_per_sec) {
		rv.tv_nsec -= nsecs_per_sec;
		rv.tv_sec++;
	}

	return rv;
}

struct timespec test_ts_delta(const struct timespec *first,
	const struct timespec *second)
{
	struct timespec rv;

	TEST_ASSERT(first != NULL, " ");
	TEST_ASSERT(second != NULL, " ");
	TS_VALIDATE(first);
	TS_VALIDATE(second);
	rv.tv_sec = second->tv_sec - first->tv_sec;
	if (second->tv_nsec >= first->tv_nsec) {
		rv.tv_nsec = second->tv_nsec - first->tv_nsec;
	} else {
		rv.tv_nsec = (second->tv_nsec + nsecs_per_sec) - first->tv_nsec;
		rv.tv_sec--;
	}

	return rv;
}

void test_ts_sum(struct timespec *sum, const struct timespec *t1,
	const struct timespec *t2)
{
	struct timespec result;

	TS_VALIDATE(t1);
	TS_VALIDATE(t2);

	result.tv_sec = t1->tv_sec + t2->tv_sec;
	if ((result.tv_sec < t1->tv_sec) || (result.tv_sec < t2->tv_sec))
		goto max;
	result.tv_nsec = t1->tv_nsec + t2->tv_nsec;
	if (result.tv_nsec >= nsecs_per_sec) {
		result.tv_nsec -= nsecs_per_sec;
		TEST_ASSERT(result.tv_nsec < nsecs_per_sec,
			"Too many nsecs after carry adjustment, "
			"result.tv_nsec: %li", result.tv_nsec);
		result.tv_sec++;
		if (result.tv_sec <= 0)
			goto max;
	}

	sum->tv_sec = result.tv_sec;
	sum->tv_nsec = result.tv_nsec;
	return;

max:
	sum->tv_sec = LONG_MAX;
	sum->tv_nsec = nsecs_per_sec - 1;
	return;
}

void test_ts_minus(struct timespec *minus, const struct timespec *t1,
	const struct timespec *t2)
{
	struct timespec result;

	TS_VALIDATE(t1);
	TS_VALIDATE(t2);

	/* So far the test_ts_* functions only support positive time.  For
	 * now, fail cases where the subtraction would produce a negative
	 * result.
	 */
	TEST_ASSERT(test_ts_cmp(t1, t2) >= 0, "t1 < t2,\n"
		"  t1->tv_sec: %lu t1->tv_nsec: %lu\n"
		"  t2->tv_sec: %lu t2->tv_nsec: %lu\n",
		t1->tv_sec, t1->tv_nsec, t2->tv_sec, t2->tv_nsec);

	result.tv_sec = t1->tv_sec - t2->tv_sec;
	result.tv_nsec = t1->tv_nsec - t2->tv_nsec;
	if (result.tv_nsec < 0) {
		result.tv_nsec += nsecs_per_sec;
		result.tv_sec -= 1;
		TEST_ASSERT((result.tv_nsec >= 0)
			&& (result.tv_nsec < nsecs_per_sec),
			"tv_nsec still negative, tv_sec: %lu tv_nsec: %lu",
			result.tv_sec, result.tv_nsec);
	}
	TEST_ASSERT((result.tv_nsec >= 0)
		&& (result.tv_nsec < nsecs_per_sec),
		"tv_nsec negative, tv_sec: %lu tv_nsec: %lu",
		result.tv_sec, result.tv_nsec);

	minus->tv_sec = result.tv_sec;
	minus->tv_nsec = result.tv_nsec;

	return;
}

int test_ts_cmp(const struct timespec *t1, const struct timespec *t2)
{
	TS_VALIDATE(t1);
	TS_VALIDATE(t2);

	if (t1->tv_sec < t2->tv_sec)
		return -1;
	if (t1->tv_sec > t2->tv_sec)
		return 1;

	if (t1->tv_nsec < t2->tv_nsec)
		return -1;
	if (t1->tv_nsec > t2->tv_nsec)
		return 1;

	return 0;
}

char *test_debugfs_mnt_point(void)
{
	FILE *fp;
	char buf[200];
	char *chptr;
	char *device, *mnt_path, *fs_type;

	/* Determine debugfs mount point */
	fp = fopen(MOUNTS_PATH, "r");
	TEST_ASSERT(fp != NULL, "test_debugfs_mnt_point error opening %s, "
		"errno: %i", MOUNTS_PATH, errno);
	while (fgets(buf, ARRAY_SIZE(buf), fp) != NULL) {
		TEST_ASSERT(strlen(buf) < (ARRAY_SIZE(buf) - 1),
			"test_debugfs_mnt_point line from %s too long,\n"
			"  line: %s", MOUNTS_PATH, buf);

		/* If present remove trailing newline */
		if ((strlen(buf) > 0) && (buf[strlen(buf) - 1] == '\n'))
			buf[strlen(buf) - 1] = '\0';

		/* Parse mount line
		 * The beginning of each line expected to be of the form:
		 *
		 *   device mount_path fs_type
		 *
		 * The fs_type may be the last field or the may be additional
		 * space separated fields beyond fs_type.
		 */
		device = buf;
		mnt_path = strchr(device, ' ');
		TEST_ASSERT(mnt_path != NULL, "test_debugfs_mnt_point "
			"mount path parse error,\n"
			"  line: %s", buf);
		mnt_path++;

		fs_type = strchr(mnt_path, ' ');
		TEST_ASSERT(fs_type != NULL, "test_debugfs_mnt_point "
			"fs type parse error,\n"
			"  line: %s", buf);
		fs_type++;
		chptr = strchr(fs_type, ' ');

		TEST_ASSERT((mnt_path - device) > 1, "test_debugfs_mnt_point "
			"device too short,\n"
			"  line: %s", buf);
		TEST_ASSERT((fs_type - mnt_path) > 1, "test_debugfs_mnt_point "
			"mnt_path too short,\n"
			"  line: %s", buf);
		TEST_ASSERT(((chptr == NULL) && (strlen(fs_type) > 0))
			|| (chptr - fs_type) > 1, "test_debugfs_mnt_point "
			"fs_type too short,\n"
			"  line: %s", buf);

		*(mnt_path - 1) = '\0';
		*(fs_type - 1) = '\0';
		if (chptr != NULL)
			*chptr = '\0';

		/* Skip all but debugfs filesystem type */
		if (strcmp(DEBUGFS_TYPE, fs_type) != 0)
			continue;

		/* Line describing debugfs found */
		fclose(fp);
		return test_dyn_sprintf("%s/", mnt_path);
	}
	TEST_ASSERT(feof(fp), "test_debugfs_mnt_point error reading from %s",
		MOUNTS_PATH);

	fclose(fp);
	return NULL;
}

struct known_sig_code {
	int val;
	const char *name;
} known_sig_code[] = {
	{CLD_EXITED, "EXITED"},
	{CLD_KILLED, "KILLED"},
	{CLD_DUMPED, "DUMPED"},
	{CLD_TRAPPED, "TRAPPED"},
	{CLD_STOPPED, "STOPPED"},
	{CLD_CONTINUED, "CONTINUED"},
};

struct known_sig_status {
	int val;
	const char *name;
} known_sig_status[] = {
	{SIGHUP, "SIGHUP"},
	{SIGINT, "SIGINT"},
	{SIGQUIT, "SIGQUIT"},
	{SIGILL, "SIGILL"},
	{SIGTRAP, "SIGTRAP"},
	{SIGBUS, "SIGBUS"},
	{SIGFPE, "SIGFPE"},
	{SIGKILL, "SIGKILL"},
	{SIGSEGV, "SIGSEGV"},
	{SIGTERM, "SIGTERM"},
};

void test_dump_siginfo(FILE *file, siginfo_t *sig)
{
	int code = sig->si_code;
	int status = sig->si_status;
	struct known_sig_code *codep;
	struct known_sig_status *statusp;

	/* Display si_code */
	fprintf(file, "  si_code: %u", code);
	for (codep = known_sig_code; codep < known_sig_code
		+ ARRAY_SIZE(known_sig_code); codep++) {
		if (code == codep->val)
			break;
	}
	if (codep < (known_sig_code + ARRAY_SIZE(known_sig_code)))
		fprintf(file, " (%s)", codep->name);

	/* Display si_status */
	fprintf(file, " si_status: %u", status);
	if ((code == CLD_KILLED) || (code == CLD_DUMPED)) {
		for (statusp = known_sig_status; statusp <
			known_sig_status + ARRAY_SIZE(known_sig_status);
			statusp++) {
			if (status == statusp->val)
				break;
		}
		if (statusp < known_sig_status + ARRAY_SIZE(known_sig_status))
			fprintf(file, " (%s)", statusp->name);
	}
	fputs("\n", file);

	/* Display PID */
	fprintf(file, "  pid: %i\n", sig->si_pid);
}

uint64_t test_tsc_freq(int cpu)
{
	int rv;
	FILE *f;
	char *path;
	long freq_khz;

	path = test_dyn_sprintf("/sys/devices/system/cpu/cpu%d/tsc_freq_khz",
		cpu);
	f = fopen(path, "r");
	TEST_ASSERT(f != NULL, "test_tsc_freq failed to open %s, errno: %i",
		path, errno);

	rv = fscanf(f, "%ld\n", &freq_khz);
	TEST_ASSERT(rv == 1, "test_tsc_freq fscanf failed, rv: %i "
		"ferror(f): %i errno: %i", rv, ferror(f), errno);

	fclose(f);
	free(path);

	return freq_khz * 1000;
}

/*
 * Hex Dump
 *
 * Displays in hex the contents of the memory starting at the location
 * pointed to by buf, for the number of bytes given by size.
 *
 * ARGS:
 *   stream     - File stream to display the output to.
 *   buf        - Starting address of memory to be dumped.
 *   size       - Number of bytes to be dumped.
 *   addr_start - Address shown for first byte dumped.
 *   indent     - Number of spaces prefixed to start of each line.
 */
#if CHAR_BIT != 8
#error "test_xdump impementation depends on 8 bits per byte."
#endif
void test_xdump(FILE *stream, const void *buf, size_t size,
	intptr_t addr_start, uint8_t indent)
{
	int rv;
	const unsigned char *ptr = buf, *start = buf;
	size_t num = size;
	char *linep;

	/* Constants for various amounts within a single line of ouput.
	 * Each line has the following format:
	 *
	 *   aaaaaa: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
	 *
	 * Where "aaaaaa" is the address and each " xx" is the dump of
	 * a single byte.  Up to 16 bytes are dumped per line, which is
	 * given by the value of bytes_per_line.  Some of these constants
	 * use a cast to char, such as in the expression sizeof((char) ':').
	 * The cast to char is needed, because character constants are auto
	 * promoted to int.  The above expression could have been specified
	 * as sizeof(char), but the ':' is used to express what character
	 * in the line output this expression is for.
	 */
	const unsigned int bytes_per_line = 16;
	const unsigned int hex_digits_per_byte = 2;
	const unsigned int addr_max_char = sizeof(uintptr_t)
		* hex_digits_per_byte;
	const unsigned int max_line = addr_max_char
		+ sizeof((char) ':')
		+ (bytes_per_line * ((sizeof((char) ' '))
			+ hex_digits_per_byte))
		+ sizeof((char) '\0');
	char line[max_line];

	linep = line;
	while (num) {
		if (((ptr - start) % bytes_per_line) == 0) {
			if (linep != line) {
				fprintf(stream, "%*s%s\n",
					indent, "", line);
			}
			linep = line;
			rv = snprintf(linep, ARRAY_SIZE(line) - (linep - line),
				"%0*llx:", addr_max_char,
				(long long) (ptr - start) + addr_start);
			linep += rv;
		}

		/* Check that there is at least room for 4
		 * more characters.  The 4 characters being
		 * a space, 2 hex digits and the terminating
		 * '\0'.
		 */
		assert((ARRAY_SIZE(line) - 4) >= (linep - line));
		rv = snprintf(linep, ARRAY_SIZE(line) - (linep - line),
			" %02x", *ptr++);
		linep += rv;
		num--;
	}

	if (linep != line)
		fprintf(stream, "%*s%s\n", indent, "", line);
}

/* Read Config String
 *
 * Args:
 *   name - name of configuration variable
 *
 * Returns:
 *   Pointer to dynamically allocated string, with setting of the
 *   configuration variable.  For error conditions specified below,
 *   NULL is returned, with errno indicating which condition occurred.
 *   All other errors (e.g. insufficient memory) cause a TEST_ASSERT failure.

 * Errors:
 *   ESRCH - No such configuration variable
 *   ENOENT - Configuration variable exists, but is not set.
 *
 * Reads the kernel configuration via /proc/config.gz and returns information
 * about the configuration variable specified by name.  Uncompressed lines
 * from /proc/config.gz are expected to be of the following forms:
 *
 *   # comment text
 *   # CONFIG_FOO is not set
 *   CONFIG_FOO=string
 *
 *   Comment lines begin with '#' and don't end with "is not set".
 *   Lines starting with '#' and ending with "is not set" describe
 *   configuration variables no setting.  While the final form describes
 *   configuration variables with a setting.  The primary purpose of the
 *   routine is to locate a configuration variable with a setting and
 *   return a dynamically allocated string that contains the setting.  The
 *   not set case is also handled, by noticing the variable and returning
 *   NULL with errno equal to ENOENT.
 */
char *test_config_str(const char *name)
{
	int status;
	FILE *stream;
	char *line = NULL;
	char *rv_str = NULL;
	size_t line_len = 0;
	ssize_t getline_rv;
	static const char *not_set_str = " is not set";
	size_t not_set_len = strlen(not_set_str);
	enum completion_reason {
		NOT_FOUND,
		NOT_SET,
		SETTING_FOUND,
	} completion_reason = NOT_FOUND;

	stream = popen("/bin/gunzip -c /proc/config.gz", "r");
	TEST_ASSERT(stream != NULL, "test_config_str popen failed, "
		"errno: %i", errno);

	while ((getline_rv = getline(&line, &line_len, stream)) != -1) {
		/* If present, remove trailing newline */
		if ((getline_rv > 0) && (line[getline_rv - 1] == '\n'))
			line[getline_rv - 1] = '\0';

		/* Skip blank lines */
		if (strlen(line) == 0)
			continue;

		/* Skip comment lines that don't end with not set. */
		if ((line[0] == '#') && ((strlen(line) < not_set_len)
			|| (strcmp(line + (strlen(line) - not_set_len),
				not_set_str) != 0)))
			continue;

		/* Configuration setting or not set line? */
		if (line[0] != '#') {
			/* Configuration setting */
			/* Lines with a configuration setting should
			 * start with "CONFIG_"
			 */
			TEST_ASSERT(strncmp(line, "CONFIG_",
				strlen("CONFIG_")) == 0, "test_config_str "
				"test_config_str \"CONFIG_\" expected,\n"
				"  line: %s", line);

			/* Skip unless this line describes the configuration
			 * variable specified by name.
			 */
			if ((strncmp(line, name, strlen(name)) != 0)
				|| (*(line + strlen(name)) != '='))
				continue;

			completion_reason = SETTING_FOUND;
			rv_str = strdup(line + strlen(name) + 1);
			TEST_ASSERT(rv_str != NULL, "Insufficient Memory");
			break;
		} else {
			/* Not set line */
			/* Not set lines should at least start with
			 * "# CONFIG_"
			 */
			TEST_ASSERT(strncmp(line, "# CONFIG_",
				strlen("# CONFIG_")) == 0, "test_config_str "
				"test_config_str \"# CONFIG_\" expected,\n"
				"  line: %s", line);

			/* Skip unless this line describes the configuration
			 * variable specified by name.
			 */
			if ((strncmp(line + 2, name, strlen(name)) != 0)
				|| (*(line + 2 + strlen(name)) != ' '))
				continue;

			completion_reason = NOT_SET;
			break;
		}
	}

	/* If needed, read rest of stream.  Could just close the stream,
	 * but it is implementation and timing dependent whether the
	 * gunzip will do exit(0), exit(1), or end due to a SIGPIPE.
	 * Easier to just read the rest of the input and treat everything
	 * but exit(0) as an error.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	while (!feof(stream) && !ferror(stream))
		getline(&line, &line_len, stream);
#pragma GCC diagnostic pop
	TEST_ASSERT(!ferror(stream), "test_config_str stream error, "
		"errno: %i", errno);

	status = pclose(stream);
	TEST_ASSERT(WIFEXITED(status) && (WEXITSTATUS(status) == 0),
		"test_config_str unexpected exit status,\n"
		"  status: 0x%x\n"
		"  WIFEXITED: %i\n"
		"  WEXITSTATUS: %i\n"
		"  WIFSIGNALED: %i\n"
		"  WTERMSIG: %i",
		status, WIFEXITED(status), WEXITSTATUS(status),
		WIFSIGNALED(status), WTERMSIG(status));

	switch (completion_reason) {
	case NOT_FOUND:
		errno = ESRCH;
		break;

	case NOT_SET:
		errno = ENOENT;
		break;

	case SETTING_FOUND:
		break;

	default:
		TEST_ASSERT(false, "test_config_str unknown completion "
			"reason, completion_reason: %i", completion_reason);
	}

	return rv_str;
}

/* Prototypes for syscalls that don't have a prototype within the
 * system headers.
 */
int capset(cap_user_header_t header, const cap_user_data_t data);
int capget(cap_user_header_t header, cap_user_data_t data);

/* Capability Get
 *
 * Reads the current capability set for the process specified by pid and
 * returns them in a dynamically allocated area pointed to by cap.
 *
 * Args:
 *   pid - Process ID
 *   cap - Pointer to the capability set pointer.
 *
 * Returns:
 *   Zero on success, -1 on error.
 *
 * Errors:
 *   EFAULT - Bad memory address
 *   ESRCH - No such process
 */
int test_cap_get(pid_t pid, test_cap_t *cap)
{
	int rv;

	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = pid,
	};

	TEST_ASSERT(cap != NULL, "test_cap_get cap NULL pointer");

	if (*cap == NULL)
		free(*cap);

	*cap = calloc(_LINUX_CAPABILITY_U32S_3,
		sizeof(struct __user_cap_data_struct));
	TEST_ASSERT(*cap != NULL, "Insufficient Memory");

	rv = capget(&header, *cap);

	return rv;
}

/* Capability Set
 *
 * Set the current capability set, for the process given by pid, to the
 * capabilities pointed to by cap.
 *
 * Args:
 *   pid - Process ID
 *   cap - Pointer to the capability set pointer.
 *
 * Returns:
 *   Zero on success, -1 on error.
 *
 * Errors:
 *   EFAULT - Bad memory address
 *   EPERM - Attempt to add a capability to the permitted set, or to
 *           set a capability in the effective or inheritable sets that
 *           is not in the permitted set.
 *   ESRCH - No such process
 */
int test_cap_set(pid_t pid, const test_cap_t *cap)
{
	int rv;

	TEST_ASSERT(cap != NULL, "test_cap_get cap NULL pointer");
	TEST_ASSERT((*cap) != NULL, "test_cap_get *cap NULL pointer");

	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = pid,
	};

	rv = capset(&header, *cap);

	return rv;
}

/* Capability Flag Fetch
 *
 * Returns the current setting of a specified capability trait.
 *
 * Args:
 *   cap   - Pointer to capability set
 *   group - Which group of capabilities, effective, permitted, or
 *           inheritable.
 *   trait - Index of particular trait.  Available indexes are specified
 *           within <linux/capability.h> as CAP_ defines.
 *
 * Returns:
 *   Setting of specified trait, TEST_ASSERT used for detected errors
 *     (e.g. invalid group).
 */
bool test_cap_flag_fetch(const test_cap_t *cap, test_cap_group_t group,
	unsigned int trait)
{
	uint32_t *valp;

	TEST_ASSERT(CAP_TO_INDEX(trait) < _LINUX_CAPABILITY_U32S_3,
		"test_cap_flag_fetch trait out of range, trait: %u", trait);

	switch (group) {
	case TEST_CAP_EFFECTIVE:
		valp = &(*cap + CAP_TO_INDEX(trait))->effective;
		break;

	case TEST_CAP_PERMITTED:
		valp = &(*cap + CAP_TO_INDEX(trait))->permitted;
		break;

	case TEST_CAP_INHERITABLE:
		valp = &(*cap + CAP_TO_INDEX(trait))->inheritable;
		break;

	default:
		TEST_ASSERT(false, "test_cap_flag_fetch unknown group, "
			"group: 0x%x", group);
		/* Not Reached */
		valp = NULL; /* Silences compiler warning */
	}

	return (*valp & CAP_TO_MASK(trait)) != 0;
}

/* Capability Flag Assign
 *
 * Set the current setting of a specified capability trait to the value
 * given by rval.  Note, cap points to an in memory copy of a capability
 * set, which allows unprivileged code to manipulate the capability set.
 * Although unprivileged code will obtain an error if they attempt to use
 * test_cap_set() to make the in-memory copy with a disallowed change
 * effective.
 *
 * Args:
 *   cap   - Pointer to capability set
 *   group - Which group of capabilities, effective, permitted, or
 *           inheritable.
 *   trait - Index of particular trait.  Available indexes are specified
 *           within <linux/capability.h> as CAP_ defines.
 *   rval  - New setting
 *
 * Returns:
 *   Nothing, TEST_ASSERT used on detected failure (e.g. invalid group).
 */
void test_cap_flag_assign(test_cap_t *cap, test_cap_group_t group,
	unsigned int trait, bool rval)
{
	uint32_t *valp;

	switch (group) {
	case TEST_CAP_EFFECTIVE:
		valp = &(*cap + CAP_TO_INDEX(trait))->effective;
		break;

	case TEST_CAP_PERMITTED:
		valp = &(*cap + CAP_TO_INDEX(trait))->permitted;
		break;

	case TEST_CAP_INHERITABLE:
		valp = &(*cap + CAP_TO_INDEX(trait))->inheritable;
		break;

	default:
		TEST_ASSERT(false, "test_cap_flag_assign unknown group, "
			"group: 0x%x", group);
		/* Not Reached */
		valp = NULL; /* Silences compiler warning */
	}

	*valp &= ~CAP_TO_MASK(trait);
	if (rval)
		*valp |= CAP_TO_MASK(trait);
}

/* Significant Bits Floating-Point Comparison
 *
 * Determine the number of significant bits between given expected
 * and actual values.  The number of significant bits is
 * determined by the following factors:
 *
 *   1. Number of matching significant bits within the mantissa after
 *      they have been adjusted so that the exponent of the expected
 *      and actual values would be the same.
 *
 *   2. The difference between the bits less significant than the
 *      matching significant bits.  The amount can be any value
 *      from 0.5 to the number of less significant bits - 0.5.  The
 *      case of 0.5 occurs with the maximum possible difference.  While
 *      a value of the number of less significant bits - 0.5 occurs
 *      for a difference in the less significant bits equal to 1.0.
 *
 *   3. Number of leading zeros for certain subnormal cases.
 *      A subnormal value is a non-zero value that is so small that
 *      the value can't be normalized.  The number of leading zeros
 *      are counted for cases where both the actual and difference
 *      between the expected and actual values are subnormal.
 *
 * Args:
 *   expected - expected value for the comparison
 *   actual   - actual value for the comparison
 *
 * Returns:
 *   Number of significant bits by which expected and actual match.
 *   Zero if expected or actual is equal to infinite, -infinite, or NaN.
 */
float test_sgniff(long double expected, float actual)
{
	return sgnif(expected, actual, FLT_MANT_DIG, FLT_MIN);
}

float test_sgnif(long double expected, double actual)
{
	return sgnif(expected, actual, DBL_MANT_DIG, DBL_MIN);
}

float test_sgnifl(long double expected, long double actual)
{
	return sgnif(expected, actual, LDBL_MANT_DIG, LDBL_MIN);
}

static float sgnif(long double expected, long double actual,
	unsigned int mant_dig, long double min_normalized)
{
	long double diff, scaled;
	float matched_bits;
	unsigned int matched_subnormal = 0;
	long double tmp_val;

	/* Return 0 for any case where expected or actual is INF, -INF,
	 * or NaN.  A design choice was made to always return 0 for
	 * these cases, even for cases where expected and actual are
	 * equal.  Design choice was based on the risk of expected
	 * accidentally being calculated as INF, -INF, or NaN, for the
	 * same reason that an incorrect program calculates the same
	 * value.  Instead of potentially not noticing an improperly
	 * calculated expected value, it is left to the caller to handle
	 * cases where INF, -INF, or NaN is expected.
	 */
	if (isinf(expected) || isinf(actual)
		|| isnan(expected) || isnan(actual))
		return 0.0;

	diff = fabsl(expected - actual);
	if (diff == 0.0)
		return mant_dig;
	scaled = fabsl(expected) / diff;
	if (scaled == 0.0)
		return mant_dig;
	matched_bits = log2l(scaled);

	/* Count leading zeros as matches in cases where actual
	 * is subnormal (!0.0 yet to small to normalize) and difference
	 * is less than min normalized.
	 */
	if ((fabsl(actual) != 0.0) && (fabsl(actual) < min_normalized)) {
		if (matched_bits < 0.0)
			matched_bits = 0.0;
		for (tmp_val = diff, matched_subnormal = 0;
			fabsl(tmp_val) < min_normalized; tmp_val *= FLT_RADIX) {
			matched_subnormal++;
			TEST_ASSERT(matched_subnormal <= mant_dig,
				"%s subnormal with leading zeros > mant_dig,\n"
				"  matched_subnormal: %u\n mant_dig: %u\n"
				"  actual: %Lg tmp_val: %Lg",
				__func__, matched_subnormal, mant_dig,
				actual, tmp_val);
		}
		matched_bits += matched_subnormal;
	}

	/* Bound the number of matched bits to:
	 *
	 *  [0.0, mant_dig]
	 *
	 * A negative number of matched bits occurs when the sign of
	 * expected and actual differ.  When the sign doesn't match
	 * consider the number of matched bits to be 0.0.
	 *
	 * Due to rounding error the calculated number of matched bits
	 * can be slightly greater than the number of available bits.
	 * For such cases the number of matched bits is bound to the
	 * number of available bits.
	 */
	if (signbit(matched_bits))
		matched_bits = 0.0;

	if (matched_bits > mant_dig)
		matched_bits = mant_dig;

	return matched_bits;
}

/* Fetch memory mapping information
 *
 * Search a user-specified process' mappings for an
 * address. If the search is successful, then the test_pg_info
 * struct is populated with the mapping's starting address,
 * ending address, size, protections, and shared status.
 *
 * Note: On success, the retrieved contents will be self-consistent,
 *       but they could describe the mapping's contents from the time
 *       this routine was entered to the time it returns. On failure,
 *       we're only guaranteed that at some time between entry and
 *       completion of this routine, a mapping with the requested address
 *       did not exist. No atomicity is guaranteed between multiple calls.
 * Note: Caller must ensure that the process with the specified pid
 *       stays alive while this function executes; otherwise, a TEST_ASSERT
 *       may be raised.
 *
 * Args:
 *   pid  -  The process whose mappings we'll search. 0 defaults to the
 *           the current process.
 *   addr -  The address for which to retrieve a mapping.
 *
 * Output:
 *   info - On success, a structure populated with information
 *          about the mapping containing the searched-for address.
 *
 * Return:
 *   Zero on success; on error, -1 and errno is set
 *
 * Errors:
 *   ENOENT  - addr not mapped
 */
int test_pg_info(pid_t pid, uint64_t addr, struct test_pg_info *info)
{
	char *path;
	int tmp_ret;
	char *buf;
	int rv;

	/* Construct the path to the proc maps file.
	 * If pid is zero, then default to the current process' maps file.
	 */
	if (pid == 0) {
		path = test_dyn_sprintf("/proc/self/maps");
	} else {
		/* Validate the pid before setting the path:
		 * Kill will set errno to ESRCH if the requested
		 * pid does not exist. Invoking kill with signal number
		 * 0 doesn't actually send a signal to the process;
		 * the primary reason to do this is to check if a
		 * pid exists.
		 *
		 * A process could, however, exit after it successfully
		 * receives the signal 0 but before this routine completes.
		 * Such an exit might render us unable to read the maps file
		 * and may trigger a less informative TEST_ASSERT. It's
		 * the caller's responsibility to ensure that the process
		 * exists throughout the entirety of this routine's lifetime.
		 * Our check here is merely a cautious one.
		 */
		tmp_ret = kill(pid, 0);
		TEST_ASSERT(tmp_ret == 0, "%s requested pid "
			"does not exist, pid: %d errno: %d", __func__,
			pid, errno);
		path = test_dyn_sprintf("/proc/%u/maps", pid);
	}

	/* Read the file in. Though reads might be subject to races, each
	 * line in the fetched buffer should be self-consistent.
	 */
	tmp_ret = test_seq_read(path, &buf, NULL);
	TEST_ASSERT(tmp_ret == TEST_UTIL_SUCCESS, "%s test read (seq)"
		"failure, path: %s ", __func__, path);

	/* Retrieve the mapping. */
	rv = test_pg_info_map(buf, addr, info);

	/* Perform necessary clean-up. */
	free(path);
	free(buf);
	return rv;
}

/* Fetch memory mapping information from buffer
 *
 * This function behaves similarly to test_pg_info: Given an address,
 * it retrieves information about a mapping containing that address.
 * Unlike test_pg_info, this function queries a user-supplied map buffer
 * for a suitable mapping.
 *
 * With test_pg_info_map and a snapshot of a proc maps file,
 * clients can safely perform multiple queries of a process'
 * mappings, even when the process' mappings are actively changing.
 *
 * A typical usage pattern might involve:
 *  1) taking a snapshot of a process-specific maps file with
 *     test_read(true, ...), and
 *  2) searching that snapshot with test_pg_info_map
 * where 2) can be repeated as many times as desired.
 *
 * Args:
 *   map  - A null-terminated string, formatted as a /proc/\*\/maps file,
 *	    to be queried for the address.
 *   addr - The address for which to retrieve a mapping.
 *
 * Output:
 *   info - On success, a structure populated with information
 *	    about the mapping containing the searched-for address.
 *
 * Return:
 *   Zero on success; on error, -1 and errno is set
 *
 * Errors:
 *   ENOENT - addr not mapped
 */

int test_pg_info_map(const char *map, uint64_t addr, struct test_pg_info *info)
{
	int tmp_ret;
	int rv;
	const char *rest;
	size_t max_nibbles;
	uint64_t curr_start;
	uint64_t curr_end;
	uint64_t inclusive_end;
	char perm[CONST_STRLEN("rwxp")];
	int prot;
	bool shared;

	/* Search for a mapping that includes addr. Populate info if such a
	 * mapping is found.
	 *
	 * Each line of the /proc/[pid]/maps file has the following format:
	 *
	 * [start_address]-[end_address + 1] [perms] [offset] \
	 *               [dev] [inode] [pathname]
	 *
	 * test_pg_info returns information from the first three fields.
	 * For more information on the proc maps file, see man proc(5).
	 */
	rest = map;
	while (true) {
		/* Parse the line. */
		tmp_ret = sscanf(rest, "%" PRIx64 "-%" PRIx64 " %4s %*[^\n]",
			&curr_start, &curr_end, perm);
		if (tmp_ret == EOF) {
			rv = -1;
			errno = ENOENT;
			goto done;
		}
		if (tmp_ret != 3) {
			TEST_ASSERT(false,
				"%s Parsing error, line: %.*s ""rv: %d",
				__func__, (int)line_len(rest), rest, tmp_ret);
		}

		/* Convert the exclusive end address to an inclusive one.
		 * This is typically done by subtracting 1 from the former;
		 * however, if the exclusive end address is 0, then we need
		 * to determine the width of desired inclusive address
		 * in order to appropriately wrap to the address maximum.
		 */
		if (curr_end != 0) {
			inclusive_end = curr_end - 1;
		} else {
			max_nibbles = proc_maps_max_nibbles(map);

			/* It's undefined to left-shift a value by a number
			 * greater than its data type's bit-width.
			 */
			if (max_nibbles == TEST_PG_MAX_NIBBLES)
				inclusive_end = ((uint64_t) 0) - 1;
			else
				inclusive_end = ((uint64_t)1 <<
					(max_nibbles * 4)) - 1;
		}
		TEST_ASSERT((curr_start % getpagesize()) == 0,
			"%s start address should be divisible by page size, "
			"curr_start: %" PRIx64 " page_size: %d",
			__func__, curr_start, getpagesize());
		TEST_ASSERT((inclusive_end % getpagesize())
			== (getpagesize() - 1),
			"%s end address does not lie before a "
			" page boundary, inclusive_end: %" PRIx64
			" page_size: %d",
			__func__, inclusive_end, getpagesize());
		TEST_ASSERT(inclusive_end > curr_start, "%s end addr not "
			"less than start addr, inclusive_end: %" PRIx64
			" curr_start: %" PRIx64, __func__, inclusive_end,
			curr_start);

		/* If we've found a suitable mapping, save its state. */
		if (curr_start <= addr && addr <= inclusive_end) {
			parse_perm(perm, &prot, &shared);
			info->start = curr_start;
			info->end = inclusive_end;
			info->size = (size_t)(inclusive_end - curr_start + 1);
			info->prot = prot;
			info->shared = shared;
			rv = 0;
			goto done;
		}

		/* Advance to the next line. */
		rest = strchr(rest, '\n');
		if (rest == NULL) {
			rv = -1;
			errno = ENOENT;
			goto done;
		}
		rest++;
	}
done:
	TEST_ASSERT(((rv == 0) || (rv == -1)) &&
		((rv == 0) || (errno != 0)),
		"%s Invalid completion of function, "
		"rv: %d errno: %d", __func__, rv, errno);
	return rv;
}

/* Set prot to carry the flags indicated in the character array
 * of permissions. Permissions are represented as three contiguous
 * characters, with a letter for a granted permission and a dash for a
 * withheld permission, in the order "read, write, execute." An
 * 's' or a 'p' is appended if the mapping is shared or private,
 * respectively.
 *
 * As an example, private, RO memory would be represented as: r--p
 */
static void parse_perm(const char *perm, int *prot, bool *shared)
{
	*prot = 0;
	*shared = false;

	if (perm[0] == 'r')
		*prot |= PROT_READ;
	if (perm[1] == 'w')
		*prot |= PROT_WRITE;
	if (perm[2] == 'x')
		*prot |= PROT_EXEC;
	if (perm[3] == 's')
		*shared = true;
	else
		*shared = false;

	if (*prot == 0)
		prot = PROT_NONE;
}

/* Correctness-Testable Memory Allocation
 *
 * Provides the user with size bytes of memory. Users can specify flags
 * to which they want the memory to conform; these flags provide
 * safeguards that allow test_malloc to validate the integrity of the memory
 * it allocates. If no alignment is requested, then test_malloc guarantees
 * that the returned address will be aligned by the size of the largest
 * fundamental type that could fit within the structure.
 * test_malloc does not guarantee that the memory will be aligned
 * by higher powers of 2; as such, if the alloc size is less than
 * __BIGGEST_ALIGNMENT, then test_malloc may produce alignments less than
 * __BIGGEST_ALIGNMENT__
 *
 * Supported flags include:
 *   TEST_MALLOC_PROT_BEFORE: Insert a guard page with protection PROT_NONE
 *                            before the user paylod.
 *   TEST_MALLOC_PROT_AFTER:  Insert a guard page with protection PROT_NONE
 *                            after the user payload.
 *
 *   Note: If users request a size that's an integer multiple of the
 *         page size, then they may request both a before and after guard page.
 *         Else, users must either request exactly one or zero guard pages.
 *
 *   TEST_MALLOC_ALIGN:       Align the user payload to the power-of-2 number
 *                            of bytes specified. When possible, the
 *                            returned address won't be aligned by higher
 *                            powers of two.
 *
 *   TEST_MALLOC_MMAP_FD:     Mmap for the user area an fd provided in the
 *                            optional list. Requires PROT_BEFORE, _AFTER,
 *                            and _ALIGN to be set. Requires a valid fd to
 *                            be passed (after alignment size) in the list
 *                            of optional arguments.
 *
 *   TEST_MALLOC_MMAP_FD_OFFSET: If doing mmap of an fd, rather than mmap at
 *                               offset zero use the provided offset (passed
 *                               after the fd).
 *
 * Supported optional arguments include (must be provided in this order):
 *   size_t align_bytes: align by a power-of-two number of bytes. align_bytes
 *                       must be less than both the requested size and the
 *                       system's page size. Where possible, the address
 *                       is not aligned to powers of 2 greater than align_bytes.
 *                       If align_bytes is 0, the structure is aligned to the
 *                       largest type that could fit in the structure --
 *                       when possible, no larger alignments are satisfied.
 *
 *   int fd:             mmap this fd for the user area if _MMAP_FD passed as a
 *                       flag. Must be valid fd of course. Must follow
 *                       align_bytes.
 *
 *   off_t offset:       offset at which to mmap if _MMAP_FD and valid fd. If
 *                       not provided assumed zero. Must follow fd. Must have
 *                       set _MMAP_FD_OFFSET flag.
 *
 *   Note: If a trailing guard page is requested with an alignment
 *         that would require a trailing buffer, a TEST_ASSERT
 *         is triggered.
 *
 * Red zones: A red zone is placed on each side of the user payload. If guard
 *            pages are present, then the red zones bleed into these pages.
 *
 * Args:
 *   size  - The number of bytes to allocate for the user. Must be non-zero.
 *   flags - The bitvector into which flags are or'd into.
 *   ...   - Optional arguments. Currently, only size_t align_bytes.
 *
 * Return:
 *   A pointer to the beginning of the user's payload. NULL is never returned;
 *   a TEST_ASSERT is triggered in out-of-memory conditions.
 */
void *test_malloc(size_t size, uint32_t flags, ...)
{
	size_t align_bytes;
	int pos;
	struct test_malloc_alloc *allocp;
	int fd = -1;
	off_t offset = 0;

	/* Validate input. */
	TEST_ASSERT(size != 0, "%s size must be non-zero",
		__func__);
	if ((flags & TEST_MALLOC_PROT_BEFORE) &&
		(flags & TEST_MALLOC_PROT_AFTER))
		TEST_ASSERT(size % getpagesize() == 0,
		"%s When two guard pages "
		"are requested, size must be a multiple of the page size, "
		"size: %zu page_size: %d", __func__, size, getpagesize());
	if (flags & TEST_MALLOC_MMAP_FD) {
		TEST_ASSERT(flags & TEST_MALLOC_PROT_BEFORE,
			"%s Set mmap fd flag but not required to mmap at "
			"page boundary", __func__);
		TEST_ASSERT(flags & TEST_MALLOC_PROT_AFTER,
			"%s Set mmap fd flag but not required to mmap "
			"ending at a page boundary", __func__);
		TEST_ASSERT(flags & TEST_MALLOC_ALIGN,
			"%s Set mmap fd flag but not required to mmap "
			"with an alignment", __func__);
	}

	/* Parse the optional arguments. */
	va_list ap;
	va_start(ap, flags);
	align_bytes = 0;
	if (flags & TEST_MALLOC_ALIGN) {
		align_bytes = va_arg(ap, size_t);

		/* align_bytes must be either 0 or a power of two, and
		 * must no greater than the requested payload size
		 * and the page size.
		 */
		TEST_ASSERT((align_bytes & (align_bytes - 1)) == 0, "%s "
			"alignment must be 0 or a power of 2, align_bytes: %zu",
			__func__, align_bytes);
		TEST_ASSERT(align_bytes <= size, "%s Cannot align greater "
			"than size bytes, align_bytes: %zu size: %zu",
			__func__, align_bytes, size);
		TEST_ASSERT(align_bytes <= getpagesize(),
			"%s alignment can be no greater than "
			"TEST_MALLOC_MAX_ALIGN, align_bytes: %zu "
			"MAX_ALIGN: %d", __func__, align_bytes,
			getpagesize());
	}

	if (flags & TEST_MALLOC_MMAP_FD) {
		fd = va_arg(ap, int);
		TEST_ASSERT((align_bytes % getpagesize()) == 0,
			"%s When mmaping an fd must pass an alignment that "
			"is a multiple of a page size (instead of %u)",
			__func__, (unsigned int) align_bytes);
		TEST_ASSERT(fd >= 0,
			"%s Invalid fd %d passed for mmaping",
			__func__, fd);
		if (flags & TEST_MALLOC_MMAP_FD_OFFSET) {
			offset = va_arg(ap, off_t);
			TEST_ASSERT((offset % getpagesize()) == 0,
				"%s When mmaping an fd must pass an offset "
				" that is a multiple of a page size (instead "
				"of %llu)", __func__,
				(unsigned long long) offset);
		}
	}

	if (align_bytes == 0) {
		/* Even if the user hasn't explicitly requested an alignment,
		 * we need to ensure that the structure is properly aligned
		 * (for portability's sake).
		 *
		 * We assume that the allocation size supplied to this
		 * function accounts for compiler-added padding. When
		 * aligning, we guarantee that the structure will
		 * be aligned by the size of its greatest fundamental
		 * type, and will ensure that it is not aligned by
		 * higher powers of two. When we cannot determine
		 * the size of the greatest fundamental type in the structure,
		 * (e.g., if the allocation size were 4 bytes, then
		 * we don't know whether the structure consists of
		 * 2 16 byte members or one 32 byte members),
		 * we assume the larger of the possible
		 * types (continuing our example, the 4 byte structure
		 * would be aligned by 4).
		 *
		 * Alignments are as follows:
		 * size       alignment
		 * 1         1
		 * 2         2
		 * 3*        1
		 * 4         4
		 * 5         1
		 * 6         2
		 * 7         1
		 * 8         8
		 *
		 * and so on -- the pattern continues with the
		 * size modulo __BIGGEST_ALIGNMENT__.
		 *
		 * *If a structure consisted of a uint16_t and a uint8_t,
		 * then the compiler would have padded its size to 4 --
		 * the smallest multiple of uint16_t. Thus, we know that
		 * the structure must consist of 3 uint8_ts. Similar
		 * reasoning can be applied to sizes 6 and 7. If the
		 * user changes alignment requirements and overrides the
		 * default structure packing (by, say, using #pragma pack),
		 * then he is fully responsible for generating code
		 * that accesses the structure in an alignment-agnostic
		 * manner.
		 */
		pos = ffs(__BIGGEST_ALIGNMENT__ | size);
		TEST_ASSERT(pos != 0, "%s No LSB set (according to ffs)"
			", rv: %d size: %zu biggest alignment: %d",
		__func__, pos, size, __BIGGEST_ALIGNMENT__);
		align_bytes = 1 << (pos - 1);
	}
	va_end(ap);

	/* Allocate space to track this allocation. */
	allocp = malloc(sizeof(*allocp));
	TEST_ASSERT(allocp != NULL, "%s Insufficient memory, "
		"requested size: %zu", __func__, sizeof(*allocp));

	/* Create the allocation and return its user address. */
	malloc_create(allocp, size, flags, align_bytes, fd, offset);
	TEST_ASSERT(allocp->user_addr != NULL, "%s unexpected "
		" NULL pointer after malloc_create", __func__);
	return allocp->user_addr;
}

/* Free memory allocated with test_malloc()
 *
 * Given a pointer to memory allocated with test_malloc(), free it and any
 * other memory that test_malloc() allocated to maintain it (including the alloc
 * struct). Additionally, vet the red zones to ensure that they haven't changed.
 *
 * TEST_ASSERTS are triggered if the pointer is invalid (i.e., NULL pointer or
 * not allocated by test_malloc()).
 *
 * Args:
 *   ptr - a pointer to memory allocated with test_malloc
 */
void test_malloc_free(void *addr)
{
	struct test_malloc_alloc *found;
	int tmp;

	TEST_ASSERT(addr != NULL, "%s invalid argument (NULL pointer)",
		__func__);

	/* Find the alloc and remove it from the list. */
	found = malloc_query(addr, true);
	TEST_ASSERT(found != NULL, "%s couldn't find pointer in alloc list "
		 "addr: %p", __func__, addr);

	if (found->mmaped) {
		tmp = munmap(found->start_addr, found->alloc_size);
		TEST_ASSERT(tmp == 0,
			"%s failed to munmap, start_addr: %p size: %zu "
			"addr: %p rv: %i errno: %d", __func__,
			found->start_addr, found->alloc_size, addr, tmp, errno);
	} else {
		free(found->start_addr);
	}

	free(found);
}

/*
 * Protect the supplied pointer with requested protections.
 *
 * Args:
 *   addr - The test-malloc-ed address to protect.
 *   prot - the bitwise or of one or more of PROT_READ, PROT_WRITE,
 *          PROT_EXEC, and PROT_NONE.
 */
void test_malloc_chg_prot(const void *addr, int prot)
{
	struct test_malloc_alloc *allocp;
	void *prot_addr;
	size_t prot_len;
	int tmp;

	/* Find the allocation corresponding to the supplied pointer,
	 * but do not remove it from the list.
	 */
	allocp = malloc_query(addr, false);
	TEST_ASSERT(allocp != NULL, "%s couldn't find pointer in alloc list "
		 "addr: %p", __func__, addr);

	/* We must be allowed to change permissions. */
	TEST_ASSERT(allocp->flags & TEST_MALLOC_ALLOW_PROT_CHG,
		"%s Payload does not have the "
		"TEST_MALLOC_ALLOW_PROT_CHG flag, user_addr: %p",
		__func__, addr);
	TEST_ASSERT(allocp->mmaped == true, "%s Memory allocated "
		"with ALLOW_PROT_CHG was not mmaped, start_addr: %p"
		"alloc size: %zu", __func__, allocp->start_addr,
		allocp->alloc_size);

	/* Calculate the address and length to mprotect.
	 *
	 * Since mprotect requires the address to be a multiple
	 * of the page size, we can't simply apply the new protections
	 * to the user address for user_size bytes.
	 */
	if (allocp->flags & TEST_MALLOC_PROT_BEFORE) {
		/* If there's a leading guard page, then
		 * the user address must sit on a page boundary.
		 * In this case, we can in fact apply our protections
		 * this address.
		 */
		prot_addr = allocp->user_addr;
		prot_len = allocp->user_size;
	} else if (allocp->flags & TEST_MALLOC_PROT_AFTER) {
		/* If there's a trailing guard page, then there's
		 * no guarantee that the user address will sit on
		 * a page boundary. Thus, we apply the protections
		 * to the starting address. Because the user payload
		 * will be preceded by a red zone buffer, we need
		 * to spread the protections over user_size +
		 * RED_ZONE_SIZE bytes.
		 */
		prot_addr = allocp->start_addr;
		prot_len = allocp->user_size +
			TEST_MALLOC_RED_ZONE_SIZE;
	} else {
		/* If there are no guard pages, we can simply apply the
		 * protections to the entire allocation.
		 */
		prot_addr = allocp->start_addr;
		prot_len = allocp->alloc_size;
	}

	/* Apply the protections. */
	tmp = mprotect(prot_addr, prot_len, prot);
	TEST_ASSERT(tmp == 0, "%s failed to mprotect, "
		"addr: %p len: %zu rv: %d errno: %d",
		__func__, prot_addr, prot_len, tmp, errno);
}

/* Retrive flags for allocation
 *
 * Args:
 *  addr - The test-malloc-ed address for which to retrieve flags
 *
 * Return:
 *  the allocation's flags. On error, a TEST_ASSERT is triggered.
 */
uint32_t test_malloc_get_flags(const void *addr)
{
	struct test_malloc_alloc *allocp;

	/* Find the allocation corresponding to the supplied pointer,
	 * but do not remove it from the list.
	 */
	allocp = malloc_query(addr, false);
	TEST_ASSERT(allocp != NULL, "%s couldn't find pointer in alloc list "
		 "addr: %p", __func__, addr);
	return allocp->flags;

}

/* Satisfies a test_malloc request and populates a pre-allocated alloc. */
static void malloc_create(struct test_malloc_alloc *allocp,
	size_t size, uint32_t flags, size_t align_bytes, int fd, off_t offset)
{
	size_t alloc_size;
	void *user_addr;
	void *start_addr;
	bool use_mmap = flags & (TEST_MALLOC_ALLOW_PROT_CHG |
		TEST_MALLOC_PROT_BEFORE | TEST_MALLOC_PROT_AFTER);
	size_t pad_before_size;
	size_t pad_after_size;
	size_t align_buffer;
	size_t tmp;

	/* Each allocation will always have two red zones -- if guard pages
	 * pages are requested, then the red zones are nested within them.
	 */
	pad_before_size = flags & TEST_MALLOC_PROT_BEFORE ? getpagesize() :
		TEST_MALLOC_RED_ZONE_SIZE;
	pad_after_size = flags & TEST_MALLOC_PROT_AFTER ? getpagesize() :
		TEST_MALLOC_RED_ZONE_SIZE;

	/* If there are no boundary pages, then we can ensure that
	 * payloads are not aligned by higher powers of two. While we only
	 * need align_bytes - 1 to get the specified alignment, we need
	 * align_bytes * 2 - 1 to ensure that alignment is not met
	 * at higher powers of 2.
	 */
	if (!(flags & (TEST_MALLOC_PROT_BEFORE | TEST_MALLOC_PROT_AFTER)))
		align_buffer = align_bytes * 2 - 1;
	else
		align_buffer = 0;

	/* Calculate the allocation size, taking guard pages, red zones,
	 * and alignment into account.
	 */
	alloc_size = size + pad_before_size + pad_after_size + align_buffer;

	/* Allocate the memory. */
	if (use_mmap) {
		start_addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		TEST_ASSERT(start_addr != MAP_FAILED, "%s Anon mmap failed, "
			"requested size: %zu", __func__, alloc_size);
	} else
		start_addr = malloc(alloc_size);
	TEST_ASSERT(start_addr != NULL, "%s Insufficient memory, "
		"requested size: %zu", __func__, alloc_size);

	/* Find the user_addr, taking alignment into account
	 *
	 * The entire user payload plus red zones are filled with poison data;
	 * only the red zones, however, are validated upon free.
	 *
	 * Note: We don't explicity work to meet alignment requests when a
	 * leading guard page is requested. Its presence guarantees that the
	 * user address will sit on a page boundary and thus be aligned.
	 */
	if (flags & TEST_MALLOC_PROT_BEFORE) {
		/* If there's a leading guard page, then the user payload
		 * and the poison data must lie exactly one page after it.
		 */
		user_addr = PTR_ADD(start_addr, getpagesize());

		/* We won't add buffers between the user payload and
		 * guard page in order to meet alignment requests.
		 */
		TEST_ASSERT((uintptr_t)user_addr
			 % align_bytes == 0, "%s cannot align "
			"structure, size: %zu align_bytes: %zu",
			__func__, size, align_bytes);

	} else if (flags & TEST_MALLOC_PROT_AFTER) {
		/* If there's a trailing guard page and no leading guard page,
		 * then the user payload sits size bytes before it.
		 */
		user_addr = PTR_ADD(start_addr,
			CEIL_BYTES_TO_PAGES(size + TEST_MALLOC_RED_ZONE_SIZE)
			* getpagesize() - size);

		/* We won't add buffers between the user payload and
		 * guard page in order to meet alignment requests.
		 */
		TEST_ASSERT((uintptr_t)user_addr
			 % align_bytes == 0, "%s cannot align "
			"structure, size: %zu align_bytes: %zu",
			__func__, size, align_bytes);
	} else {
		/* Otherwise, if there are no guard pages, then the user
		 * address lies at least RED_ZONE_SIZE bytes ahead of the
		 * starting addresses. If we need to align the address,
		 * however, the user address may be pushed up further.
		 */
		user_addr = PTR_ADD(start_addr, TEST_MALLOC_RED_ZONE_SIZE);

		/* Align user_addr by align_bytes. */
		tmp = (uintptr_t)user_addr % align_bytes;
		user_addr = (tmp != 0)
			? PTR_ADD(user_addr, (align_bytes - tmp))
			: user_addr;

		/* user_addr shouldn't be divisible by
		 * powers of two greater than align_bytes.
		 */
		user_addr = ((uintptr_t)user_addr % (align_bytes * 2)
			== 0)
			? PTR_ADD(user_addr, align_bytes)
			: user_addr;
	}

	/* Protect the guard pages. */
	if (flags & TEST_MALLOC_PROT_BEFORE)
		mprotect(start_addr, getpagesize(), PROT_NONE);
	if (flags & TEST_MALLOC_PROT_AFTER)
		mprotect(PTR_ADD(user_addr, size), getpagesize(), PROT_NONE);

	/* If fd, remap the user_addr backing it up with fd. First, munmap the
	 * target user region (we don't [want a | care about the] private anon
	 * region there).  Leave the guard pages, before and after, in place,
	 * as PROT_NONE.  Then, mmap again into the user region the intended
	 * fd, offset, and size. Later when cleaning up, a single munmap of
	 * [before guard page, fd mmap, after guard page] will clean up
	 * everything in one fell swoop. */
	if (flags & TEST_MALLOC_MMAP_FD) {
		void *check;
		TEST_ASSERT(0 == munmap(user_addr, size),
				"%s Could not munmap the actual user area "
				"in other to re map with fd (errno %d)",
				__func__, errno);
		check = mmap(user_addr, size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED, fd, offset);
		TEST_ASSERT(check == user_addr,
				"%s Could not remap fd %d at address %p "
				"with request size: %llu (errno %d)",
				__func__, fd, user_addr,
				(unsigned long long) size, errno);
	}

	/* Update the alloc and add it to the head of the list. */
	allocp->next = alloc_list;
	allocp->user_addr = user_addr;
	allocp->start_addr = start_addr;
	allocp->user_size = size;
	allocp->alloc_size = alloc_size;
	allocp->flags = flags;
	allocp->mmaped = use_mmap;
	alloc_list = allocp;
}

/* Retrieves an alloc from the list and, if remove is true,
 * unlinks it from the list as well.
 */
static struct test_malloc_alloc *malloc_query(const void *addr, bool unlink)
{
	struct test_malloc_alloc *curr, *prev;
	curr = prev = NULL;
	for (curr = alloc_list; curr != NULL; curr = curr->next) {
		if (curr->user_addr == addr)
			break;
		prev = curr;
	}
	if (curr && unlink) {
		if (prev)
			prev->next = curr->next;
		else
			alloc_list = curr->next;
	}
	return curr;
}

/* Retrieve the maximum width in nibbles of all the addresses
 * represented in map, where map is a string in the format
 * of a valid /proc/\*\/maps file.
 */
static int proc_maps_max_nibbles(const char *map)
{
	const char *chptr1, *chptr2;
	int curr_nibbles;
	int max_nibbles = -1;
	const char *rest = map;
	while (true) {
		/* See if the length of the first address gives us a new max. */
		for (chptr1 = chptr2 = rest; isxdigit(*chptr2); chptr2++)
			;
		if (*chptr2 != '-') {
			TEST_ASSERT(false, "%s Parsing error, line: %.*s",
				__func__, (int)line_len(rest), rest);
		}
		curr_nibbles = chptr2 - chptr1;
		if (curr_nibbles > max_nibbles)
			max_nibbles = curr_nibbles;

		/* See if the length of the 2nd address gives us a new max. */
		for (chptr1 = ++chptr2; isxdigit(*chptr2); chptr2++)
			;
		if (*chptr2 != ' ') {
			TEST_ASSERT(false, "%s Parsing error, line: %.*s",
				__func__, (int)line_len(rest), rest);
		}
		curr_nibbles = chptr2 - chptr1;
		if (curr_nibbles > max_nibbles)
			max_nibbles = curr_nibbles;

		/* Advance to the next line. */
		rest = strchr(rest, '\n');
		if (rest == NULL || *(++rest) == '\0')
			break;
	}

	/* The width must be non-zero and no greater than the maximum allowed
	 * bit-width. */
	TEST_ASSERT((max_nibbles > 0) && (max_nibbles <= TEST_PG_MAX_NIBBLES),
		"%s invalid max_nibbles (likely because "
		"the maps file is invalid), max_nibbles: %d "
		"map:\n%s\n", __func__, max_nibbles, map);
	return max_nibbles;
}

/* Given a string, returns the number of characters included in the range
 * [str, '\n'). If no newline is present, returns the length of the string.
 */
static size_t line_len(const char *str)
{
	const char *chptr;
	chptr = strchrnul(str, '\n');
	return chptr - str;
}

/* Test Write
 *
 * A wrapper for write(2), that automatically handles the following
 * special conditions:
 *
 *   + Interrupted system call (EINTR)
 *   + Write of less than requested amount
 *   + Non-block return (EAGAIN)
 *
 * For each of the above, an additional write is performed to automatically
 * continue writing the requested data.
 * There are also many cases where write(2) can return an unexpected
 * error (e.g. EIO).  Such errors cause a TEST_ASSERT failure.
 *
 * Note, for function signature compatibility with write(2), this function
 * returns the number of bytes written, but that value will always be equal
 * to the number of requested bytes.  All other conditions in this and
 * future enhancements to this function either automatically issue another
 * write(2) or cause a TEST_ASSERT failure.
 *
 * Args:
 *  fd    - Opened file descriptor to file to be written.
 *  count - Number of bytes to write.
 *
 * Output:
 *  buf   - Starting address of data to be written.
 *
 * Return:
 *  On success, number of bytes written.
 *  On failure, a TEST_ASSERT failure is caused.
 */
ssize_t test_write(int fd, const void *buf, size_t count)
{
	ssize_t write_rv;
	ssize_t num_written = 0;
	size_t num_left = count;
	const char *ptr = buf;

	/* Note: Count of zero is allowed (see "RETURN VALUE" portion of
	 * write(2) manpage for details.
	 */
	TEST_ASSERT(count >= 0, "Unexpected count, count: %li", count);

	do {
		write_rv = write(fd, ptr, num_left);

		switch (write_rv) {
		case -1:
			if ((errno = EAGAIN) || (errno == EINTR))
				continue;
			TEST_ASSERT(false, "Unexpected write failure,\n"
				"  rv: %zi errno: %i", write_rv, errno);
			/* NOT REACHED */
			exit(1);

		default:
			TEST_ASSERT(write_rv >= 0, "Unexpected rv from write,\n"
				"  rv: %zi errno: %i", write_rv, errno);
			TEST_ASSERT(write_rv <= num_left, "More bytes written "
				"then requested,\n"
				"  rv: %zi num_left: %zi", write_rv, num_left);
			num_written += write_rv;
			num_left -= write_rv;
			ptr = ptr + write_rv;
			break;
		}
	} while (num_written < count);

	return num_written;
}

/* Test Read
 *
 * A wrapper for read(2), that automatically handles the following
 * special conditions:
 *
 *   + Interrupted system call (EINTR)
 *   + Read of less than requested amount
 *   + Non-block return (EAGAIN)
 *
 * For each of the above, an additional read is performed to automatically
 * continue reading the requested data.
 * There are also many cases where read(2) can return an unexpected
 * error (e.g. EIO).  Such errors cause a TEST_ASSERT failure.  Note,
 * it is expected that the file opened by fd at the current file position
 * contains at least the number of requested bytes to be read.  A TEST_ASSERT
 * failure is produced if an End-Of-File condition occurs, before all the
 * data is read.  It is the callers responsibility to assure that sufficient
 * data exists.
 *
 * Note, for function signature compatibility with read(2), this function
 * returns the number of bytes read, but that value will always be equal
 * to the number of requested bytes.  All other conditions in this and
 * future enhancements to this function either automatically issue another
 * read(2) or cause a TEST_ASSERT failure.
 *
 * Args:
 *  fd    - Opened file descriptor to file to be read.
 *  count - Number of bytes to read.
 *
 * Output:
 *  buf   - Starting address of where to write the bytes read.
 *
 * Return:
 *  On success, number of bytes read.
 *  On failure, a TEST_ASSERT failure is caused.
 */
ssize_t test_read(int fd, void *buf, size_t count)
{
	ssize_t read_rv;
	ssize_t num_read = 0;
	size_t num_left = count;
	void *ptr = buf;

	/* Note: Count of zero is allowed (see "If count is zero" portion of
	 * read(2) manpage for details.
	 */
	TEST_ASSERT(count >= 0, "Unexpected count, count: %li", count);

	do {
		read_rv = read(fd, ptr, num_left);

		switch (read_rv) {
		case -1:
			if ((errno = EAGAIN) || (errno == EINTR))
				continue;
			TEST_ASSERT(false, "Unexpected read failure,\n"
				"  rv: %zi errno: %i", read_rv, errno);
			break;

		case 0:
			TEST_ASSERT(false, "Unexpected EOF,\n"
				"  rv: %zi num_read: %zi num_left: %zu",
				read_rv, num_read, num_left);
			break;

		default:
			TEST_ASSERT(read_rv > 0, "Unexpected rv from read,\n"
				"  rv: %zi errno: %i", read_rv, errno);
			TEST_ASSERT(read_rv <= num_left, "More bytes read "
				"then requested,\n"
				"  rv: %zi num_left: %zi", read_rv, num_left);
			num_read += read_rv;
			num_left -= read_rv;
			ptr = (void *) ((uintptr_t) ptr + read_rv);
			break;
		}
	} while (num_read < count);

	return num_read;
}

/* Read contents of sequential file
 *
 * Given a path to a sequential file, allocate and return a buffer that
 * contains its contents. We do NOT guarantee a thread safe read; that is,
 * other processes can race with our attempt to read the provided
 * path. However, each line read should be self-consistent.
 *
 * This function could be useful to read, say, sequential files.
 *
 * Args:
 *  path -   the pathname to the file to open
 *
 * Output:
 *  size - If not supplied as NULL, points to the number of bytes
 *         held by the output buffer.
 *  buf  - A pointer to the allocated buffer.
 *
 * Return:
 *  On success, returns TEST_UTIL_SUCCESS. Failures trigger
 *  TEST_ASSERTs.
 */
int test_seq_read(const char *path, char **bufp, size_t *sizep)
{
	int fd;
	int tmp;
	char *buf;
	size_t buf_len;
	int tmp_read;
	size_t read_bytes;
	size_t max_read;
	off_t prev_partial_offset;
	size_t buf_initial_size;
	size_t buf_growth_amt;

	/* Validate input. */
	TEST_ASSERT(bufp != NULL, "%s unexpected NULL pointer ",
		__func__);
	TEST_ASSERT(path != NULL, "%s unexpected NULL pointer ",
		__func__);

	/* Open the file. */
	fd = open(path, O_RDONLY);
	TEST_ASSERT(fd >= 0, "%s failed to open file, path: %s errno: %d",
		__func__, path, errno);

	/* Initial buf size and growth amount. Each time the size
	 * of the buffer is found to be insufficient, it is grown
	 * by the growth amount.
	 *
	 * Note: For the forward progress detection logic (see
	 * use of prev_partial_offset) to be valid, the growth
	 * amount must be >= the length of the longest line.
	 */
	buf_initial_size = getpagesize();
	buf_growth_amt = 2 * getpagesize();
	TEST_ASSERT(buf_growth_amt >= getpagesize(), "%s buf_growth_amt "
		"is too small, buf_growth_amt: %zu page_size: %d",
		__func__, buf_growth_amt, getpagesize());

	/* Allocate the buffer. */
	buf_len = buf_initial_size;
	buf = malloc(buf_len);
	TEST_ASSERT(buf != NULL, "%s insufficent memory, "
		"buf_len: %zu", __func__, buf_len);

	/* Fetch the file.
	 *
	 * For all seq_files, we guarantee that the retrieved data will be
	 * self-consistent in each line. Seq_files are read by
	 * seq_read, which buffers each line as it begins to read it
	 * -- thus the assumption of self-consistent lines per single reads.
	 * For more information, see fs/seq_file.c and fs/task_mmu.c
	 *
	 * In order to guarantee this line-level self-consistency, we cannot
	 * read partial lines. If we have reason to believe that a partial
	 * read occurred (i.e., if the last byte read was not a newline),
	 * then we lseek back to the beginning of the file, increase the
	 * size of the buffer if necessary, and begin reading once again.
	 *
	 * If we're reading a generic file, then we can't guarantee
	 * any atomicity.
	 */
	read_bytes = 0;
	prev_partial_offset = 0;
	while (true) {
		max_read = buf_len - read_bytes - 1;
		tmp_read = read(fd, buf + read_bytes, max_read);
		TEST_ASSERT(tmp_read >= 0 && tmp_read <= max_read,
			"%s failed call to system call read, "
			"fd: %d read_bytes: %zu rv: %d, errno: %d.",
			__func__, fd, read_bytes, tmp_read, errno);
		read_bytes += tmp_read;

		/* If we've successfully read the entire file, then
		 * read should have returned 0.
		 */
		if (tmp_read == 0) {
			buf[read_bytes] = '\0';
			break;
		}

		/* Cautiously check that we can support this line length. */
		tmp = line_len(buf + read_bytes);
		TEST_ASSERT(tmp <= buf_growth_amt, "%s insufficetly small "
			"growth amount, buf_growth_amt: %zu line_len: %d",
			__func__, buf_growth_amt, tmp);

		/* If the last byte read was not a newline, then we've
		 * violated our atomicity guarantee -- i.e., that
		 * the contents of the buffer will have self-consistent
		 * lines. Unfortunately, that means we'll have to reread
		 * the fd from byte 0.
		 */
		if ((buf[read_bytes - 1] != '\n')) {

			/* If we hit a partial line, we should be at an
			 * offset greater than the one we were at the last
			 * time we hit a partial line.
			 */
			TEST_ASSERT(read_bytes > prev_partial_offset, "%s "
				"No forward progress, prev_partial_offset: %zu "
				"read_bytes: %zu", __func__,
				prev_partial_offset, read_bytes);
			TEST_ASSERT(read_bytes == buf_len - 1,
				"%s partial line encountered before entire "
				"buffer was consumed, read_bytes: %zu "
				"buf_len: %zu", __func__, read_bytes,
				buf_len - 1);

			prev_partial_offset = read_bytes;
			tmp = lseek(fd, SEEK_SET, 0);
			TEST_ASSERT(tmp == 0, "%s failed to lseek to "
				"byte 0, fd: %d errno: %d",
			__func__, fd, errno);

			/* Since we're reading from the beginning of the
			 * fd, at the start of the next iteration we'll have
			 * read 0 bytes.
			 */
			read_bytes = 0;
		}

		/* If we read as much as we requested, then
		 * it's very likely that we haven't read the entire file yet.
		 * We'll cautiously increase the size of our buffer.
		 */
		if (tmp_read == max_read) {
			buf_len += 2 * getpagesize();
			buf = realloc(buf, buf_len);
			TEST_ASSERT(buf != NULL,
				"%s Insufficient memory while reallocating, "
			"buf_len: %zu", __func__, buf_len);
		}
	}

	/* Perform the necessary clean-up and store the output. */
	close(fd);
	*bufp = buf;
	if (sizep != NULL)
		*sizep = read_bytes;
	return TEST_UTIL_SUCCESS;
}

void test_elfhdr_get(const char *filename, Elf64_Ehdr *hdrp)
{
	off_t offset_rv;

	/* Open the ELF file. */
	int fd;
	fd = open(filename, O_RDONLY);
	TEST_ASSERT(fd >= 0, "Failed to open ELF file,\n"
		"  filename: %s\n"
		"  rv: %i errno: %i", filename, fd, errno);

	/* Read in and validate ELF Identification Record.
	 * The ELF Identification record is the first 16 (EI_NIDENT) bytes
	 * of the ELF header, which is at the beginning of the ELF file.
	 * For now it is only safe to read the first EI_NIDENT bytes.  Once
	 * read and validated, the value of e_ehsize can be used to determine
	 * the real size of the ELF header.
	 */
	unsigned char ident[EI_NIDENT];
	test_read(fd, ident, sizeof(ident));
	TEST_ASSERT((ident[EI_MAG0] == ELFMAG0) && (ident[EI_MAG1] == ELFMAG1)
		&& (ident[EI_MAG2] == ELFMAG2) && (ident[EI_MAG3] == ELFMAG3),
		"ELF MAGIC Mismatch,\n"
		"  filename: %s\n"
		"  ident[EI_MAG0 - EI_MAG3]: %02x %02x %02x %02x\n"
		"  Expected: %02x %02x %02x %02x",
		filename,
		ident[EI_MAG0], ident[EI_MAG1], ident[EI_MAG2], ident[EI_MAG3],
		ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3);
	TEST_ASSERT(ident[EI_CLASS] == ELFCLASS64,
		"Current implementation only able to handle ELFCLASS64,\n"
		"  filename: %s\n"
		"  ident[EI_CLASS]: %02x\n"
		"  expected: %02x",
		filename,
		ident[EI_CLASS], ELFCLASS64);
	TEST_ASSERT(((BYTE_ORDER == LITTLE_ENDIAN)
			&& (ident[EI_DATA] == ELFDATA2LSB))
		|| ((BYTE_ORDER == BIG_ENDIAN)
			&& (ident[EI_DATA] == ELFDATA2MSB)), "Current "
		"implementation only able to handle\n"
		"cases where the host and ELF file endianness\n"
		"is the same:\n"
		"  host BYTE_ORDER: %u\n"
		"  host LITTLE_ENDIAN: %u\n"
		"  host BIG_ENDIAN: %u\n"
		"  ident[EI_DATA]: %u\n"
		"  ELFDATA2LSB: %u\n"
		"  ELFDATA2MSB: %u",
		BYTE_ORDER, LITTLE_ENDIAN, BIG_ENDIAN,
		ident[EI_DATA], ELFDATA2LSB, ELFDATA2MSB);
	TEST_ASSERT(ident[EI_VERSION] == EV_CURRENT,
		"Current implementation only able to handle current "
		"ELF version,\n"
		"  filename: %s\n"
		"  ident[EI_VERSION]: %02x\n"
		"  expected: %02x",
		filename, ident[EI_VERSION], EV_CURRENT);

	/* Read in the ELF header.
	 * With the ELF Identification portion of the ELF header
	 * validated, especially that the value at EI_VERSION is
	 * as expected, it is now safe to read the entire ELF header.
	 */
	offset_rv = lseek(fd, 0, SEEK_SET);
	TEST_ASSERT(offset_rv == 0, "Seek to ELF header failed,\n"
		"  rv: %zi expected: %i", offset_rv, 0);
	test_read(fd, hdrp, sizeof(*hdrp));
	TEST_ASSERT(hdrp->e_phentsize == sizeof(Elf64_Phdr),
		"Unexpected physical header size,\n"
		"  hdrp->e_phentsize: %x\n"
		"  expected: %zx",
		hdrp->e_phentsize, sizeof(Elf64_Phdr));
	TEST_ASSERT(hdrp->e_shentsize == sizeof(Elf64_Shdr),
		"Unexpected section header size,\n"
		"  hdrp->e_shentsize: %x\n"
		"  expected: %zx",
		hdrp->e_shentsize, sizeof(Elf64_Shdr));
}

/* Test ELF Get Symbol Info
 *
 * Look up and return information about a specified symbol, within a specified
 * ELF file (i.e. executable, object file).  Note, that archive files
 * contain ELF files are not currently supported.  The symbol name is given
 * by name, while the path to the ELF file is given by filename.  When found,
 * information about the symbol is returned in the structure pointed to
 * by symbp.
 *
 * TODO(lhuemill): Simplify implementation by using libbfd.
 *
 * Args:
 *  filename - Path to ELF file
 *      name - Symbol name
 *
 * Output:
 *  symbp - Information about specified symbol.
 *
 * Return:
 *  On success, returns 0.
 *  Symbol not found, returns -1, with errno equal to ENOENT.
 *  All other unexpected conditions cause a TEST_ASSERT failure.
 */
int test_elfsymb_get(const char *filename, const char *name,
	struct test_elfsymb *symbp)
{
	bool symb_found = false;
	off_t offset, offset_rv;

	/* Open the ELF file. */
	int fd;
	fd = open(filename, O_RDONLY);
	TEST_ASSERT(fd >= 0, "Failed to open ELF file,\n"
		"  filename: %s\n"
		"  rv: %i errno: %i", filename, fd, errno);

	/* Read in the ELF header. */
	Elf64_Ehdr hdr;
	test_elfhdr_get(filename, &hdr);

	/* For each section header.
	 * The following ELF header members specify the location
	 * and size of the section headers:
	 *
	 *  e_shoff - File offset to start of section headers
	 *  e_shentsize - Size of each section header
	 *  e_shnum - Number of section header entries
	 */
	for (unsigned int n1 = 0; n1 < hdr.e_shnum; n1++) {
		/* Seek to the beginning of the section header. */
		offset = hdr.e_shoff + (n1 * hdr.e_shentsize);
		offset_rv = lseek(fd, offset, SEEK_SET);
		TEST_ASSERT(offset_rv == offset,
			"Failed to seek to begining of section header %u,\n"
			"  filename: %s\n"
			"  rv: %jd errno: %i",
			n1, filename, (intmax_t) offset_rv, errno);

		/* Read in the section header */
		Elf64_Shdr shdr;
		test_read(fd, &shdr, sizeof(shdr));

		/* Skip if this section doesn't contain symbols. */
		if ((shdr.sh_type != SHT_SYMTAB)
			&& (shdr.sh_type != SHT_DYNSYM))
			continue;

		/* Obtain corresponding string table.
		 * The sh_link member of a symbol table section header,
		 * specifies which section contains the string table
		 * for these symbol names.
		 */
		Elf64_Shdr strtab_shdr;
		offset = hdr.e_shoff + (shdr.sh_link * hdr.e_shentsize);
		offset_rv = lseek(fd, offset, SEEK_SET);
		TEST_ASSERT(offset_rv == offset,
			"Failed to seek to begining of section header %u,\n"
			"  filename: %s\n"
			"  rv: %jd errno: %i",
			n1, filename, (intmax_t) offset_rv, errno);
		test_read(fd, &strtab_shdr, sizeof(strtab_shdr));

		char *strtab = malloc(strtab_shdr.sh_size);
		TEST_ASSERT(strtab, "Insufficient Memory");
		offset = strtab_shdr.sh_offset;
		offset_rv = lseek(fd, offset, SEEK_SET);
		TEST_ASSERT(offset_rv == offset,
			"Seek to string table failed,\n"
			"  rv: %zi expected: %jd",
			(intmax_t) offset_rv, offset);
		test_read(fd, strtab, strtab_shdr.sh_size);

		/* For each symbol */
		for (unsigned int n2 = 0;
			n2 <  (shdr.sh_size / sizeof(Elf64_Sym)); n2++) {
			Elf64_Sym sym;

			offset = shdr.sh_offset + (n2 * sizeof(sym));
			offset_rv = lseek(fd, offset, SEEK_SET);
			TEST_ASSERT(offset_rv == offset,
				"Seek to start of symbol entries failed,\n"
				"  offset: %jd\n"
				"  rv: %jd expected: %jd",
				(intmax_t) offset, (intmax_t) offset_rv,
				(intmax_t) offset);

			test_read(fd, &sym, sizeof(sym));

			/* Is this the symbol were searching for? */
			if (strcmp(strtab + sym.st_name, name) == 0) {
				symbp->value = sym.st_value;
				symbp->size = sym.st_size;
				symb_found = true;
				break;
			}
		}
		free(strtab);

		/* If the symbol was found, no need to search additional
		 * sections that describe symbols.  Although highly unlikely,
		 * when two or more entries exist for the same symbol name,
		 * only information about the first occurrence found is
		 * returned.
		 */
		if (symb_found)
			break;
	}

	close(fd);

	if (!symb_found) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

/*
 * Given a virtual address in our address space, get count
 * /proc/self/pageflags entries.
 */
void extract_pageflags(void *addr, unsigned int count, uint64_t *buffer)
{
	off_t offset, rvo;
	ssize_t rv;
	size_t readsz;
	int fd = open("/proc/self/pageflags", O_RDONLY);
	TEST_ASSERT(fd >= 0, "Failed to open pageflags file "
			     "rv: %i errno: %i", fd, errno);

	TEST_ASSERT((((unsigned long) addr) % getpagesize()) == 0,
			"Please pass page-aligned address (%p) to extract_"
			"pageflags", addr);

	offset = (((off_t) addr) / getpagesize()) * sizeof(uint64_t);
	rvo = lseek(fd, offset, SEEK_SET);
	TEST_ASSERT(rvo == offset, "%s failed to lseek pageflags to byte %llu "
				   "(%llu), va 0x%lx fd: %d errno: %d",
				   __func__,
				   (unsigned long long) offset,
				   (unsigned long long) rvo,
				   (unsigned long) addr, fd, errno);

	readsz = count * sizeof(uint64_t);
	rv = read(fd, buffer, readsz);
	TEST_ASSERT(rv == readsz,
			"%s could not read %lu pageflags (%ld) errno %d",
			__func__, (unsigned long) readsz, (long) rv, errno);
	TEST_ASSERT(0 == close(fd), "%s failed to close pageflags errno %d",
					__func__, errno);
}

/* Initialization function that sets up the test_utils
 * environment.
 */
static void __attribute__((constructor)) test_init(void)
{
	srand48(0);
}
