/*
 * gtests/include/test_util.h
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#ifndef _GTESTS_TEST_UTIL_H
#define _GTESTS_TEST_UTIL_H

#include <errno.h>
#include <regex.h>
#include <signal.h> /* For siginfo_t */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h> /* For struct timespec */
#include <unistd.h>

#include <sys/wait.h>
#include <sys/types.h>

#include <linux/capability.h>
#include <linux/elf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* For portability with use of __func__. */
#if __STDC_VERSION__ < 199901L
#	if __GNUC__ >= 2
#		define __func__ __FUNCTION__
#	else
#		define __func__ "<unknown>"
#	endif
#endif

#define TEST_UTIL_SUCCESS 0
#define TEST_UTIL_SYNTAX_ERR 1
#define TEST_UTIL_VALUE_ERR 2

#define TEST_MALLOC_PROT_BEFORE (1 << 0)
#define TEST_MALLOC_PROT_AFTER (1 << 1)
#define TEST_MALLOC_ALIGN (1 << 2)
#define TEST_MALLOC_ALLOW_PROT_CHG (1 << 3)
#define TEST_MALLOC_MMAP_FD (1 << 4)
#define TEST_MALLOC_MMAP_FD_OFFSET (TEST_MALLOC_MMAP_FD | (1 << 5))

enum test_malloc_ctl_cmd {
	CHG_PROT, /* Change the protections of test_malloc'd memory.
		   * Memory must have been allocated with the
		   * TEST_MALLOC_PROT_CHG flag in order to use this command. */
	GET_FLAGS, /* Retrieve flags with which memory was test_malloc'd. */
};

struct test_rng {
	uint64_t low;
	uint64_t high; /* Inclusive */
};

struct test_symb {
	const char *name;
	uint64_t val;
};
struct test_symbi {
	const char *name;
	int64_t val;
};

/* Wraps information retrieved from the proc/<pid>/maps
 * file concerning a specific mapped memory address.
 */
struct test_pg_info {
	uint64_t start; /* The starting address of the mapping, inclusive. */
	uint64_t end;   /* The ending address of the mapping, inclusive. */
	size_t size; /* The size of the mapping. */
	int prot;    /* The protections of the mapping,
		      * one or more of PROT_READ, PROT_WRITE, PROT_EXEC,
		      * or PROT_NONE as defined in sys/mman.h. */
	bool shared; /* Whether the mapping is shared or private. */
};

typedef struct __user_cap_data_struct *test_cap_t;
typedef enum {
	TEST_CAP_EFFECTIVE = 0x2bc0,
	TEST_CAP_PERMITTED,
	TEST_CAP_INHERITABLE,
} test_cap_group_t;

extern const struct test_symb test_symb_infinity[];
extern const struct test_symb test_known_errno[];
extern const struct test_symb test_known_sig[];

char *test_get_opt_str(const char *arg1, char *args[]);
int test_parse_i64(const char *str, int64_t *val, int64_t min,
	int64_t max, const struct test_symbi symb[]);
int test_parse_u32(const char *str, uint32_t *val, uint32_t max,
	const struct test_symb symb[]);
int test_parse_u64(const char *str, uint64_t *val, uint64_t max,
	const struct test_symb symb[]);
int test_parse_float(const char *str, float *val);
int test_parse_rngs(const char *str, struct test_rng **rngs, unsigned int *num,
	uint64_t max, const struct test_symb symb[]);
char *test_rngs2str(const struct test_rng *rngs, unsigned int num,
	unsigned int radix);
bool test_rngs_idx_isset(unsigned long long idx, const struct test_rng *rngs,
	unsigned int num);
void test_rngs_idx_set(unsigned long long idx, struct test_rng **rngs,
	unsigned int *num);

char *test_dyn_sprintf(const char *fmt, ...);
/* Don't inline so we can omit from stack dumps. See test_dump_stack. */
void __attribute__((noinline)) __attribute__ ((format (printf, 5, 6)))
	test_assert(bool exp, const char *exp_str,
		    const char *file, unsigned int line, const char *fmt, ...);
uint32_t test_rand32(void);
bool test_rand_bool(void);
uint32_t test_rand32_mod(uint32_t mod);
unsigned int test_rand_choice(unsigned int num, const float weights[]);

void test_delay(double amt);
void test_delay_ts(const struct timespec *amt);
int test_delay_until(const struct timespec *end, pid_t pid);
double test_ts2double(const struct timespec *val);
struct timespec test_double2ts(double amt);

/* Current implementation of test_ts_delta requires *second >= *first */
struct timespec test_ts_delta(const struct timespec *first,
	const struct timespec *second);
void test_ts_sum(struct timespec *sum, const struct timespec *t1,
	const struct timespec *t2);
/* Current implementation of test_ts_minums requires *t1 >= * t2 */
void test_ts_minus(struct timespec *minus, const struct timespec *t1,
	const struct timespec *t2);
int test_ts_cmp(const struct timespec *t1, const struct timespec *t2);

char *test_debugfs_mnt_point(void);
void test_dump_siginfo(FILE *file, siginfo_t *sig);

uint64_t test_tsc_freq(int cpu);
void test_xdump(FILE *stream, const void *buf, size_t size,
	intptr_t addr_start, uint8_t indent);

char *test_config_str(const char *name);

int test_cap_get(pid_t pid, test_cap_t *cap);
int test_cap_set(pid_t pid, const test_cap_t *cap);
bool test_cap_flag_fetch(const test_cap_t *cap, test_cap_group_t group,
	unsigned int trait);
void test_cap_flag_assign(test_cap_t *cap, test_cap_group_t group,
	unsigned int trait, bool rval);

float test_sgniff(long double expected, float actual);
float test_sgnif(long double expected, double actual);
float test_sgnifl(long double expected, long double actual);

int test_pg_info(pid_t pid, uint64_t addr,
	struct test_pg_info *info);
int test_pg_info_map(const char *map, uint64_t addr,
	struct test_pg_info *info);

ssize_t test_write(int fd, const void *buf, size_t count);
ssize_t test_read(int fd, void *buf, size_t count);
int test_seq_read(const char *path, char **bufp, size_t *sizep);

void *test_malloc(size_t size, uint32_t flags, ...);
void test_malloc_free(void *addr);
void test_malloc_chg_prot(const void *addr, int prot);
uint32_t test_malloc_get_flags(const void *addr);

#define TEST_ASSERT(e, fmt, ...) \
	test_assert((e), #e, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* Shorthand for TEST_ASSERT(e, "%s", "") */
#define ASSERT(e) \
	TEST_ASSERT(e, "ASSERT(%s) failed.", #e)

#define ASSERT_EQ(a, b) do { \
	typeof(a) __a = (a); \
	typeof(b) __b = (b); \
	TEST_ASSERT(__a == __b, \
		    "ASSERT_EQ(%s, %s) failed.\n" \
		    "\t%s is %#lx\n" \
		    "\t%s is %#lx", \
		    #a, #b, #a, (unsigned long) __a, #b, (unsigned long) __b); \
} while (0)

int __attribute__ ((format (printf, 1, 2))) test_printk(const char *fmt, ...);

struct test_elfsymb {
	uintmax_t value;
	size_t   size;
};
void test_elfhdr_get(const char *filename, Elf64_Ehdr *hdrp);
int test_elfsymb_get(const char *filename, const char *name,
	struct test_elfsymb *symbp);

void extract_pageflags(void *addr, unsigned int count, uint64_t *buffer);

/* Architecture dependent inline functions.
 *
 * For each architecutre the following inline functions are provided:
 *
 *   void test_barrier_read(void)
 *     Delay until the current processor has completed all outstanding
 *     cache coherence read operations.
 *
 *   void test_barrier_write(void)
 *     Delay until the current processor has completed all outstanding
 *     cache coherence write operations.
 *
 *   void test_barrier_read_write(void)
 *     Delay until the current processor has completed all outstanding
 *     cache coherence read and write operations.
 *
 *   void test_serialize(void)
 *     Delay until the current processor has completed all outstanding
 *     operations.  At a minimum, this includes the following:
 *
 *       + Background cache coherence read operations.
 *       + Background cache coherence write operations.
 *       + Flush instruction pipeline.
 *
 *   uint64_t test_rdtsc(bool skip_isync)
 *     Reads the processors time-stamp counter and returns its value.
 *     Each implementation assures that instructions before reading
 *     the time-stamp counter have completed (e.g. instruction pipe-line
 *     flush), although there may be pending backgroud operations
 *     (e.g. backgroup cache-coherence operations).  Note, an instruction
 *     pipe-line flush is not performed after reading the time-stamp
 *     counter, because it is assumed that there is a time-stamp counter
 *     per processor and thus it is not a shared resource, which could
 *     delay the ability to read the counter value.
 */
#if defined(__x86_64__)
static inline void test_barrier_read(void)
{
	__asm__ __volatile__("lfence" : : : "memory");
}

static inline void test_barrier_write(void)
{
	__asm__ __volatile__("sfence" : : : "memory");
}

static inline void test_barrier_read_write(void)
{
	__asm__ __volatile__("mfence" : : : "memory");
}

static inline void test_serialize(void)
{
	uint32_t eax, ebx, ecx, edx;

	__asm__ __volatile__ (
		"cpuid\n"
		: "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
		: "a" (0), "c" (0)
		: "memory"
	);
}

static inline uint64_t test_rdtsc(void)
{
	uint32_t low, high;

	asm volatile("mfence; lfence");
	__asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
	asm volatile("lfence");

	return ((uint64_t) high << 32) | low;
}


#elif defined(__PPC64__)

static inline void test_barrier_read(void)
{
	__asm__ volatile ("sync" : : : "memory");
}

static inline void test_barrier_write(void)
{
	__asm__ volatile ("sync" : : : "memory");
}

static inline void test_serialize(void)
{
	__asm__ volatile ("sync");
}

static inline uint64_t test_rdtsc(void)
{
	uint64_t upper, lower, upper_again;

	/* Can only read the upper or lower half of the time-stamp counter
	 * with a single instruction.  To handle this, will read the
	 * upper half, then the lower half, then the upper half again.
	 * Will combine and return the upper and lower half only when
	 * the first and second read of the upper half return the same
	 * value.  In cases where the upper half is different between
	 * the two times it is read, the whole process is repeated, until
	 * a case occurs when the two reads of the upper half return the
	 * same value.
	 */
	__asm__ volatile(
		"0:\n"
		"\tmftbu %0\n"
		"\tmftb %1\n"
		"\tmftbu %2\n"
		"\tcmpw %2, %0\n"
		"\tbne 0b\n"
		: "=r"(upper), "=r"(lower),"=r"(upper_again)
	);

	return (upper << 32) | lower;
}

#elif defined(__aarch64__)

static inline void test_barrier_read(void)
{
	/* "memory" to prevent compiler reordering.
	 * "dsb ld" == data synchronization barrier, full system, reads.
	 * This instruction completes after all prior memory reads issued by
	 * this CPU to any observer in the system, are complete.
	 * See ARMv8 Architecture Reference Manual sections B2.7.3 and C6.6.62.
	 */
	__asm__ volatile ("dsb ld" : : : "memory");
}

static inline void test_barrier_write(void)
{
	/* "memory" to prevent compiler reordering.
	 * "dsb st" == data synchronization barrier, full system, writes.
	 * This instruction completes after all prior memory writes issued by
	 * this CPU are visible to all observers in the system.
	 * See ARMv8 Architecture Reference Manual sections B2.7.3 and C6.6.62.
	 */
	__asm__ volatile ("dsb st" : : : "memory");
}

static inline void test_serialize(void)
{
	/* "memory" to prevent compiler reordering.
	 * "dsb sy" == data synchronization barrier, full system, all types.
	 * "isb sy" == instruction synchronization barrier, full system.
	 * See ARMv8 Architecture Reference Manual sections B2.7.3, C6.6.62 and
	 * C6.6.72.
	 */
	__asm__ volatile (
		"dsb sy\n\t"
		"isb sy"
		: : : "memory");
}

static inline uint64_t test_rdtsc(void)
{
	uint64_t value;

	/*
	 * Read the virtual timer, to ensure this will work correctly within
	 * VMs as well. Note that the timer typically runs at a lower frequency
	 * than the CPU.
	 */
	test_serialize();
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));

	return value;
}

#else
#error "Unknown architecture"
#endif

/* Metrics - C Language Interface
 *
 * Note: C++-language portion of interface described below, within
 *       "__cplusplus" portion of this header.  See below,
 *       class GtestsUtilMetrics..
 */
void metrics_post_uint64(const char *name, uint64_t value, const char *units);
void metrics_post_int64(const char *name, int64_t value, const char *units);
void metrics_post_float(const char *name, float value, const char *units);
void metrics_post_double(const char *name, double value, const char *units);
void metrics_post_uint64_array(const char *name,
	const uint64_t *values, unsigned int num, const char *units);
void metrics_post_int64_array(const char *name,
	const int64_t *values, unsigned int num, const char *units);
void metrics_post_float_array(const char *name,
	const float *values, unsigned int num, const char *units);
void metrics_post_double_array(const char *name,
	const double *values, unsigned int num, const char *units);

#ifdef __cplusplus
}  /* Closing brace for extern "C" */

/* Declarations for C++ only. */
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

const unsigned int GtestsUtil_Magic001 = 0x3a40;

std::string StringPrintf(const char* format, ...);

class GtestsUtil_Log {
      public:
	static const unsigned int magic001 = 0x3a40;

	enum LogSeverity {
		INFO = magic001,
		WARNING,
		ERROR,
		FATAL,
	};

	GtestsUtil_Log(const char* file, unsigned int line,
		enum LogSeverity severity);
	~GtestsUtil_Log();

	template <typename T> GtestsUtil_Log& operator<<(const T& v) {
		/* Right-hand-side operand is inserted to the string_
		 * variable, instead of directly to the stream, so
		 * that the current state of std::cout and std::cerr
		 * don't effect how the log entry is formatted.  On
		 * destruction the contents of string_, plus a newline,
		 *  is inserted to the underlying stream.
		 */
		string_ << v;

		return *this;
	}

	/* Handle stream manipulators. */
	typedef ::std::ostream& (StdManip1)(::std::ostream &os);
	typedef ::std::ios_base& (StdManip2)(::std::ios_base &os);
	GtestsUtil_Log& operator<<(StdManip1 m);
	GtestsUtil_Log& operator<<(StdManip2 m);

      private:
	GtestsUtil_Log();
	std::ostringstream string_;
	std::ostream& stream_;
	const enum LogSeverity severity_;
};

/* Log Macro
 *
 * Caller is expected to use one of:
 *
 *    LOG(INFO)
 *    LOG(WARNING)
 *    LOG(ERROR)
 *    LOG(FATAL)
 *
 * All four of the above forms of the LOG macro cause a prefix of
 * the following format:
 *
 *   SMMDD hh:mm:ss.uuuuuu ttttttt ffffff:llll]
 *
 * where:
 *
 *   S - severity - one of I (info), W (warning), E (error), or F (fatal)
 *   MM - month - 01 (January) to (12) December
 *   DD - day of month
 *   hh - hour
 *   mm - minute
 *   ss - seconds
 *   uuuuuu - micro-seconds
 *   ttttttt - thread ID
 *   ffffff - filename
 *   llll - line number
 *
 * the MM, DD, hh, mm, ss, and uuuuuu fields above are prefixed with
 * zeros as needed to be of the length shown above.  While the thread
 * ID is prefixed with space characters as needed to be a total of 7
 * characters long.  The filename and line numbers are displayed in
 * whatever minimal number of characters needed to display their entire
 * value.  The INFO and WARNING forms of the LOG macros send their
 * output to std::cout, while the ERROR and FATAL forms send it to
 * std::stderr.
 *
 * Although not derived from any of the standard stream classes, the
 * underlying GtestsUtil_Log class overloads the << operator so that
 * ostream objects and stream manipulators can be used to the temporary
 * object created by the various forms of the LOG macro.  For example,
 * the following will display to std::cout the hex value of a variable
 * named foo:
 *
 *   LOG(INFO) << "foo: 0x" << std::hex << foo;
 *
 * After displaying the log message prefix and anything pushed via the
 * << operator, a newline is displayed and the stream is flushed.
 * Additionally, the FATAL form of the LOG macro causes a TEST_ASSERT failure.
 */
#define LOG(severity) \
	GtestsUtil_Log(__FILE__, __LINE__, GtestsUtil_Log::severity)

/* CHECK Macros
 *
 * A minimal implementation of the CHECK macros, from google3.  As with
 * the LOG macro, in the future these macros and underlying classes may
 * be enhanced, but in general tests that need more than this minimal
 * implementation should be implemented and maintained within google3.
 *
 * The basic form of the CHECK macro takes a single boolean expression.
 * Under normal conditions this expression should evaluate to true.  When
 * true, the CHECK macro effectively becomes a null-operation. When
 * true, expressions on the right-hand-side of a << operator are not
 * even evaluated.  In contrast, when the expression is false, a LOG(FATAL)
 * is used to display a log prefix and the values pushed to the CHECK
 * macro, via the << operator.  Further, the use of LOG(FATAL) causes
 * a TEST_ASSERT failure, after the values are displayed.
 *
 * There are additional forms of the CHECK macro that instead of taking
 * a Boolean expression, take two values.  Those two values are compared
 * via an operation specified by a suffix to the CHECK macro name.  The
 * supported forms of these macros and the operation performed are:
 *
 *  CHECK_EQ     == (Equal)
 *  CHECK_NE     != (Not Equal)
 *  CHECK_LE     <= (Less Than or Equal)
 *  CHECK_LT     <  (Less Than)
 *  CHECK_GE     >= (Greater Than or Equal)
 *  CHECK_GT     >  (Greater Than)
 *
 * Note: The CHECK macro intentionally uses a while() with
 *       no braces.  This effectively forms what appears
 *       to be a short-circuit evaluation of the << operator.
 *       For example, caller might use this macro as:
 *
 *         CHECK(cond) << "n: " << n++;
 *
 *       Because no braces were used, the caller can
 *       add << operators to the right of the macro
 *       expansion.  While the use of while causes the
 *       << operands to only be evaluated when the condition
 *       is false.  In the above example, n is only increamented
 *       when cond is false.
 */
#define CHECK(condition) \
	while (!(condition)) \
		LOG(FATAL) << "FAILED: " #condition << std::endl

#define CHECK_EQ(val1, val2) GTESTSUTIL_CHECK_OP(==, val1, val2)
#define CHECK_NE(val1, val2) GTESTSUTIL_CHECK_OP(!=, val1, val2)
#define CHECK_LE(val1, val2) GTESTSUTIL_CHECK_OP(<=, val1, val2)
#define CHECK_LT(val1, val2) GTESTSUTIL_CHECK_OP(< , val1, val2)
#define CHECK_GE(val1, val2) GTESTSUTIL_CHECK_OP(>=, val1, val2)
#define CHECK_GT(val1, val2) GTESTSUTIL_CHECK_OP(> , val1, val2)
#define GTESTSUTIL_CHECK_OP(condition, val1, val2) \
	/* Note: Intentional use of while() with no braces. \
	 *       See description of CHECK macro above for \
	 *       explanation. \
	 */ \
	while (!(val1 condition val2)) \
		LOG(FATAL) << "FAILED: " << #val1 << ' ' << #condition << ' ' \
			<< #val2 << std::endl \
			<< "val1: " << val1 << std::endl \
			<< "val2: " << val2 << std::endl \

/* Metrics - C++ Language Interface
 *
 * Note: C-language portion of interface described above, within "extern C"
 *       portion of this header.  See above, metric_post_.
 */
class GtestsUtilMetrics {
      public:
	/* Post a set of metrics.
	 *
	 * name: ^[a-zA-Z_]+[0-9a-zA-Z_]*$
	 * values: vector of type uint64_t, int64_t, float, or double.
	 * units: ^[a-zA-Z_%]+[0-9.a-zA-Z_/%^]*$
	 *   Characters of /, ^, and % provided to support units
	 *   like "meters/second^2" and "%_of_baseline".
	 */
	static const std::string kMetricsNameRe;
	static const std::string kMetricsUnitsRe;

	template <typename T>
	static void Post(const std::string& name, const std::vector<T>& values,
		  const std::string& units) {
		Post(name, values.cbegin(), values.cend(), units);
	}
	template <typename T>
	static void Post(const std::string& name,
        	const T begin, const T end, const std::string& units);

      private:
	static void Initialize();
};

#endif /* __cplusplus */
#endif /* _GTESTS_TEST_UTIL_H */
