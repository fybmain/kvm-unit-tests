/*
 * gtests/include/test_sparsebit.h
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 *
 * Header file that describes API to the test_sparsebit library.
 * This library provides a memory efficient means of storing
 * the settings of bits indexed via a uint64_t.  Memory usage
 * is reasonable, significantly less than (2^64 / 8) bytes, as
 * long as bits that are mostly set or mostly cleared are close
 * to each other.  This library is efficient in memory usage
 * even in the case where most bits are set.
 */

#ifndef _TEST_SPARSEBIT_H_
#define _TEST_SPARSEBIT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct test_sparsebit;
typedef struct test_sparsebit test_sparsebit_t;
typedef uint64_t test_sparsebit_idx_t;
typedef uint64_t test_sparsebit_num_t;

test_sparsebit_t *test_sparsebit_alloc(void);
void test_sparsebit_free(test_sparsebit_t **sbitp);
void test_sparsebit_copy(test_sparsebit_t *dstp, const test_sparsebit_t *src);

bool test_sparsebit_is_set(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx);
bool test_sparsebit_is_set_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx, test_sparsebit_num_t num);
bool test_sparsebit_is_clear(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx);
bool test_sparsebit_is_clear_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx, test_sparsebit_num_t num);
test_sparsebit_num_t test_sparsebit_num_set(const test_sparsebit_t *sbit);
bool test_sparsebit_any_set(const test_sparsebit_t *sbit);
bool test_sparsebit_any_clear(const test_sparsebit_t *sbit);
bool test_sparsebit_all_set(const test_sparsebit_t *sbit);
bool test_sparsebit_all_clear(const test_sparsebit_t *sbit);
test_sparsebit_idx_t test_sparsebit_first_set(const test_sparsebit_t *sbit);
test_sparsebit_idx_t test_sparsebit_first_clear(const test_sparsebit_t *sbit);
test_sparsebit_idx_t test_sparsebit_next_set(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t prev);
test_sparsebit_idx_t test_sparsebit_next_clear(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t prev);
test_sparsebit_idx_t test_sparsebit_next_set_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t start, test_sparsebit_num_t num);
test_sparsebit_idx_t test_sparsebit_next_clear_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t start, test_sparsebit_num_t num);

void test_sparsebit_set(test_sparsebit_t *sbitp, test_sparsebit_idx_t idx);
void test_sparsebit_set_num(test_sparsebit_t *sbitp, test_sparsebit_idx_t start,
	test_sparsebit_num_t num);
void test_sparsebit_set_all(test_sparsebit_t *sbitp);

void test_sparsebit_clear(test_sparsebit_t *sbitp, test_sparsebit_idx_t idx);
void test_sparsebit_clear_num(test_sparsebit_t *sbitp,
	test_sparsebit_idx_t start, test_sparsebit_num_t num);
void test_sparsebit_clear_all(test_sparsebit_t *sbitp);

void test_sparsebit_dump(FILE *stream, const test_sparsebit_t *sbit,
	unsigned int indent);
void test_sparsebit_dump_internal(FILE *stream, const test_sparsebit_t *sbit,
	unsigned int indent);
void test_sparsebit_validate_internal(const test_sparsebit_t *sbit);

#ifdef __cplusplus
}
#endif

#endif /* _TEST_SPARSEBIT_H_ */
