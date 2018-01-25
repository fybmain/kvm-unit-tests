/*
 * gtests/lib/test_sparsebit.c
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 *
 * Test Sparsebit Library
 *
 * This library provides functions to support a memory efficient bit array,
 * with an index size of 2^64.  A sparsebit array is allocated through
 * the use test_sparsebit_alloc() and free'd via test_sparsebit_free(),
 * such as in the following:
 *
 *   test_sparsebit_t *s;
 *   s = test_sparsebit_alloc();
 *   test_sparsebit_free(&s);
 *
 * The test_sparsebit_t type resolves down to a struct test_sparsebit.
 * Note that, test_sparsebit_free() takes a pointer to the test_sparsebit
 * structure.  This is so that test_sparsebit_free() is able to poison
 * the pointer (e.g. set it to NULL) to the struct test_sparsebit before
 * returning to the caller.
 *
 * Between the return of test_sparsebit_alloc() and the call of
 * test_sparsebit_free(), there are multiple query and modifying operations
 * that can be performed on the allocated test sparsebit array.  All of
 * these operations take as a parameter the value returned from
 * test_sparsebit_alloc() and most also take a bit index.  Frequently
 * used routines include:
 *
 *  ---- Query Operations
 *  test_sparsebit_is_set(sbit, idx)
 *  test_sparsebit_is_clear(sbit, idx)
 *  test_sparsebit_any_set(sbit)
 *  test_sparsebit_first_set(sbit)
 *  test_sparsebit_next_set(sbit, prev_idx)
 *
 *  ---- Modifying Operations
 *  test_sparsebit_set(sbit, idx)
 *  test_sparsebit_clear(sbit, idx)
 *  test_sparsebit_set_num(sbit, idx, num);
 *  test_sparsebit_clear_num(sbit, idx, num);
 *
 * A common operation, is to itterate over all the bits set in a test
 * sparsebit array.  This can be done via code with the following structure:
 *
 *   test_sparsebit_idx_t idx;
 *   if (test_sparsebit_any_set(sbit)) {
 *     idx = test_sparsebit_first_set(sbit);
 *     do {
 *       ...
 *       idx = test_sparsebit_next_set(sbit, idx);
 *     } while (idx != 0);
 *   }
 *
 * The index of the first bit set needs to be obtained via
 * test_sparsebit_first_set(), because test_sparsebit_next_set(), needs
 * the index of the previously set.  The test_sparsebit_idx_t type is
 * unsigned, so there is no previous index before 0 that is available.
 * Also, the call to test_sparsebit_first_set() is not made unless there
 * is at least 1 bit in the array set.  This is because a TEST_ASSERT
 * failure is produced if test_sparsebit_first_set() is called with
 * no bits set.  It is the callers responsibility to assure that the
 * test sparsebit array has at least a single bit set before calling
 * test_sparsebit_first_set().
 *
 * ==== Implementation Overview ====
 * For the most part the internal implementation of test sparsebit is
 * opaque to the caller.  One important implementation detail that the
 * caller may need to be aware of is the spatial complexity of the
 * implementation.  This implementation of a sparsebit array is not
 * only sparse, in that it uses memory proportional to the number of bits
 * set.  It is also efficient in memory usage when most of the bits are
 * set.
 *
 * At a high-level the state of the bit settings are maintained through
 * the use of a binary-search tree, where each node contains at least
 * the following members:
 *
 *   typedef uint64_t test_sparsebit_idx_t;
 *   typedef uint64_t test_sparsebit_num_t;
 *
 *   test_sparsebit_idx_t idx;
 *   uint32_t mask;
 *   test_sparsebit_num_t num_after;
 *
 * The idx member contains the bit index of the first bit described by this
 * node, while the mask member stores the setting of the first 32-bits.
 * The setting of the bit at idx + n, where 0 <= n < 32, is located in the
 * mask member at 1 << n.
 *
 * Nodes are sorted by idx and the bits described by two nodes will never
 * overlap. The idx member is always aligned to the mask size, i.e. a
 * multiple of 32.
 *
 * Beyond a typical implementation, the nodes in this implementation also
 * contains a member named num_after.  The num_after member holds the
 * number of bits immediately after the mask bits that are contiguously set.
 * The use of the num_after member allows this implementation to efficiently
 * represent cases where most bits are set.  For example, the case of all
 * but the last two bits set, is represented by the following two nodes:
 *
 *   node 0 - idx: 0x0 mask: 0xffffffff num_after: 0xffffffffffffffc0
 *   node 1 - idx: 0xffffffffffffffe0 mask: 0x3fffffff num_after: 0
 *
 * ==== Invariants ====
 * This implementation usses the following invariants:
 *
 *   + Node are only used to represent bits that are set.
 *     Nodes with a mask of 0 and num_after of 0 are not allowed.
 *
 *   + Sum of bits set in all the nodes is equal to the value of
 *     the struct test_sparsebit_pvt num_set member.
 *
 *   + The setting of at least one bit is always described in a nodes
 *     mask (mask >= 1).
 *
 *   + A node with all mask bits set only occurs when the last bit
 *     described by the previous node is not equal to this nodes
 *     starting index - 1.  All such occurences of this condition are
 *     avoided by moving the setting of the nodes mask bits into
 *     the previous nodes num_after setting.
 *
 *   + Node starting index is evenly divisable by the number of bits
 *     within a nodes mask member.
 *
 *   + Nodes never represent a range of bits that wrap around the
 *     highest supported index.
 *
 *      (idx + MASK_BITS + num_after - 1) <= ((test_sparsebit_idx_t) 0) - 1)
 *
 *     As a consequence of the above, the num_after member of a node
 *     will always be <=:
 *
 *       maximum_index - nodes_starting_index - number_of_mask_bits
 *
 *   + Nodes within the binary search tree are sorted based on each
 *     nodes starting index.
 *
 *   + The range of bits described by any two nodes do not overlap.  The
 *     range of bits described by a single node is:
 *
 *       start: node->idx
 *       end (inclusive): node->idx + MASK_BITS + node->num_after - 1;
 *
 * Note, at times these invariants are temporarily violated for a
 * specific portion of the code.  For example, when setting a mask
 * bit, there is a small delay between when the mask bit is set and the
 * value in the struct test_sparsebit_pvt num_set member is updated.  Other
 * temporary violations occur when node_split() is called with a specified
 * index and assures that a node where its mask represents the bit
 * at the specified index exists.  At times to do this node_split()
 * must split an existing node into two nodes or create a node that
 * has no bits set.  Such temporary violations must be corrected before
 * returning to the caller.  These corrections are typically performed
 * by the local function node_reduce().
 */

#include <test_sparsebit.h>

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <test_util.h>
#include <values.h>

#define DUMP_LINE_MAX 100 /* Does not include indent amount */

/* Concrete definition of test_sparsebit_t and definition of
 * implementation private structures.
 */
struct test_sparsebit_pvt;
struct test_sparsebit {
	struct test_sparsebit_pvt *pimpl; /* Pointer to implementation private
					   * data.
					   */
};
struct node;
typedef struct test_sparsebit_pvt {
	struct node *root; /* Points to root node of the binary search
			    * tree.  Equal to NULL when no bits are set in
			    * the entire sparsebit array.
			    */
	test_sparsebit_num_t num_set; /* A redundant count of the total
				       * number of bits set.  Used for
				       * diagnostic purposes and to change
				       * the time complexity of
				       * test_sparsebit_num_set() from
				       * O(n) to O(1).
				       * Note: Due to overflow, a value of
				       * 0 means none or all set.
				       */
} pvt_t;

typedef uint32_t mask_t;
#define MASK_BITS (sizeof(mask_t) * CHARBITS)
typedef struct node {
	struct node *parent;
	struct node *left;
	struct node *right;
	test_sparsebit_idx_t idx; /* index of least-significant bit in mask */
	test_sparsebit_num_t num_after; /* num contiguously set after mask */
	mask_t mask;
} node_t;

/* File Scope Function Prototypes */
static test_sparsebit_num_t node_num_set(const node_t *nodep);
static node_t *node_copy_subtree(const node_t *subtree);
static node_t *node_find(pvt_t *s, test_sparsebit_idx_t idx);
static const node_t *node_find_const(const pvt_t *s, test_sparsebit_idx_t idx);
static node_t *node_add(pvt_t *s, test_sparsebit_idx_t idx);
static void node_rm(pvt_t *s, node_t *nodep);
static node_t *node_split(pvt_t *s, test_sparsebit_idx_t idx);
static const node_t *node_first_const(const pvt_t *s);
static node_t *node_next(pvt_t *s, node_t *n);
static const node_t *node_next_const(const pvt_t *s, const node_t *n);
static node_t *node_prev(pvt_t *s, node_t *n);
static bool all_set(const pvt_t *s);
static bool is_set(const pvt_t *s, test_sparsebit_idx_t idx);
static void bit_set(pvt_t *s, test_sparsebit_idx_t idx);
static void bit_clear(pvt_t *s, test_sparsebit_idx_t idx);
static void node_reduce(pvt_t *s, node_t *nodep);
static size_t display_range(FILE *stream, test_sparsebit_idx_t low,
	test_sparsebit_idx_t high,  bool prepend_comma_space);
static void dump_nodes(FILE *stream, const node_t *node,
	unsigned int indent);

/* Test Sparsebit Allocate
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Return:
 *   Allocated test sparsebit array.
 *
 * Allocates the memory needed to maintain the initial state of
 * a test sparsebit array.  The initial state of the newly allocated
 * sparsebit array has all bits cleared.
 */
test_sparsebit_t *test_sparsebit_alloc(void)
{
	test_sparsebit_t *s;

	/* Allocate top level structure. */
	s = calloc(1, sizeof(*s));
	TEST_ASSERT(s != NULL, "Insufficent Memory");

	/* Allocate memory, to hold implementation private data */
	s->pimpl = calloc(1, sizeof(*s->pimpl));
	TEST_ASSERT(s->pimpl != NULL, "Insufficent Memory");

	return  s;
}

/* Test Sparsebit Free
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   sbitpp - pointer to opaque sparsebit array pointer
 *
 * Return: None
 *
 * Frees the implementation dependent data for the test sparsebit array
 * pointed to by sbitp and poisons the pointer to that data.
 */
void test_sparsebit_free(test_sparsebit_t **sbitp)
{
	pvt_t *pvt = (*sbitp)->pimpl;

	if (pvt != NULL) {

		/* First clear any bits already set in the destination */
		test_sparsebit_clear(*sbitp, 0);
		test_sparsebit_clear_num(*sbitp, 1,
			~((test_sparsebit_num_t) 0));
		if (test_sparsebit_any_set(*sbitp)) {
			fputs("  dump_internal:\n", stderr);
			test_sparsebit_dump_internal(stderr, *sbitp, 4);
		}
		TEST_ASSERT((pvt->root == NULL) && (pvt->num_set == 0),
			"Unexpected non-NULL root or num_set != 0, after "
			"clearing all bits\n"
			"  *sbitp: %p (*sbitp)->pimpl: %p pvt->root: %p "
			"pvt->num_set: 0x%lx",
			*sbitp, (*sbitp)->pimpl, pvt->root, pvt->num_set);

		free(pvt);
		(*sbitp)->pimpl = NULL;
	}

	/* Free top-level structure and then posion caller's pointer to it. */
	free(*sbitp);
	*sbitp = NULL;
}

/* Test Sparsebit Copy
 *
 * Input Args:
 *   src - Source test sparsebit array
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   dst - Destination test sparsebit array
 *
 * Return: None
 *
 * Makes a copy of the sparsebit array given by source, to the sparsebit
 * array given by dst.  Note, dst must have already been allocated via
 * test_sparsebit_alloc().  It can though already have bit settings, which
 * if different from src will be cleared.
 */
void test_sparsebit_copy(test_sparsebit_t *dstp, const test_sparsebit_t *src)
{
	pvt_t *d = dstp->pimpl;
	const pvt_t *s = src->pimpl;

	/* First clear any bits already set in the destination */
	test_sparsebit_clear(dstp, 0);
	test_sparsebit_clear_num(dstp, 1, ~((test_sparsebit_num_t) 0));
	if (test_sparsebit_any_set(dstp)) {
		fputs("  dump_internal src:\n", stderr);
		test_sparsebit_dump_internal(stderr, src, 4);
		fputs("  dump_internal dst:\n", stderr);
		test_sparsebit_dump_internal(stderr, dstp, 4);
		TEST_ASSERT(false, "Destination bits set after clearing "
			"all bits");
	}
	TEST_ASSERT((d->root == NULL) && (d->num_set == 0),
		"Unexpected non-NULL root or num_set != 0, after "
		"clearing all bits\n"
		"  d: %p d->root: %p d->num_set: %lu",
		d, d->root, d->num_set);

	if (s->root) {
		d->root = node_copy_subtree(s->root);
		d->num_set = s->num_set;
	}
}

/* Test Sparsebit Is Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index
 *
 * Output Args: None
 *
 * Return:
 *   True if the bit is set, false otherwise
 *
 * Determines whether the bit at the index given by idx, within the
 * test sparsebit array is set or not.  Returns true if the bit is
 * set, otherwise false is returned.
 */
bool test_sparsebit_is_set(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx)
{
	return is_set(sbit->pimpl, idx);
}

/* Test Sparsebit Is Set Num
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index
 *   num - number of consecutive bits to check
 *
 * Output Args: None
 *
 * Return:
 *   True if num consecutive bits starting at idx are all set,
 *   false otherwise.
 *
 * Determines whether num consecutive bits starting at idx are all
 * set.  Returns true if all the bits are set, otherwise false
 * is returned.
 */
bool test_sparsebit_is_set_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx, test_sparsebit_num_t num)
{
	test_sparsebit_idx_t next_cleared;

	TEST_ASSERT(num > 0, "Num of 0 not supported, num: 0x%lx", num);

	TEST_ASSERT((idx + (num - 1)) >= idx, "Index plus num wraps beyond "
		"highest supported index,\n"
		"  idx: 0x%lx num: 0x%lx", idx, num);

	/* With num > 0, the first bit must be set. */
	if (!test_sparsebit_is_set(sbit, idx))
		return false;

	/* Find the next cleared bit */
	next_cleared = test_sparsebit_next_clear(sbit, idx);


	/* If no cleared bits beyond idx, then there are at least num
	 * set bits. Earlier TEST_ASSERT confirmed that idx + num
	 * doesn't wrap.
	 */
	if (next_cleared == 0)
		return true;

	/* Are there enough set bits between idx and the next cleared bit? */
	if ((next_cleared - idx) >= num)
		return true;

	return false;
}

/* Test Sparsebit Is Clear
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index
 *
 * Output Args: None
 *
 * Return:
 *   True if the bit is cleared, false otherwise
 *
 * Determines whether the bit at the index given by idx, within the
 * test sparsebit array is set or not.  Returns true if the bit is
 * cleared, otherwise false is returned.
 */
bool test_sparsebit_is_clear(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx)
{
	return !test_sparsebit_is_set(sbit, idx);
}

/* Test Sparsebit Is Cleared Num
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index
 *   num - number of consecutive bits to check
 *
 * Output Args: None
 *
 * Return:
 *   True if num consecutive bits starting at idx are all cleared,
 *   false otherwise.
 *
 * Determines whether num consecutive bits starting at idx are all
 * cleared.  Returns true if all the bits are cleared, otherwise false
 * is returned.
 */
bool test_sparsebit_is_clear_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t idx, test_sparsebit_num_t num)
{
	test_sparsebit_idx_t next_set;

	TEST_ASSERT(num > 0, "Num of 0 not supported, num: 0x%lx", num);

	TEST_ASSERT((idx + (num - 1)) >= idx, "Index plus num wraps beyond "
		"highest supported index,\n"
		"  idx: 0x%lx num: 0x%lx", idx, num);

	/* With num > 0, the first bit must be cleared. */
	if (!test_sparsebit_is_clear(sbit, idx))
		return false;

	/* Find the next set bit */
	next_set = test_sparsebit_next_set(sbit, idx);

	/* If no set bits beyond idx, then there are at least num
	 * cleared bits. Earlier TEST_ASSERT confirmed that idx + num
	 * doesn't wrap.
	 */
	if (next_set == 0)
		return true;

	/* Are there enough cleared bits between idx and the next set bit? */
	if ((next_set - idx) >= num)
		return true;

	return false;
}

/* Test Sparsebit Num Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return:
 *   Total number of bits set.  Note: a value of 0 is returned for
 *   the case of all bits set.  This is because with all bits set, there
 *   is 1 additional bit set beyond what can be represented in the return
 *   value.  The function, test_sparsebit_any_set(), instead of
 *   test_sparseibt_num_set() > 0, should be used to determine if the
 *   test sparsebit array has any bits set.
 */
test_sparsebit_num_t test_sparsebit_num_set(const test_sparsebit_t *sbit)
{
	return sbit->pimpl->num_set;
}

/* Test Sparsebit Any Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return:
 *   True if any bit is set.
 *
 * Determines whether any bit is set in the test sparsebit array
 * given by sbit.  Return true if any bit is set, false otherwise.
 */
bool test_sparsebit_any_set(const test_sparsebit_t *sbit)
{
	const pvt_t *s = sbit->pimpl;

	/* Nodes only describe set bits.  If any nodes then there
	 * is at least 1 bit set.
	 */
	if (s->root) {
		/* Every node should have a non-zero mask.  For now will
		 * just assure that the root node has a non-zero mask,
		 * which is a quick check that at least 1 bit is set.
		 */
		TEST_ASSERT(s->root->mask != 0, "Root node with mask "
			"of zero: mask: %x", s->root->mask);

		TEST_ASSERT((s->num_set > 0)
			|| ((s->root->num_after == ((test_sparsebit_num_t) 0)
				- MASK_BITS) && (s->root->mask == ~(mask_t) 0)),
			"Total num_set == 0, without all bits set,\n"
			"  s->num_set: 0x%lx s->root->mask: %x "
			"s->root->num_after: 0x%lx", s->num_set, s->root->mask,
			s->root->num_after);

		return true;
	}

	return false;
}

/* Test Sparsebit All Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return:
 *   True if all bits are set.
 *
 * Determines whether all the bits in the test sparsebit array are set.
 */
bool test_sparsebit_all_set(const test_sparsebit_t *sbit)
{
	return all_set(sbit->pimpl);
}

/* Test Sparsebit All Cleared
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return:
 *   True if all bits are cleared.
 *
 * Determines whether all the bits in the test sparsebit array are cleared.
 */
bool test_sparsebit_all_clear(const test_sparsebit_t *sbit)
{
	return !test_sparsebit_any_set(sbit);
}

/* Test Sparsebit Any Clear
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return:
 *   True if any bits are set.
 *
 * Determines whether all the bits in the test sparsebit array are set.
 */
bool test_sparsebit_any_clear(const test_sparsebit_t *sbit)
{
	return !test_sparsebit_all_set(sbit);
}

/* Test Sparsebit First Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Entry Requirement:
 *   + At least one bit within the test sparsebit array given by
 *     sbit is set.
 *
 * Return:
 *   Index of first set bit.
 *
 * Determines and returns the index of the first set bit.  A TEST_ASSERT()
 * failure occurs if no bits are set.  Code of the following form is
 * typically used to iterate over all the set bits:
 *
 *   if (test_sparsebit_any_set(sbit)) {
 *     idx = test_sparsebit_first_set(sbit);
 *     do {
 *       ...
 *       idx = test_sparsebit_next_set(sbit, idx);
 *     } while (idx != 0);
 *   }
 */
test_sparsebit_idx_t test_sparsebit_first_set(const test_sparsebit_t *sbit)
{
	unsigned int n1;
	const pvt_t *s = sbit->pimpl;
	const node_t *nodep;

	/* Validate at least 1 bit is set */
	TEST_ASSERT(test_sparsebit_any_set(sbit), "No bits set");

	/* Find the left-most node. */
	nodep = node_first_const(s);
	TEST_ASSERT(nodep != NULL, "Unexpected, no nodes");

	/* Return index of first bit set in mask.
	 * Note: Each node is required to have a non-zero mask.  In the case
	 * where the mask is ~0, it is not allowed to set the mask to 0,
	 * reduce  .idx by MASK_BITS and increase .num_after by MASK_BITS.
	 */
	for (n1 = 0; n1 < MASK_BITS; n1++) {
		if (nodep->mask & (1 << n1))
			break;
	}
	TEST_ASSERT(n1 < MASK_BITS, "No bits set in mask, "
		"nodep->idx: %lx nodep->mask: %x", nodep->idx, nodep->mask);

	return nodep->idx + n1;
}

/* Test Sparsebit First Clear
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Entry Requirement:
 *   + At least one bit within the test sparsebit array given by
 *     sbit is cleared.
 *
 * Return:
 *   Index of first cleared bit.
 *
 * Determines and returns the index of the first cleared bit.  A TEST_ASSERT()
 * failure occurs if no bits are cleared.  Code of the following form is
 * typically used to iterate over all the cleared bits:
 *
 *   if (test_sparsebit_any_clear(sbit)) {
 *     idx = test_sparsebit_first_clear(sbit);
 *     do {
 *       ...
 *       idx = test_sparsebit_next_clear(sbit, idx);
 *     } while (idx != 0);
 *   }
 */
test_sparsebit_idx_t test_sparsebit_first_clear(const test_sparsebit_t *sbit)
{
	const pvt_t *s = sbit->pimpl;
	const node_t *nodep1, *nodep2;

	/* Validate at least 1 bit is cleared. */
	TEST_ASSERT(test_sparsebit_any_clear(sbit), "No bits cleared");

	/* Find the left-most node. */
	nodep1 = node_first_const(s);

	/* If no nodes or first node index > 0 then lowest cleared is 0 */
	if ((nodep1 == NULL) || (nodep1->idx > 0))
		return 0;

	/* Does the mask in the first node contain any cleared bits. */
	for (unsigned int n1 = 0; n1 < MASK_BITS; n1++) {
		if (!(nodep1->mask & (1 << n1)))
			return nodep1->idx + n1;
	}

	/* All mask bits set in first node.  If there isn't a second node
	 * then the first cleared bit is the first bit after the bits
	 * described by the first node.
	 */
	nodep2 = node_next_const(s, nodep1);
	if (nodep2 == NULL) {
		/* No second node.  First cleared bit is first bit beyond
		 * bits described by first node.
		 */
		TEST_ASSERT(nodep1->mask == ~((mask_t) 0), "Node 1 "
			"expected to have a mask with all bits set,\n"
			"  nodep1: %p nodep1->mask: %x",
			nodep1, nodep1->mask);
		TEST_ASSERT((nodep1->idx + MASK_BITS + nodep1->num_after - 1)
			< ~((test_sparsebit_idx_t) 0), "Node 1 describes "
			"all bits set, but earlier check\n"
			"indicated there is at least one cleared bit.\n"
			"  nodep1: %p nodep1->idx: 0x%lx nodep1->mask: %x "
			"nodep1->num_after: 0x%lx",
			nodep1, nodep1->idx, nodep1->mask, nodep1->num_after);
		return nodep1->idx + MASK_BITS + nodep1->num_after;
	}

	/* There is a second node.
	 * If it is not adjacent to the first node, then there is a gap
	 * of cleared bits between the nodes.
	 */
	if ((nodep1->idx + MASK_BITS + nodep1->num_after) != nodep2->idx) {
		/* Gap exists between the first and second nodes.
		 * Return index of first bit within the gap.
		 */
		return nodep1->idx + MASK_BITS + nodep1->num_after;
	}

	/* Second node is adjacent to the first node.
	 * Because it is adjacent, its mask should be non-zero.  If all
	 * its mask bits are set, then with it being adjacent, it should
	 * have had the mask bits moved into the num_after setting of the
	 * previous node.
	 */
	TEST_ASSERT(nodep2->mask != ~((mask_t) 0), "Unexpected all bits "
		"set in second node,\n"
		"  nodep2: %p nodep2->idx: 0x%lx nodep2->mask: %x",
		nodep2, nodep2->idx, nodep2->mask);
	for (unsigned int n1 = 0; n1 < MASK_BITS; n1++) {
		if (!(nodep2->mask & (1 << n1)))
			return nodep2->idx + n1;
	}

	/* Not Reached */
	TEST_ASSERT(false, "No cleared bit found in second node,\n"
		"  nodep2: %p nodep2->idx: 0x%lx nodep2->mask: %x",
		nodep2, nodep2->idx, nodep2->mask);
	return -1;
}

/* Test Sparsebit Next Set
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index of previous bit
 *
 * Output Args: None
 *
 * Return:
 *   Index of next bit after prev that is set.
 *   Zero if no bit after prev is set.
 *
 * Returns index of next bit set within sbit after the index given by prev.
 * Returns 0 if there are no bits after prev that are set.
 */
test_sparsebit_idx_t test_sparsebit_next_set(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t prev)
{
	test_sparsebit_idx_t lowest_possible = prev + 1;
	const pvt_t *s = sbit->pimpl;

	/* A bit after the highest index can't be set. */
	if (lowest_possible == 0)
		return 0;

	/* Find the leftmost 'candidate' overlapping or to the right
	 * of lowest_possible.
	 */
	const node_t *candidate = NULL;
	bool contains = false;  /* true iff lowest_possible is
				 * within candidate
				 */

	/* Find node that describes setting of bit at lowest_possible.
	 * If such a node doesn't exist, find the node with the lowest
	 * starting index that is > lowest_possible.
	 */
	for (const node_t *nodep = s->root; nodep;) {
		if ((nodep->idx + MASK_BITS + nodep->num_after - 1)
			>= lowest_possible) {
			candidate = nodep;
			if (candidate->idx <= lowest_possible) {
				contains = true;
				break;
			}
			nodep = nodep->left;
		} else {
			nodep = nodep->right;
		}
	}
	if (candidate == NULL)
		return 0;

	/* Does the candidate node describe the setting of lowest_possible? */
	if (!contains) {
		/* Candidate doesn't describe setting of bit at lowest_possible.
		 * Candidate points to the first node with a starting index
		 * > lowest_possible.
		 */
		TEST_ASSERT(candidate->idx > lowest_possible, "Candidate "
			"not containing lowest_possible has starting index\n"
			"before lowest_possible,\n"
			"  lowest_possible: 0x%lx\n"
			"  candidate->idx: 0x%lx\n"
			"  contains: %u",
			lowest_possible, candidate->idx, contains);
		TEST_ASSERT(candidate->mask != 0, "Zero mask");

		/* Locate and return the index of the index that describes
		 * the first non-zero mask bit.
		 */
		for (unsigned int n1 = 0; n1 < MASK_BITS; n1++) {
			if (candidate->mask & (1 << n1))
				return candidate->idx + n1;
		}

		/* Not Reached */
		TEST_ASSERT(false, "Not Reached");
	}

	/* Candidate describes setting of bit at lowest_possible.
	 * Note: although the node describes the setting of the bit
	 * at lowest_possible, its possible that its setting and the
	 * setting of all latter bits described by this node are 0.
	 * For now, just handle the cases where this node describes
	 * a bit at or after an index of lowest_possible that is set.
	 */
	TEST_ASSERT(candidate->mask != 0, "Zero mask");
	test_sparsebit_idx_t start = lowest_possible - candidate->idx;
	for (test_sparsebit_idx_t n1 = start; n1 < MASK_BITS; n1++) {
		if (candidate->mask & (1 << n1))
			return candidate->idx + n1;
	}
	if (candidate->num_after) {
		test_sparsebit_idx_t first_num_after_idx
			= candidate->idx + MASK_BITS;
		return lowest_possible < first_num_after_idx
			? first_num_after_idx : lowest_possible;
	}

	/* Although candidate node describes setting of bit at
	 * the index of lowest_possible, all bits at that index and
	 * latter that are described by candidate are cleared.  With
	 * this, the next bit is the first bit in the next node, if
	 * such a node exists.  If a next node doesn't exist, then
	 * there is no next set bit.
	 */
	const node_t *candidate_next = node_next_const(s, candidate);
	if (!candidate_next)
		return 0;

	TEST_ASSERT(candidate_next->mask != 0, "Unexpected zero mask");
	for (unsigned int n1 = 0; n1 < MASK_BITS; n1++) {
		if (candidate_next->mask & (1 << n1))
			return candidate_next->idx + n1;
	}

	/* Not Reached */
	TEST_ASSERT(false, "Not Reached");

	return 0;
}

/* Test Sparsebit Next Cleared
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   idx - Bit index of previous bit
 *
 * Output Args: None
 *
 * Return:
 *   Index of next bit after prev that is set.
 *   Zero if no bit after prev is cleared.
 *
 * Returns index of next bit cleared within sbit after the index given by prev.
 * Returns 0 if there are no bits after prev that are cleared.
 */
test_sparsebit_idx_t test_sparsebit_next_clear(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t prev)
{
	const node_t *nodep1, *nodep2;
	unsigned int n1;
	const pvt_t *s = sbit->pimpl;

	/* A bit after the highest index can't be set. */
	if (prev == ~(test_sparsebit_idx_t) 0)
		return 0;

	/* Does a node describing the setting of prev + 1 exist? */
	nodep1 = node_find_const(s, prev + 1);
	if (nodep1 == NULL) {
		/* No node that describes the setting of prev + 1,
		 * so the bit at prev + 1 is cleared.
		 */
		return prev + 1;
	}

	/* Does a mask bit in node 1 describe the next cleared bit. */
	for (test_sparsebit_idx_t idx = ((prev + 1) - nodep1->idx);
		idx < MASK_BITS; idx++) {
		if (!(nodep1->mask & (1 << idx)))
			return nodep1->idx + idx;
	}

	/* Next cleared bit is not described by node 1.  If there
	 * isn't a next node, then next cleared bit is described
	 * by bit after the bits described by the first node.
	 */
	nodep2 = node_next_const(s, nodep1);
	if (nodep2 == NULL) {
		/* No second node.  First cleared bit is first bit beyond
		 * bits described by first node.
		 */
		return nodep1->idx + MASK_BITS + nodep1->num_after;
	}

	/* There is a second node.
	 * If it is not adjacent to the first node, then there is a gap
	 * of cleared bits between the nodes.
	 */
	if ((nodep1->idx + MASK_BITS + nodep1->num_after) != nodep2->idx) {
		/* Gap exists between the first and second nodes.
		 * Return index of first bit within the gap.
		 */
		return nodep1->idx + MASK_BITS + nodep1->num_after;
	}

	/* Second node is adjacent to the first node.
	 * Because it is adjacent, its mask should be non-zero.  If all
	 * its mask bits are set, then with it being adjacent, it should
	 * have had the mask bits moved into the num_after setting of the
	 * previous node.
	 */
	TEST_ASSERT(nodep2->mask != ~((mask_t) 0), "Unexpected all bits "
		"set in second node,\n"
		"  nodep2: %p nodep2->idx: 0x%lx nodep2->mask: %x",
		nodep2, nodep2->idx, nodep2->mask);
	for (n1 = 0; n1 < MASK_BITS; n1++) {
		if (!(nodep2->mask & (1 << n1)))
			return nodep2->idx + n1;
	}

	/* Not Reached */
	TEST_ASSERT(false, "No cleared bit found in second node,\n"
		"  nodep2: %p nodep2->idx: 0x%lx nodep2->mask: %x",
		nodep2, nodep2->idx, nodep2->mask);

	return 0;
}

/* Test Sparsebit Next Set Num
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   start - Bit index of previous bit
 *   num - number of consecutively set bits
 *
 * Output Args: None
 *
 * Return:
 *   Index of first sequence of num consequitvely set bits, with an
 *   index > start.  Value of 0 returned if no such sequence exsists.
 *
 * Starting with the index 1 greater than the index given by start, finds
 * and returns the index of the first sequence of num consecutively set
 * bits.  Returns a value of 0 of no such sequence exists.
 */
test_sparsebit_idx_t test_sparsebit_next_set_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t start, test_sparsebit_num_t num)
{
	test_sparsebit_idx_t idx;

	TEST_ASSERT(num >= 1, "num too small, num: 0x%lx", num);

	for (idx = test_sparsebit_next_set(sbit, start);
		(idx != 0) && ((idx + (num - 1)) >= idx);
		idx = test_sparsebit_next_set(sbit, idx)) {
		TEST_ASSERT(test_sparsebit_is_set(sbit, idx),
			"Unexpected, bit not set, idx: %lx", idx);

		/* Does the sequence of bits starting at idx consist of
		 * num set bits?
		 */
		if (test_sparsebit_is_set_num(sbit, idx, num))
			return idx;

		/* Sequence of set bits at idx isn't large enough.
		 * Skip this entire sequence of set bits.
		 */
		idx = test_sparsebit_next_clear(sbit, idx);
		if (idx == 0)
			return 0;
	}

	return 0;
}

/* Test Sparsebit Next Clear Num
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   start - Bit index of previous bit
 *   num - number of consecutively cleared bits
 *
 * Output Args: None
 *
 * Return:
 *   Index of first sequence of num consequitvely cleared bits, with an
 *   index > start.  Value of 0 returned if no such sequence exsists.
 *
 * Starting with the index 1 greater than the index given by start, finds
 * and returns the index of the first sequence of num consecutively cleared
 * bits.  Returns a value of 0 of no such sequence exists.
 */
test_sparsebit_idx_t test_sparsebit_next_clear_num(const test_sparsebit_t *sbit,
	test_sparsebit_idx_t start, test_sparsebit_num_t num)
{
	test_sparsebit_idx_t idx;

	TEST_ASSERT(num >= 1, "num too small, num: 0x%lx", num);

	for (idx = test_sparsebit_next_clear(sbit, start);
		(idx != 0) && ((idx + (num - 1)) >= idx);
		idx = test_sparsebit_next_clear(sbit, idx)) {
		TEST_ASSERT(test_sparsebit_is_clear(sbit, idx),
			"Unexpected, bit not cleared, idx: %lx", idx);

		/* Does the sequence of bits starting at idx consist of
		 * num cleared bits?
		 */
		if (test_sparsebit_is_clear_num(sbit, idx, num))
			return idx;

		/* Sequence of cleared bits at idx isn't large enough.
		 * Skip this entire sequence of cleared bits.
		 */
		idx = test_sparsebit_next_set(sbit, idx);
		if (idx == 0)
			return 0;
	}

	return 0;
}

/* Test Sparsebit Set Bit
 *
 * Input Args:
 *    idx - bit index
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array given by sbit, sets the bit at the
 * index given by idx.
 */
void test_sparsebit_set(test_sparsebit_t *sbitp, test_sparsebit_idx_t idx)
{
	test_sparsebit_set_num(sbitp, idx, 1);
}

/* Test Sparsebit Clear Bit
 *
 * Input Args:
 *    idx - bit index
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array given by sbit, clears the bit at the
 * index given by idx.
 */
void test_sparsebit_clear(test_sparsebit_t *sbitp, test_sparsebit_idx_t idx)
{
	test_sparsebit_clear_num(sbitp, idx, 1);
}

/* Test Sparsebit Set Num
 *
 * Input Args:
 *    idx - bit index
 *    num - number of bits to set
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array given by sbit, inclusively sets the bits
 * at the index of idx through idx + num - 1.
 */
void test_sparsebit_set_num(test_sparsebit_t *sbitp,
	test_sparsebit_idx_t start, test_sparsebit_num_t num)
{
	pvt_t *s = sbitp->pimpl;
	node_t *nodep, *next;
	unsigned int n1;

	TEST_ASSERT(num > 0, "Num of 0 not supported, num: 0x%lx", num);

	TEST_ASSERT((start + (num - 1)) >= start, "Index plus num wraps beyond "
		"highest supported index,\n"
		"  start: 0x%lx num: 0x%lx", start, num);

	/* Copy of input arguments, which during processing get modified,
	 * instead of modifying the actual input parameters.
	 */
	test_sparsebit_idx_t idx = start;
	test_sparsebit_num_t n = num;

	/* Leading - bits before first mask boundary */
	/* TODO(lhuemill): With some effort it may be possible to
	 *   replace the following loop with a sequential sequence
	 *   of statements.  High level sequence would be:
	 *
	 *     1. Use node_split() to force node that describes setting
	 *        of idx to be within the mask portion of a node.
	 *     2. Form mask of bits to be set.
	 *     3. Determine number of mask bits already set in the node
	 *        and store in a local variable named num_already_set.
	 *     4. Set the appropriate mask bits within the node.
	 *     5. Increment struct test_sparsebit_pvt num_set member
	 *        by the number of bits that were actually set.
	 *        Exclude from the counts bits that were already set.
	 *     6. Before returning to the caller, use node_reduce() to
	 *        handle the multiple corner cases that this method
	 *        introduces.
	 */
	for (; (n > 0) && ((idx % MASK_BITS) != 0); idx++, n--)
		bit_set(s, idx);

	/* Middle - bits spanning one or more entire mask */
	test_sparsebit_idx_t middle_start, middle_end;
	middle_start = idx;
	middle_end = middle_start + n - (n % MASK_BITS) - 1;
	if (n >= MASK_BITS) {
		nodep = node_split(s, middle_start);
		TEST_ASSERT(nodep, "No node at split point, after calling "
			"node_split(), "
			"nodep: %p middle_start: 0x%lx", nodep, middle_start);

		/* As needed, split just after end of middle bits.
		 * No split needed if end of middle bits is at highest
		 * supported bit index.
		 */
		if ((middle_end + 1) > middle_end)
			(void) node_split(s, middle_end + 1);

		/* Delete nodes that only describe bits within the middle. */
		for (next = node_next(s, nodep);
			next && (next->idx < middle_end);
			next = node_next(s, nodep)) {
			TEST_ASSERT((next->idx + MASK_BITS + next->num_after
				- 1) <= middle_end, "Node not part of "
				"middle,\n"
				"  middle start: 0x%lx end: 0x%lx\n"
				"  next->idx: 0x%lx\n"
				"  MASK_BITS: %lu\n"
				"  next->num_after: 0x%lx",
				middle_start, middle_end, next->idx,
				MASK_BITS, next->num_after);
			node_rm(s, next);
			next = NULL;
		}

		/* As needed set each of the mask bits */
		for (n1 = 0; n1 < MASK_BITS; n1++) {
			if (!(nodep->mask & (1 << n1))) {
				nodep->mask |= (1 << n1);
				s->num_set++;
			}
		}

		s->num_set -= nodep->num_after;
		nodep->num_after = 0;
		s->num_set += (middle_end - middle_start) + 1 - MASK_BITS;
		nodep->num_after = (middle_end - middle_start) + 1 - MASK_BITS;

		node_reduce(s, nodep);
	}
	idx = middle_end + 1;
	n -= (middle_end - middle_start) + 1;

	/* Trailing - bits at and beyond last mask boundary */
	TEST_ASSERT(n < MASK_BITS, "More than mask worth of trailing bits, "
		"idx: 0x%lx n: %lu", idx, n);
	for (; n > 0; idx++, n--)
		bit_set(s, idx);
}

/* Test Sparsebit Clear Num
 *
 * Input Args:
 *    idx - bit index
 *    num - number of bits to set
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array given by sbit, inclusively clears the bits
 * at the index of idx through idx + num - 1.
 */
void test_sparsebit_clear_num(test_sparsebit_t *sbitp,
	test_sparsebit_idx_t start, test_sparsebit_num_t num)
{
	TEST_ASSERT(num > 0, "Num of 0 not supported, num: 0x%lx", num);

	TEST_ASSERT((start + (num - 1)) >= start, "Index plus num wraps beyond "
		"highest supported index,\n"
		"  start: 0x%lx num: 0x%lx", start, num);

	/* Copy of input arguments, which during processing get modified,
	 * instead of modifying the actual input parameters.
	 */
	test_sparsebit_idx_t idx = start;
	test_sparsebit_num_t n = num;

	pvt_t *s = sbitp->pimpl;
	node_t *nodep;
	unsigned int n1;

	/* Leading - bits before first mask boundary */
	for (; (n > 0) && ((idx % MASK_BITS) != 0); idx++, n--)
		bit_clear(s, idx);

	/* Middle - bits spanning one or more entire mask */
	test_sparsebit_idx_t middle_start, middle_end;
	middle_start = idx;
	middle_end = middle_start + n - (n % MASK_BITS) - 1;
	if (n >= MASK_BITS) {
		nodep = node_split(s, middle_start);
		TEST_ASSERT(nodep, "No node at split point, after calling "
			"node_split(), "
			"nodep: %p middle_start: 0x%lx", nodep, middle_start);

		/* As needed, split just after end of middle bits.
		 * No split needed if end of middle bits is at highest
		 * supported bit index.
		 */
		if ((middle_end + 1) > middle_end)
			(void) node_split(s, middle_end + 1);

		/* Delete nodes that only describe bits within the middle. */
		for (node_t *next = node_next(s, nodep);
			next && (next->idx < middle_end);
			next = node_next(s, nodep)) {
			TEST_ASSERT((next->idx + MASK_BITS
				+ next->num_after - 1) <= middle_end,
				"Unexpected node crossing middle end "
				"boundary,\n"
				"  middle_end: 0x%lx\n"
				"  next->idx: 0x%lx\n"
				"  MASK_BITS: %lu\n"
				"  next->num_after: 0x%lx",
				middle_end, next->idx, MASK_BITS,
				next->num_after);
			node_rm(s, next);
			next = NULL;
		}

		/* As needed clear each of the mask bits */
		for (n1 = 0; n1 < MASK_BITS; n1++) {
			if (nodep->mask & (1 << n1)) {
				nodep->mask &= ~(1 << n1);
				s->num_set--;
			}
		}

		/* Clear any bits described by num_after */
		s->num_set -= nodep->num_after;
		nodep->num_after = 0;

		/* Delete the node that describes the beginning of
		 * the middle bits and perform any allowed reductions
		 * with the nodes prev or next of nodep.
		 */
		node_reduce(s, nodep);
		nodep = NULL;
	}
	idx = middle_end + 1;
	n -= (middle_end - middle_start) + 1;

	/* Trailing - bits at and beyond last mask boundary */
	TEST_ASSERT(n < MASK_BITS, "More than mask worth of trailing bits, "
		"idx: 0x%lx n: %lu", idx, n);
	for (; n > 0; idx++, n--)
		bit_clear(s, idx);
}

/* Test Sparsebit Set All
 *
 * Input Args: None
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets all the bits within the test sparsebit array specified
 * by sbitp.
 */
void test_sparsebit_set_all(test_sparsebit_t *sbitp)
{
	test_sparsebit_set(sbitp, 0);
	test_sparsebit_set_num(sbitp, 1, ~(test_sparsebit_idx_t) 0);
}

/* Test Sparsebit Clear All
 *
 * Input Args: None
 *
 * Input/Output Args:
 *   sbitp - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Clear all the bits within the test sparsebit array specified
 * by sbitp.
 */
void test_sparsebit_clear_all(test_sparsebit_t *sbitp)
{
	test_sparsebit_clear(sbitp, 0);
	test_sparsebit_clear_num(sbitp, 1, ~(test_sparsebit_idx_t) 0);
}

/* Test Sparsebit Dump
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   indent - number of spaces at start of each output line
 *
 * Output Args:
 *   stream - output stream
 *
 * Return: None
 *
 * Dumps to the FILE stream given by stream, the bit settings
 * of sbit.  Each line of output is prefixed with the number of
 * spaces given by indent.  The length of each line is implementation
 * dependent and does not depend on the indent amount.  The following
 * is an example output of a sparsebit array that has bits:
 *
 *   5, 8, 10, 11, 12, 13, 14, 18
 *
 * set:
 *
 *   0x5, 0x8, 0xa:0xe, 0x12
 *
 * Note that a ':', instead of a '-' is used to specify a range of
 * contiguous bits.  This is done because '-' is used to specify command-line
 * options, and sometimes ranges are specified as command-line arguments.
 */
void test_sparsebit_dump(FILE *stream, const test_sparsebit_t *sbit,
	unsigned int indent)
{
	const pvt_t *s = sbit->pimpl;
	size_t current_line_len = 0;
	size_t sz;

	if (!test_sparsebit_any_set(sbit))
		return;

	/* Display initial indent */
	fprintf(stream, "%*s", indent, "");

	/* For each node */
	for (const node_t *nodep = node_first_const(s);
		nodep; nodep = node_next_const(s, nodep)) {
		unsigned int n1;
		test_sparsebit_idx_t low, high;

		/* For each group of bits in the mask */
		for (n1 = 0; n1 < MASK_BITS; n1++) {
			if (nodep->mask & (1 << n1)) {
				low = high = nodep->idx + n1;

				for (; n1 < MASK_BITS; n1++) {
					if (nodep->mask & (1 << n1))
						high = nodep->idx + n1;
					else
						break;
				}

				if ((n1 == MASK_BITS) && nodep->num_after)
					high += nodep->num_after;

				/* How much room will it take to display
				 * this range.
				 */
				sz = display_range(NULL, low, high,
					current_line_len != 0);

				/* If there is not enough room, display
				 * a newline plus the indent of the next
				 * line.
				 */
				if ((current_line_len + sz) > DUMP_LINE_MAX) {
					fputs("\n", stream);
					fprintf(stream, "%*s", indent, "");
					current_line_len = 0;
				}

				/* Display the range */
				sz = display_range(stream, low, high,
					current_line_len != 0);
				current_line_len += sz;
			}
		}

		/* If num_after and most significant-bit of mask is not
		 * set, then still need to display a range for the bits
		 * described by num_after.
		 */
		if (!(nodep->mask & (1 << (MASK_BITS - 1)))
			&& nodep->num_after) {
			low = nodep->idx + MASK_BITS;
			high = nodep->idx + MASK_BITS + nodep->num_after - 1;

			/* How much room will it take to display
			 * this range.
			 */
			sz = display_range(NULL, low, high,
				current_line_len != 0);

			/* If there is not enough room, display
			 * a newline plus the indent of the next
			 * line.
			 */
			if ((current_line_len + sz) > DUMP_LINE_MAX) {
				fputs("\n", stream);
				fprintf(stream, "%*s", indent, "");
				current_line_len = 0;
			}

			/* Display the range */
			sz = display_range(stream, low, high,
				current_line_len != 0);
			current_line_len += sz;
		}
	}
	fputs("\n", stream);
}

/* Test Sparsebit Dump Internal
 *
 * Input Args:
 *   sbit - test sparsebit array
 *   indent - number of spaces at start of each output line
 *
 * Output Args:
 *   stream - output stream
 *
 * Return: None
 *
 * Dumps to the FILE stream specified by stream, the implementation dependent
 * internal state of sbit.  Each line of output is prefixed with the number
 * of spaces given by indent.  The output is completely implementation
 * dependent and subject to change.  Output from this function should only
 * be used for diagnostic purposes.  For example, this function can be
 * used by test cases after they detect an unexpected condition, as a means
 * to capture diagnostic information.
 */
void test_sparsebit_dump_internal(FILE *stream, const test_sparsebit_t *sbit,
	unsigned int indent)
{
	const pvt_t *s = sbit->pimpl;

	/* Dump the contents of sbit */
	fprintf(stream, "%*sroot: %p\n", indent, "", s->root);
	fprintf(stream, "%*snum_set: 0x%lx\n", indent, "", s->num_set);

	if (s->root)
		dump_nodes(stream, s->root, indent);
}

/* Test Sparsebit Validate Internal
 *
 * Input Args:
 *   sbit - test sparsebit array
 *
 * Output Args: None
 *
 * Return: None
 *
 * Validates the internal state of the test sparsebit array given by
 * sbit.  On error, diagnostic information is printed to stderr and
 * TEST_ASSERT failure is produced, which terminates the calling program.
 * The checks performed are implementation dependent.
 */
void test_sparsebit_validate_internal(const test_sparsebit_t *sbit)
{
	bool error_detected = false;
	const node_t *nodep, *prev = NULL;
	test_sparsebit_num_t total_bits_set = 0;
	const pvt_t *s = sbit->pimpl;

	/* For each node */
	for (nodep = node_first_const(s); nodep;
		prev = nodep, nodep = node_next_const(s, nodep)) {

		/* Increase total bits set by the number of bits set
		 * in this node.
		 */
		for (unsigned int n1 = 0; n1 < MASK_BITS; n1++) {
			if (nodep->mask & (1 << n1))
				total_bits_set++;
		}

		total_bits_set += nodep->num_after;

		/* Arbitrary choice as to whether a mask of 0 is allowed
		 * or not.  For diagnostic purposes it is beneficial to
		 * have only one valid means to represent a set of bits.
		 * To support this an arbitrary choice has been made
		 * to not allow a mask of zero.
		 */
		if (nodep->mask == 0) {
			fprintf(stderr, "Node mask of zero, "
				"nodep: %p nodep->mask: 0x%x",
				nodep, nodep->mask);
			error_detected = true;
			break;
		}

		/* Validate num_after is not greater than the max index
		 * - the number of mask bits.  The num_after member
		 * uses 0-based indexing and thus has no value that
		 * represents all bits set.  This limitation is handled
		 * by requiring a non-zero mask.  With a non-zero mask,
		 * MASK_BITS worth of bits are described by the mask,
		 * which makes the largest needed num_after equal to:
		 *
		 *    (~(test_sparsebit_num_t) 0) - MASK_BITS + 1
		 */
		if (nodep->num_after
			> (~(test_sparsebit_num_t) 0) - MASK_BITS + 1) {
			fprintf(stderr, "num_after too large, "
				"nodep: %p nodep->num_after: 0x%lx",
				nodep, nodep->num_after);
			error_detected = true;
			break;
		}

		/* Validate node index is divisible by the mask size */
		if (nodep->idx % MASK_BITS) {
			fprintf(stderr, "Node index not divisable by "
				"mask size,\n"
				"  nodep: %p nodep->idx: 0x%lx "
				"MASK_BITS: %lu\n",
				nodep, nodep->idx, MASK_BITS);
			error_detected = true;
			break;
		}

		/* Validate bits described by node don't wrap beyond the
		 * highest supported index.
		 */
		if ((nodep->idx + MASK_BITS + nodep->num_after - 1)
			< nodep->idx) {
			fprintf(stderr, "Bits described by node wrap "
				"beyond highest supported index,\n"
				"  nodep: %p nodep->idx: 0x%lx\n"
				"  MASK_BITS: %lu nodep->num_after: 0x%lx",
				nodep, nodep->idx, MASK_BITS, nodep->num_after);
			error_detected = true;
			break;
		}

		/* Check parent pointers. */
		if (nodep->left) {
			if (nodep->left->parent != nodep) {
				fprintf(stderr, "Left child parent pointer "
					"doesn't point to this node,\n"
					"  nodep: %p nodep->left: %p "
					"nodep->left->parent: %p",
					nodep, nodep->left,
					nodep->left->parent);
				error_detected = true;
				break;
			}
		}

		if (nodep->right) {
			if (nodep->right->parent != nodep) {
				fprintf(stderr, "Right child parent pointer "
					"doesn't point to this node,\n"
					"  nodep: %p nodep->right: %p "
					"nodep->right->parent: %p",
					nodep, nodep->right,
					nodep->right->parent);
				error_detected = true;
				break;
			}
		}

		if (nodep->parent == NULL) {
			if (s->root != nodep) {
				fprintf(stderr, "Unexpected root node, "
					"s->root: %p nodep: %p",
					s->root, nodep);
				error_detected = true;
				break;
			}
		}

		if (prev != NULL) {
			/* Is index of previous node before index of
			 * current node?
			 */
			if (prev->idx >= nodep->idx) {
				fprintf(stderr, "Previous node index "
					">= current node index,\n"
					"  prev: %p prev->idx: 0x%lx\n"
					"  nodep: %p nodep->idx: 0x%lx",
					prev, prev->idx, nodep, nodep->idx);
				error_detected = true;
				break;
			}

			/* Nodes occur in asscending order, based on each
			 * nodes starting index.
			 */
			if ((prev->idx + MASK_BITS + prev->num_after - 1)
				>= nodep->idx) {
				fprintf(stderr, "Previous node bit range "
					"overlap with current node bit range,\n"
					"  prev: %p prev->idx: 0x%lx "
					"prev->num_after: 0x%lx\n"
					"  nodep: %p nodep->idx: 0x%lx "
					"nodep->num_after: 0x%lx\n"
					"  MASK_BITS: %lu",
					prev, prev->idx, prev->num_after,
					nodep, nodep->idx, nodep->num_after,
					MASK_BITS);
				error_detected = true;
				break;
			}

			/* When the node has all mask bits set, it shouldn't
			 * be adjacent to the last bit described by the
			 * previous node.
			 */
			if (((nodep->mask) == ~((mask_t) 0))
				&& ((prev->idx + MASK_BITS + prev->num_after)
					== nodep->idx)) {
				fprintf(stderr, "Current node has mask with "
					"all bits set and is adjacent to the "
					"previous node,\n"
					"  prev: %p prev->idx: 0x%lx "
					"prev->num_after: 0x%lx\n"
					"  nodep: %p nodep->idx: 0x%lx "
					"nodep->num_after: 0x%lx\n"
					"  MASK_BITS: %lu",
					prev, prev->idx, prev->num_after,
					nodep, nodep->idx, nodep->num_after,
					MASK_BITS);

				error_detected = true;
				break;
			}
		}
	}

	if (!error_detected) {
		/* Is sum of bits set in each node equal to the count
		 * of total bits set.
		 */
		if (s->num_set != total_bits_set) {
			fprintf(stderr, "Number of bits set missmatch,\n"
				"  s->num_set: 0x%lx total_bits_set: 0x%lx",
				s->num_set, total_bits_set);

			error_detected = true;
		}
	}

	if (error_detected) {
		fputs("  dump_internal:\n", stderr);
		test_sparsebit_dump_internal(stderr, sbit, 4);
		TEST_ASSERT(false, "Validate internal detected an error.");
		assert(false);
	}
}

/* ======= Start of Implementation Dependent Local Functions ============ */

/* Node Num Set
 *
 * Input Args:
 *   nodep - pointer to node to count set bits within
 *
 * Output Args: None
 *
 * Return:
 *   Number of bits set.
 *
 * Determines and returns the number of set bits described by the settings
 * of the node pointed to by nodep.
 */
static test_sparsebit_num_t node_num_set(const node_t *nodep)
{
	unsigned int n1;
	test_sparsebit_num_t total = 0;

	for (n1 = 0; n1 < MASK_BITS; n1++) {
		if (nodep->mask & (1 << n1))
			total++;
	}
	total += nodep->num_after;

	return total;
}

/* Node Copy Subtree
 *
 * Input Args:
 *   subtree - pointer to root of sub-tree of nodes
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to newly allocated copy of subtree.
 *
 * Allocates space to hold a copy of the node sub-tree pointed to by
 * subtree and duplicates the bit settings to the newly allocated nodes.
 * In the case of insufficient memory a TEST_ASSERT failure is produced.
 */
static node_t *node_copy_subtree(const node_t *subtree)
{
	node_t *root;

	/* Duplicate the node at the root of the subtree */
	root = calloc(1, sizeof(*root));
	TEST_ASSERT(root != NULL, "Insufficient Memory");
	root->idx = subtree->idx;
	root->mask = subtree->mask;
	root->num_after = subtree->num_after;

	/* As needed, recursively duplicate the left and right subtrees */
	if (subtree->left) {
		root->left = node_copy_subtree(subtree->left);
		root->left->parent = root;
	}

	if (subtree->right) {
		root->right = node_copy_subtree(subtree->right);
		root->right->parent = root;
	}

	return root;
}

/* Node Find Const
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   idx - bit index
 *
 * Output Args: None
 *
 * Return: Pointer to node that describes the setting of the bit at idx.
 *   NULL if there is no such node.
 *
 * Searches for and returns a pointer to the node that describes the setting
 * of the bit given by idx.  A node describes the setting of a bit if its
 * index is within the bits described by the mask bits or the number of
 * contiguous bits set after the mask.
 */
static const node_t *node_find_const(const pvt_t *s, test_sparsebit_idx_t idx)
{
	node_t *nodep;

	/* Find the node that describes the setting of the bit at idx */
	for (nodep = s->root; nodep;
		nodep = (nodep->idx > idx) ? nodep->left : nodep->right) {
		if ((idx >= nodep->idx) && (idx <= (nodep->idx + MASK_BITS
			+ nodep->num_after - 1)))
			break;
	}

	return nodep;
}

/* Node Find
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   idx - bit index
 *
 * Output Args: None
 *
 * Return: Pointer to node that describes the setting of the bit at idx.
 *   NULL if there is no such node.
 *
 * A non-const wrapper of node_find_const().  This wrapper works the same
 * as node_find_const() but takes a non-const pointer to the test
 * sparsebit implementation private area and returns a non-const pointer
 * to the node, if it is found.
 */
static node_t *node_find(pvt_t *s, test_sparsebit_idx_t idx)
{
	return (node_t *) node_find_const(s, idx);
}

/* Node Add
 *
 * Input Args:
 *   idx - bit index
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Return: pointer to newly added node
 *
 * Entry Requirements:
 *   + A node that describes the setting of idx is not already present.
 *
 * Adds a new node to describe the setting of the bit at the index given
 * by idx.  Returns a pointer to the newly added node.
 *
 * TODO(lhuemill): Degenerative cases causes this implementation of
 *                 a binary search tree to turn into a doubly-linked list.
 *                 Change implementation to a red-black tree, which is a
 *                 form of a partially balanced binary tree.  Worst case
 *                 the lowest leaf node of a red-black tree will be at
 *                 most 2 times the distance of the highest leaf node.
 */
static node_t *node_add(pvt_t *s, test_sparsebit_idx_t idx)
{
	node_t *nodep, *parentp, *prev;

	TEST_ASSERT(node_find_const(s, idx) == NULL, "There is already a node "
		" that describes the setting of this bit, idx: 0x%lx", idx);

	/* Allocate and initialize the new node. */
	nodep = calloc(1, sizeof(*nodep));
	TEST_ASSERT(nodep != NULL, "Insufficient Memory");
	nodep->idx = idx - (idx % MASK_BITS);

	/* If no nodes, set it up as the root node. */
	if (s->root == NULL) {
		s->root = nodep;
		return nodep;
	}

	/* Find the parent where the new node should be attached
	 * and add the node there.
	 */
	TEST_ASSERT(s->root != NULL, "Unexpected missing root node, "
		"s->root: %p", s->root);
	parentp = s->root;
	while (true) {
		if (idx < parentp->idx) {
			if (!parentp->left) {
				parentp->left = nodep;
				nodep->parent = parentp;
				break;
			}
			parentp = parentp->left;
		} else {
			TEST_ASSERT(idx > (parentp->idx + MASK_BITS
				+ parentp->num_after - 1),
				"Unexpected node that describes setting "
				"of idx,\n"
				"  idx: 0x%lx\n"
				"  parentp->idx: 0x%lx\n"
				"  MASK_BITS: %lu\n"
				"  parentp->num_after: %lu",
				idx, parentp->idx, MASK_BITS,
				parentp->num_after);
			if (!parentp->right) {
				parentp->right = nodep;
				nodep->parent = parentp;
				break;
			}
			parentp = parentp->right;
		}
	}

	/* Does num_after bits of previous node overlap with the mask
	 * of the new node.  If so set the bits in the new nodes mask
	 * and reduce the previous nodes num_after.
	 */
	prev = node_prev(s, nodep);
	while (prev && ((prev->idx + MASK_BITS + prev->num_after - 1)
		>= nodep->idx)) {
		TEST_ASSERT(prev->num_after > 0, "Expected previous node "
			"to have bits described by num_after,\n"
			"  prev: %p prev->idx: 0x%lx prev->num_after: 0x%lx\n"
			"  nodep: %p nodep->idx: 0x%lx",
			prev, prev->idx, prev->num_after, nodep, nodep->idx);
		unsigned int n1 = (prev->idx + MASK_BITS + prev->num_after - 1)
			- nodep->idx;
		TEST_ASSERT(n1 < MASK_BITS, "Expected last bit "
			"described by prev->num_after to be within "
			"new nodes mask,\n"
			"  n1: %u prev->idx: 0x%lx MASK_BITS: %lu "
			"prev->num_after: 0x%lx nodep->idx: 0x%lx",
			n1, prev->idx, MASK_BITS, prev->num_after,
			nodep->idx);
		TEST_ASSERT(!(nodep->mask & (1 << n1)), "Unexpected "
			"mask bit already set,\n"
			"  nodep->idx: 0x%lx nodep->mask: 0x%x n1: %u\n"
			"  prev->idx: 0x%lx MASK_BITS: %lu "
			"  prev->num_after: 0x%lx",
			nodep->idx, nodep->mask, n1,
			prev->idx, MASK_BITS, prev->num_after);
		nodep->mask |= (1 << n1);
		prev->num_after--;
	}

	return nodep;
}

/* Node Remove
 *
 * Input Args:
 *   nodep - pointer to test sparsebit array node to be removed
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Return: None
 *
 * Clears all bits described by the node pointed to by nodep, then
 * removes the node.
 */
static void node_rm(pvt_t *s, node_t *nodep)
{
	node_t *tmp;

	TEST_ASSERT(nodep, "NULL node pointer, nodep: %p", nodep);

	TEST_ASSERT((s->num_set >= node_num_set(nodep)) || all_set(s),
		"Count of total bits set is less than bits being removed,\n"
		"  s->num_set: 0x%lx node_num_set(nodep): 0x%lx "
		"nodep->mask: %x nodep->num_after: 0x%lx",
		s->num_set, node_num_set(nodep), nodep->mask, nodep->num_after);
	s->num_set -= node_num_set(nodep);

	/* Have both left and right child */
	if (nodep->left && nodep->right) {
		/* Move left children to the leftmost leaf node
		 * of the right child.
		 */
		for (tmp = nodep->right; tmp->left; tmp = tmp->left)
			;
		tmp->left = nodep->left;
		nodep->left = NULL;
		tmp->left->parent = tmp;
	}

	/* Left only child */
	if (nodep->left) {
		TEST_ASSERT(nodep->right == NULL, "Has right child,\n"
			"  nodep: %p nodep->left: %p nodep->right: %p",
			nodep, nodep->left, nodep->right);
		if (nodep->parent == NULL) {
			s->root = nodep->left;
			nodep->left->parent = NULL;
		} else {
			nodep->left->parent = nodep->parent;
			if (nodep == nodep->parent->left)
				nodep->parent->left = nodep->left;
			else {
				TEST_ASSERT(nodep == nodep->parent->right,
					"Expected right child");
				nodep->parent->right = nodep->left;
			}
		}

		nodep->parent = nodep->left = nodep->right = NULL;
		free(nodep);

		return;
	}


	/* Right only child */
	if (nodep->right) {
		TEST_ASSERT(nodep->left == NULL, "Has left child,\n"
			"  nodep: %p nodep->left: %p nodep->right: %p",
			nodep, nodep->left, nodep->right);

		if (nodep->parent == NULL) {
			s->root = nodep->right;
			nodep->right->parent = NULL;
		} else {
			nodep->right->parent = nodep->parent;
			if (nodep == nodep->parent->left)
				nodep->parent->left = nodep->right;
			else {
				TEST_ASSERT(nodep == nodep->parent->right,
					"Expected right child");
				nodep->parent->right = nodep->right;
			}
		}

		nodep->parent = nodep->left = nodep->right = NULL;
		free(nodep);

		return;
	}

	/* Leaf Node */
	TEST_ASSERT((nodep->left == NULL) && (nodep->right == NULL),
		"Not a leaf node, nodep: %p nodep->left: %p nodep->right: %p",
		nodep, nodep->left, nodep->right);
	if (nodep->parent == NULL) {
		s->root = NULL;
	} else {
		if (nodep->parent->left == nodep)
			nodep->parent->left = NULL;
		else {
			TEST_ASSERT(nodep == nodep->parent->right,
				"Expected right child");
			nodep->parent->right = NULL;
		}
	}

	nodep->parent = nodep->left = nodep->right = NULL;
	free(nodep);

	return;
}

/* Node Split
 *
 * Input Args:
 *   idx - bit index
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Return:
 *   Pointer to new/previously_existing node where the nodes starting
 *   index is equal to idx.
 *
 * Entry Requirements:
 *   + idx at start of a mask boundary
 *
 * Splits the node containing the bit at idx so that there is a node
 * that starts at the specified index.  If no such node exists, a new
 * node at the specified index is created.
 */
static node_t *node_split(pvt_t *s, test_sparsebit_idx_t idx)
{
	node_t *nodep1, *nodep2;
	test_sparsebit_idx_t offset;
	test_sparsebit_num_t orig_num_after;

	TEST_ASSERT(!(idx % MASK_BITS), "Split index not on a mask boundary, "
		"idx: 0x%lx", idx);

	/* Is there a node that describes the setting of idx?
	 * If not, add it.
	 */
	nodep1 = node_find(s, idx);
	if (nodep1 == NULL) {
		nodep1 = node_add(s, idx);
		TEST_ASSERT(nodep1 != NULL, "NULL return from node_add()");
		TEST_ASSERT(nodep1->idx == idx, "Unexpected starting index,\n"
			"  nodep1->idx: 0x%lx\n"
			"  idx: 0x%lx", nodep1->idx, idx);
		return nodep1;
	}

	/* All done if the starting index of the node is where the
	 * split should occur.
	 */
	if (nodep1->idx == idx)
		return nodep1;

	/* Split point not at start of mask, so it must be part of
	 * bits described by num_after.
	 */
	/* Calculate offset within num_after for where the split is
	 * to occur.
	 */
	offset = idx - (nodep1->idx + MASK_BITS);
	orig_num_after = nodep1->num_after;

	/* Add a new node to describe the bits starting at
	 * the split point.
	 */
	nodep1->num_after = offset;
	nodep2 = node_add(s, idx);
	TEST_ASSERT(nodep2 != NULL, "NULL return from node_add()");
	TEST_ASSERT(nodep2->idx == idx, "Unexpected starting index,\n"
		"  nodep2->idx: 0x%lx\n"
		"  idx: 0x%lx", nodep2->idx, idx);

	/* Move bits after the split point into the new node */
	nodep2->num_after = orig_num_after - offset;
	if (nodep2->num_after >= MASK_BITS) {
		nodep2->mask = ~((mask_t) 0);
		nodep2->num_after -= MASK_BITS;
	} else {
		nodep2->mask = (1 << nodep2->num_after) - 1;
		nodep2->num_after = 0;
	}

	return nodep2;
}

/* Node First Const
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Output Args: None
 *
 * Return:
 *   Node pointer to the node with the lowest index.
 *
 * Searches for and returns a pointer to the node that describes the
 * lowest bit index.
 */
static const node_t *node_first_const(const pvt_t *s)
{
	const node_t *nodep;

	for (nodep = s->root; nodep && nodep->left; nodep = nodep->left)
		;

	return nodep;
}

/* Node Next Const
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   np - pointer to previous test sparsebit array node
 *
 * Output Args: None
 *
 * Return:
 *   Node pointer to the node with the lowest index > the index
 *   of the node pointed to by np.
 *   NULL if no node with a higher index exists.
 *
 * Searches for and returns a pointer to the node that describes the
 * lowest bit index.
 */
static const node_t *node_next_const(const pvt_t *s, const node_t *np)
{
	const node_t *nodep = np;

	/* If current node has a right child, next node is the left-most
	 * of the right child.
	 */
	if (nodep->right) {
		for (nodep = nodep->right; nodep->left; nodep = nodep->left)
			;
		return nodep;
	}

	/* No right child.  Go up until node is left child of a parent.
	 * That parent is then the next node.
	 */
	for (; nodep->parent && nodep == nodep->parent->right;
		nodep = nodep->parent)
		;

	return nodep->parent;
}

/* Node Next
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   idx - bit index
 *
 * Output Args: None
 *
 * Return:
 *   Node pointer to the node with the lowest index > the index
 *   of the node pointed to by np.
 *   NULL if no node with a higher index exists.

 * A non-const wrapper of node_find_const().  This wrapper works the same
 * as node_find_const() but takes a non-const pointer to the test
 * sparsebit implementation private area and returns a non-const pointer
 * to the node, if it is found.
 */
static node_t *node_next(pvt_t *s, node_t *np)
{
	return (node_t *) node_next_const(s, np);
}

/* Node Previous
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   np - pointer to next test sparsebit array node
 *
 * Output Args: None
 *
 * Return:
 *   Node pointer to the node with the highest index < the index
 *   of the node pointed to by np.
 *   NULL if no node with a lower index exists.
 *
 * Searches for and returns a pointer to the node that describes the
 * lowest bit index.
 */
static node_t *node_prev(pvt_t *s, node_t *np)
{
	const node_t *nodep = np;

	/* If current node has a left child, next node is the right-most
	 * of the left child.
	 */
	if (nodep->left) {
		for (nodep = nodep->left; nodep->right; nodep = nodep->right)
			;
		return (node_t *) nodep;
	}

	/* No left child.  Go up until node is right child of a parent.
	 * That parent is then the next node.
	 */
	for (; nodep->parent && nodep == nodep->parent->left;
		nodep = nodep->parent)
		;

	return (node_t *) nodep->parent;
}

/* All Set
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Output Args: None
 *
 * Return:
 *   True if all bits are set.
 *
 * Determines whether all the bits in the test sparsebit array are set.
 */
static bool all_set(const pvt_t *s)
{
	/* If any nodes there must be at least one bit set.  Only case
	 * where a bit is set and total num set is 0, is when all bits
	 * are set.
	 */
	if (s->root && (s->num_set == 0))
		return true;

	return false;
}

/* Is Set
 *
 * Input Args:
 *   s - pointer to test sparsebit array implementation private data
 *   idx - Bit index
 *
 * Output Args: None
 *
 * Return:
 *   True if the bit is set, false otherwise
 *
 * Determines whether the bit at the index given by idx, within the
 * test sparsebit array is set or not.  Returns true if the bit is
 * set, otherwise false is returned.
 */
static bool is_set(const pvt_t *s, test_sparsebit_idx_t idx)
{
	const node_t *nodep;

	/* Find the node that describes the setting of the bit at idx */
	for (nodep = s->root; nodep;
		nodep = (nodep->idx > idx) ? nodep->left : nodep->right) {
		if ((idx >= nodep->idx) && (idx <= (nodep->idx + MASK_BITS
			+ nodep->num_after - 1)))
			break;
	}
	if (nodep == NULL)
		return false;

	/* Bit is set if it is any of the bits described by num_after */
	if (nodep->num_after && (idx >= (nodep->idx + MASK_BITS)))
		return true;

	/* Is the corresponding mask bit set */
	TEST_ASSERT((idx >= nodep->idx) && ((idx - nodep->idx) < MASK_BITS),
		"index not part of bits described by mask, "
		"idx: 0x%lx nodep->idx: 0x%lx MASK_BITS: %lu",
		idx, nodep->idx, MASK_BITS);
	if (nodep->mask & (1 << (idx - nodep->idx)))
		return true;

	return false;
}

/* Bit Set
 *
 * Input Args:
 *   idx - bit index
 *
 * Input/Output Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array pointed to by s, sets the bit
 * at the index given by idx.
 */
static void bit_set(pvt_t *s, test_sparsebit_idx_t idx)
{
	node_t *nodep;

	/* Skip bits that are already set */
	if (is_set(s, idx))
		return;

	/* Get a node where the bit at idx is described by the mask.
	 * The node_split will also create a node, if there isn't
	 * already a node that describes the setting of bit.
	 */
	nodep = node_split(s, idx - (idx % MASK_BITS));
	TEST_ASSERT(nodep, "node not present after node_split, "
		"nodep: %p idx: 0x%lx", nodep, idx);

	/* Set the bit within the nodes mask */
	TEST_ASSERT((idx >= nodep->idx)
		&& (idx <= (nodep->idx + MASK_BITS - 1)),
		"After node split, idx not part of node mask, "
		"nodep: %p nodep->idx: 0x%lx idx: 0x%lx MASK_BITS: %lu",
		nodep, nodep->idx, idx, MASK_BITS);
	TEST_ASSERT(!(nodep->mask & (1 << (idx - nodep->idx))),
		"Unexpected, bit already set, idx: 0x%lx "
		"nodep->idx: 0x%lx nodep->mask: 0x%x",
		idx, nodep->idx, nodep->mask);
	nodep->mask |= (1 << (idx - nodep->idx));
	s->num_set++;

	node_reduce(s, nodep);
}

/* Bit Clear
 *
 * Input Args:
 *   idx - bit index
 *
 * Input/Output Args:
 *   s - pointer to test sparsebit array implementation private data
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the test sparsebit array pointed to by s, clears the bit
 * at the index given by idx.
 */
static void bit_clear(pvt_t *s, test_sparsebit_idx_t idx)
{
	node_t *nodep;

	/* Skip bits that are already cleared */
	if (!is_set(s, idx))
		return;

	/* Is there a node that describes the setting of this bit? */
	nodep = node_find(s, idx);
	if (nodep == NULL)
		return;

	/* If a num_after bit, split the node, so that the bit is
	 * part of a node mask.
	 */
	if (idx >= (nodep->idx + MASK_BITS)) {
		nodep = node_split(s, idx - (idx % MASK_BITS));
		TEST_ASSERT(nodep, "node not present after node_split, "
			"nodep: %p idx: 0x%lx", nodep, idx);
		TEST_ASSERT((idx >= nodep->idx)
			&& (idx <= (nodep->idx + MASK_BITS - 1)),
			"After node split, idx not part of node mask, "
			"nodep: %p nodep->idx: 0x%lx idx: 0x%lx MASK_BITS: %lu",
			nodep, nodep->idx, idx, MASK_BITS);
	}

	/* After node_split above, bit at idx should be within the mask.
	 * Clear that bit.
	 */
	TEST_ASSERT((idx >= nodep->idx) && (idx <= nodep->idx + MASK_BITS - 1),
		"Index not within node mask after doing node_split,\n"
		"  nodep: %p  nodep->idx: 0x%lx idx: 0x%lx MASK_BITS: %lu",
		nodep, nodep->idx, idx, MASK_BITS);
	TEST_ASSERT(nodep->mask & (1 << (idx - nodep->idx)),
		"Unexpected, mask bit is clear, "
		"idx: 0x%lx nodep->idx: 0x%lx "
		"nodep->mask: 0x%x",
		idx, nodep->idx, nodep->mask);
	TEST_ASSERT(nodep->mask & (1 << (idx - nodep->idx)),
		"Unexpected, bit already cleared, idx: 0x%lx "
		"nodep->idx: 0x%lx nodep->mask: 0x%x",
		idx, nodep->idx, nodep->mask);
	nodep->mask &= ~(1 << (idx - nodep->idx));
	TEST_ASSERT((s->num_set > 0) || all_set(s),
		"Unexpected global count "
		"of bits set, s->num_set: 0x%lx", s->num_set);
	s->num_set--;

	node_reduce(s, nodep);
}

/* Node Reduce
 *
 * Input Args: None
 *
 * Input/Output Args:
 *   nodep - pointer to next test sparsebit array node
 *   s - pointer to test sparsebit array implementation private data
 *
 * Output Args: None
 *
 * Return: None
 *
 * Iteratively reduces the node pointed to by nodep and its adjacent
 * nodes into a more compact form.  For example, a node with a mask with
 * all bits set adjacent to a previous node, will get combined into a
 * single node with an increased num_after setting.
 *
 * After each reduction, a further check is made to see if additional
 * reductions are possible with the new previous and next nodes.  Note,
 * a search for a reduction is only done across the nodes nearest nodep
 * and those that became part of a reduction.  Reductions beyond nodep
 * and the adjacent nodes that are reduced are not discovered.  It is the
 * responsibility of the caller to pass a nodep that is within one node
 * of each possible reduction.
 *
 * This function does not fix the temporary violation of all invariants.
 * For example it does not fix the case where the bit settings described
 * by two or more nodes overlap.  Such a violation introduces the potential
 * complication of a bit setting for a specific index having different settings
 * in different nodes.  This would then introduce the further complication
 * of which node has the correct setting of the bit and thus such conditions
 * are not allowed.
 *
 * This function is designed to fix invariant violations that are introduced
 * by node_split() and by changes to the nodes mask or num_after members.
 * For example, when setting a bit within a nodes mask, the function that
 * sets the bit doesn't have to worry about whether the setting of that
 * bit caused the mask to have leading only or trailing only bits set.
 * Instead, the function can call node_reduce(), with nodep equal to the
 * node address that it set a mask bit in, and node_reduce() will notice
 * the cases of leading or trailing only bits and that there is an
 * adjacent node that the bit settings could be merged into.
 *
 * This implementation specifically detects and corrects violation of the
 * following invariants:
 *
 *   + Node are only used to represent bits that are set.
 *     Nodes with a mask of 0 and num_after of 0 are not allowed.
 *
 *   + The setting of at least one bit is always described in a nodes
 *     mask (mask >= 1).
 *
 *   + A node with all mask bits set only occurs when the last bit
 *     described by the previous node is not equal to this nodes
 *     starting index - 1.  All such occurences of this condition are
 *     avoided by moving the setting of the nodes mask bits into
 *     the previous nodes num_after setting.
 */
static void node_reduce(pvt_t *s, node_t *nodep)
{
	bool reduction_performed;

	do {
		reduction_performed = false;
		node_t *prev, *next, *tmp;

		/* Potential reductions within the current node. */
		/* Nodes with all bits cleared may be removed. */
		if ((nodep->mask == 0) && (nodep->num_after == 0)) {
			/* About to remove the node pointed to by
			 * nodep, which normally would cause a problem
			 * for the next pass through the reduction loop,
			 * because the node at the starting point no longer
			 * exists.  This potential problem is handled
			 * by first remembering the location of the next
			 * or previous nodes.  Doesn't matter which, because
			 * once the node at nodep is removed, there will be
			 * no other nodes between prev and next.
			 *
			 * Note, the checks performed on nodep against both
			 * both prev and next both check for an adjacent
			 * node that can be reduced into a single node.  As
			 * such, after removing the node at nodep, doesn't
			 * matter whether the nodep for the next pass
			 * through the loop is equal to the previous pass
			 * prev or next node.  Either way, on the next pass
			 * the one not selected will become either the
			 * prev or next node.
			 */
			tmp = node_next(s, nodep);
			if (tmp == NULL)
				tmp = node_prev(s, nodep);

			node_rm(s, nodep);
			nodep = NULL;

			nodep = tmp;
			reduction_performed = true;
			continue;
		}

		/* When the mask is 0, can reduce the amount of num_after
		 * bits by moving the initial num_after bits into the mask.
		 */
		if (nodep->mask == 0) {
			TEST_ASSERT(nodep->num_after != 0, "Expected at "
				"least 1 num_after bit,\n"
				"  nodep: %p nodep->mask: 0x%x "
				"nodep->num_after: 0x%lx",
				nodep, nodep->mask, nodep->num_after);
			TEST_ASSERT((nodep->idx + MASK_BITS) > nodep->idx,
				"non-zero num_after setting describes bits "
				"beyond the max index,\n"
				"  nodep: %p nodep->idx: 0x%lx MASK_BITS: %lu",
				nodep, nodep->idx, MASK_BITS);

			nodep->idx += MASK_BITS;

			if (nodep->num_after >= MASK_BITS) {
				nodep->mask = ~0;
				nodep->num_after -= MASK_BITS;
			} else {
				nodep->mask = (1u << nodep->num_after) - 1;
				nodep->num_after = 0;
			}

			TEST_ASSERT(nodep->mask != 0, "Unexpected mask of "
				"zero, nodep: %p nodep->mask: 0x%x",
				nodep, nodep->mask);

			reduction_performed = true;
			continue;
		}

		/* Potential reductions between the current and
		 * previous nodes.
		 */
		prev = node_prev(s, nodep);
		if (prev) {
			test_sparsebit_idx_t prev_highest_bit;

			/* Nodes with no bits set can be removed. */
			if ((prev->mask == 0) && (prev->num_after == 0)) {
				node_rm(s, prev);

				reduction_performed = true;
				continue;
			}

			/* All mask bits set and previous node has
			 * adjacent index.
			 */
			if (((nodep->mask + 1) == 0)
				&& ((prev->idx + MASK_BITS) == nodep->idx)) {
				prev->num_after += MASK_BITS + nodep->num_after;
				nodep->mask = 0;
				nodep->num_after = 0;

				reduction_performed = true;
				continue;
			}

			/* Is node adjacent to previous node and the node
			 * contains a single contiguous range of bits
			 * starting from the beginning of the mask?
			 */
			prev_highest_bit = prev->idx + MASK_BITS - 1
				+ prev->num_after;
			if (((prev_highest_bit + 1) == nodep->idx)
				&& ((nodep->mask | (nodep->mask >> 1))
					== nodep->mask)) {
				/* How many contiguous bits are there?
				 * Is equal to the total number of set
				 * bits, due to an earlier check that
				 * there is a single contiguous range of
				 * set bits.
				 */
				unsigned int num_contiguous
					= __builtin_popcount(nodep->mask);
				TEST_ASSERT((num_contiguous > 0)
					&& ((1ULL << num_contiguous) - 1)
					== nodep->mask,
					"Unexpected mask, mask: 0x%x "
					"num_contiguous: %u",
					nodep->mask, num_contiguous);

				prev->num_after += num_contiguous;
				nodep->mask = 0;

				/* For predictable performance, handle special
				 * case where all mask bits are set and there
				 * is a non-zero num_after setting.  This code
				 * is functionally correct without the following
				 * conditionalized statements, but without them
				 * the value of num_after is only reduced by
				 * the number of mask bits per pass.  There are
				 * cases where num_after can be close to 2^64.
				 * Without this code it could take nearly
				 * (2^64) / 32 passes to perform the full
				 * reduction.
				 */
				if (num_contiguous == MASK_BITS) {
					prev->num_after += nodep->num_after;
					nodep->num_after = 0;
				}

				reduction_performed = true;
				continue;
			}
		}

		/* Potential reductions between the current and
		 * next nodes.
		 */
		next = node_next(s, nodep);
		if (next) {
			/* Nodes with no bits set can be removed. */
			if ((next->mask == 0) && (next->num_after == 0)) {
				node_rm(s, next);
				reduction_performed = true;
				continue;
			}

			/* Is next node index adjacent to current node
			 * and has a mask with all bits set? */
			if ((next->idx == (nodep->idx
				+ MASK_BITS + nodep->num_after))
				&& (next->mask == ~((mask_t) 0))) {
				nodep->num_after += MASK_BITS;
				next->mask = 0;
				nodep->num_after += next->num_after;
				next->num_after = 0;

				node_rm(s, next);
				next = NULL;

				reduction_performed = true;
				continue;
			}
		}
	} while (nodep && reduction_performed);
}

/* Display Range
 *
 * Input Args: None
 *   low - low index of range
 *   high - high index of range
 *   prepend_comma_space - add ", " prefix
 *
 * Output Args:
 *   stream - output stream
 *
 * Return:
 *   Number of characters that were or would have been displayed.
 *
 * When stream is non-Null, displays the inclusive index range given by
 * low and high.  When prepend_comma_space is true, the character sequence
 * ", " is prefixed to the displayed range.
 *
 * When stream is NULL, nothing is displayed, but the number of characters
 * that would have been printed is still returned.
 */
static size_t display_range(FILE *stream, test_sparsebit_idx_t low,
	test_sparsebit_idx_t high, bool prepend_comma_space)
{
	const char *fmt_str;
	size_t sz;

	/* Determine the printf format string */
	if (low == high)
		fmt_str = (prepend_comma_space)
			? ", 0x%lx" : "0x%lx";
	else
		fmt_str = (prepend_comma_space)
			? ", 0x%lx:0x%lx" : "0x%lx:0x%lx";

	/* When stream is NULL, just determine the size of what would
	 * have been printed, else print the range.
	 */
	if (stream == NULL)
		sz = snprintf(NULL, 0, fmt_str, low, high);
	else
		sz = fprintf(stream, fmt_str, low, high);

	return sz;
}

/* Dump Sub-Tree of Nodes
 *
 * Input Args:
 *   nodep - pointer to top of node sub-tree to be dumped
 *   indent - number of spaces at start of each output line
 *
 * Output Args:
 *   stream - output stream
 *
 * Return: None
 *
 * Recursively dumps to the FILE stream given by stream the contents
 * of the sub-tree of nodes pointed to by nodep.  Each line of output
 * is prefixed by the number of spaces given by indent.  On each
 * recursion, the indent amount is increased by 2.  This causes nodes
 * at each level deeper into the binary search tree to be displayed
 * with a greater indent.
 */
static void dump_nodes(FILE *stream, const node_t *nodep,
	unsigned int indent)
{
	const char *node_type;

	/* Dump contents of node */
	if (nodep->parent == NULL)
		node_type = "root";
	else if (nodep == nodep->parent->left)
		node_type = "left";
	else {
		TEST_ASSERT(nodep == nodep->parent->right,
			"Unexpected, not right child, "
			"nodep: %p nodep->parent->right: %p",
			nodep, nodep->parent->right);
		node_type = "right";
	}
	fprintf(stream, "%*s---- %s nodep: %p\n", indent, "", node_type, nodep);
	fprintf(stream, "%*s  parent: %p left: %p right: %p\n", indent, "",
		nodep->parent, nodep->left, nodep->right);
	fprintf(stream, "%*s  idx: 0x%lx mask: 0x%x num_after: 0x%lx\n",
		indent, "", nodep->idx, nodep->mask, nodep->num_after);

	/* If present, dump contents of left child nodes */
	if (nodep->left)
		dump_nodes(stream, nodep->left, indent + 2);

	/* If present, dump contents of right child nodes */
	if (nodep->right)
		dump_nodes(stream, nodep->right, indent + 2);
}
