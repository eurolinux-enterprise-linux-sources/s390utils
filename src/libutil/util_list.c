/*
 * util - Utility function library
 *
 * Linked list functions
 *
 * Copyright IBM Corp. 2013
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

/*
 * Initialize linked list
 */
void util_list_init_offset(struct util_list *list, unsigned long offset)
{
	memset(list, 0, sizeof(*list));
	list->offset = offset;
}

/*
 * Create new linked list
 */
struct util_list *util_list_new_offset(unsigned long offset)
{
	struct util_list *list = malloc(sizeof(*list));

	if (!list)
		return NULL;
	util_list_init_offset(list, offset);
	return list;
}

/*
 * Free linked list
 */
void util_list_free(struct util_list *list)
{
	free(list);
}

/*
 * Add new element to end of list
 */
void util_list_entry_add_tail(struct util_list *list, void *entry)
{
	struct util_list_node *node = entry + list->offset;

	node->next = NULL;
	if (!list->start) {
		list->start = node;
		node->prev = NULL;
	} else {
		list->end->next = node;
		node->prev = list->end;
	}
	list->end = node;
}

/*
 * Add new element to front of list
 */
void util_list_entry_add_head(struct util_list *list, void *entry)
{
	struct util_list_node *node = entry + list->offset;

	node->prev = NULL;
	node->next = NULL;
	if (!list->start) {
		list->end = node;
	} else {
		list->start->prev = node;
		node->next = list->start;
	}
	list->start = node;
}

/*
 * Add new element (entry) after an existing element (list_entry)
 */
void util_list_entry_add_next(struct util_list *list, void *entry,
			      void *list_entry)
{
	struct util_list_node *node = entry + list->offset;
	struct util_list_node *list_node = list_entry + list->offset;

	node->next = list_node->next;
	node->prev = list_node;
	if (list_node->next)
		list_node->next->prev = node;
	else
		list->end = node;
	list_node->next = node;
}

/*
 * Add new element (entry) before an existing element (list_entry)
 */
void util_list_entry_add_prev(struct util_list *list, void *entry,
			      void *list_entry)
{
	struct util_list_node *node = entry + list->offset;
	struct util_list_node *list_node = list_entry + list->offset;

	node->prev = list_node->prev;
	node->next = list_node;
	if (list_node->prev)
		list_node->prev->next = node;
	else
		list->start = node;
	list_node->prev = node;
}

/*
 * Remove element from list
 */
void util_list_entry_remove(struct util_list *list, void *entry)
{
	struct util_list_node *node = entry + list->offset;

	if (list->start == node)
		list->start = node->next;
	if (list->end == node)
		list->end = node->prev;
	if (node->prev)
		node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;
}

/*
 * Get first element of list
 */
void *util_list_entry_start(struct util_list *list)
{
	if (!list->start)
		return NULL;
	return ((void *) list->start) - list->offset;
}

/*
 * Get next element after entry
 */
void *util_list_entry_next(struct util_list *list, void *entry)
{
	struct util_list_node *node;

	if (!entry)
		return NULL;
	node = entry + list->offset;
	node = node->next;
	if (!node)
		return NULL;
	return ((void *) node) - list->offset;
}

/*
 * Get previous element before entry
 */
void *util_list_entry_prev(struct util_list *list, void *entry)
{
	struct util_list_node *node;

	if (!entry)
		return NULL;
	node = entry + list->offset;
	node = node->prev;
	if (!node)
		return NULL;
	return ((void *) node) - list->offset;
}

/*
 * Check if list is empty
 */
int util_list_is_empty(struct util_list *list)
{
	return list->start == NULL;
}
