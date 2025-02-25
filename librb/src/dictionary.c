/*
 * Comet: a slightly advanced ircd
 * rb_dictionary.c: Dictionary-based information storage.
 *
 * Copyright (c) 2007 Ariadne Conill <ariadne -at- dereferenced.org>
 * Copyright (c) 2007 Jilles Tjoelker <jilles -at- stack.nl>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice is present in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <librb_config.h>
#include <rb_lib.h>
#include <rb_dictionary.h>

struct rb_dictionary
{
	DCF compare_cb;
	rb_dictionary_element *root, *head, *tail;
	unsigned int count;
	char *id;
	unsigned int dirty:1;

	rb_dlink_node node;
};

static rb_dlink_list dictionary_list = {NULL, NULL, 0};

/*
 * rb_dictionary_create(const char *name, DCF compare_cb)
 *
 * Dictionary object factory.
 *
 * Inputs:
 *     - dictionary name
 *     - function to use for comparing two entries in the dtree
 *
 * Outputs:
 *     - on success, a new dictionary object.
 *
 * Side Effects:
 *     - if services runs out of memory and cannot allocate the object,
 *       the program will abort.
 */
rb_dictionary *rb_dictionary_create(const char *name,
	DCF compare_cb)
{
	rb_dictionary *dtree = (rb_dictionary *) rb_malloc(sizeof(rb_dictionary));

	dtree->compare_cb = compare_cb;
	dtree->id = rb_strdup(name);

	rb_dlinkAdd(dtree, &dtree->node, &dictionary_list);

	return dtree;
}

/*
 * rb_dictionary_set_comparator_func(rb_dictionary *dict,
 *     DCF compare_cb)
 *
 * Resets the comparator function used by the dictionary code for
 * updating the DTree structure.
 *
 * Inputs:
 *     - dictionary object
 *     - new comparator function (passed as functor)
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the dictionary comparator function is reset.
 */
void rb_dictionary_set_comparator_func(rb_dictionary *dict,
	DCF compare_cb)
{
	lrb_assert(dict != NULL);
	lrb_assert(compare_cb != NULL);

	dict->compare_cb = compare_cb;
}

/*
 * rb_dictionary_get_comparator_func(rb_dictionary *dict)
 *
 * Returns the current comparator function used by the dictionary.
 *
 * Inputs:
 *     - dictionary object
 *
 * Outputs:
 *     - comparator function (returned as functor)
 *
 * Side Effects:
 *     - none
 */
DCF
rb_dictionary_get_comparator_func(rb_dictionary *dict)
{
	lrb_assert(dict != NULL);

	return dict->compare_cb;
}

/*
 * rb_dictionary_get_linear_index(rb_dictionary *dict,
 *     const void *key)
 *
 * Gets a linear index number for key.
 *
 * Inputs:
 *     - dictionary tree object
 *     - pointer to data
 *
 * Outputs:
 *     - position, from zero.
 *
 * Side Effects:
 *     - rebuilds the linear index if the tree is marked as dirty.
 */
int
rb_dictionary_get_linear_index(rb_dictionary *dict, const void *key)
{
	rb_dictionary_element *elem;

	lrb_assert(dict != NULL);

	elem = rb_dictionary_find(dict, key);
	if (elem == NULL)
		return -1;

	if (!dict->dirty)
		return elem->position;
	else
	{
		rb_dictionary_element *delem;
		int i;

		for (delem = dict->head, i = 0; delem != NULL; delem = delem->next, i++)
			delem->position = i;

		dict->dirty = FALSE;
	}

	return elem->position;
}

/*
 * rb_dictionary_retune(rb_dictionary *dict, const void *key)
 *
 * Retunes the tree, self-optimizing for the element which belongs to key.
 *
 * Inputs:
 *     - node to begin search from
 *
 * Outputs:
 *     - none
 *
 * Side Effects:
 *     - a new root node is nominated.
 */
static void
rb_dictionary_retune(rb_dictionary *dict, const void *key)
{
	rb_dictionary_element n, *tn, *left, *right, *node;
	int ret;

	lrb_assert(dict != NULL);

	if (dict->root == NULL)
		return;

	/*
	 * we initialize n with known values, since it's on stack
	 * memory. otherwise the dict would become corrupted.
	 *
 	 * n is used for temporary storage while the tree is retuned.
	 *    -nenolod
	 */
	n.left = n.right = NULL;
	left = right = &n;

	/* this for(;;) loop is the main workhorse of the rebalancing */
	for (node = dict->root; ; )
	{
		if ((ret = dict->compare_cb(key, node->key)) == 0)
			break;

		if (ret < 0)
		{
			if (node->left == NULL)
				break;

			if ((ret = dict->compare_cb(key, node->left->key)) < 0)
			{
				tn = node->left;
				node->left = tn->right;
				tn->right = node;
				node = tn;

				if (node->left == NULL)
					break;
			}

			right->left = node;
			right = node;
			node = node->left;
		}
		else
		{
			if (node->right == NULL)
				break;

			if ((ret = dict->compare_cb(key, node->right->key)) > 0)
			{
				tn = node->right;
				node->right = tn->left;
				tn->left = node;
				node = tn;

				if (node->right == NULL)
					break;
			}

			left->right = node;
			left = node;
			node = node->right;
		}
	}

	left->right = node->left;
	right->left = node->right;

	node->left = n.right;
	node->right = n.left;

	dict->root = node;
}

/*
 * rb_dictionary_link(rb_dictionary *dict,
 *     rb_dictionary_element *delem)
 *
 * Links a dictionary tree element to the dictionary.
 *
 * When we add new nodes to the tree, it becomes the
 * next nominated root. This is perhaps not a wise
 * optimization because of automatic retuning, but
 * it keeps the code simple.
 *
 * Inputs:
 *     - dictionary tree
 *     - dictionary tree element
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - a node is linked to the dictionary tree
 */
static rb_dictionary_element *
rb_dictionary_link(rb_dictionary *dict,
	rb_dictionary_element *delem)
{
	lrb_assert(dict != NULL);
	lrb_assert(delem != NULL);

	dict->dirty = TRUE;

	dict->count++;

	if (dict->root == NULL)
	{
		delem->left = delem->right = NULL;
		delem->next = delem->prev = NULL;
		dict->head = dict->tail = dict->root = delem;
	}
	else
	{
		int ret;

		rb_dictionary_retune(dict, delem->key);

		if ((ret = dict->compare_cb(delem->key, dict->root->key)) < 0)
		{
			delem->left = dict->root->left;
			delem->right = dict->root;
			dict->root->left = NULL;

			if (dict->root->prev)
				dict->root->prev->next = delem;
			else
				dict->head = delem;

			delem->prev = dict->root->prev;
			delem->next = dict->root;
			dict->root->prev = delem;
			dict->root = delem;
		}
		else if (ret > 0)
		{
			delem->right = dict->root->right;
			delem->left = dict->root;
			dict->root->right = NULL;

			if (dict->root->next)
				dict->root->next->prev = delem;
			else
				dict->tail = delem;

			delem->next = dict->root->next;
			delem->prev = dict->root;
			dict->root->next = delem;
			dict->root = delem;
		}
		else
		{
			dict->root->key = delem->key;
			dict->root->data = delem->data;
			dict->count--;

			rb_free(delem);
			delem = dict->root;
		}
	}

	return delem;
}

/*
 * rb_dictionary_unlink_root(rb_dictionary *dict)
 *
 * Unlinks the root dictionary tree element from the dictionary.
 *
 * Inputs:
 *     - dictionary tree
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the root node is unlinked from the dictionary tree
 */
static void
rb_dictionary_unlink_root(rb_dictionary *dict)
{
	rb_dictionary_element *delem, *nextnode, *parentofnext;

	dict->dirty = TRUE;

	delem = dict->root;
	if (delem == NULL)
		return;

	if (dict->root->left == NULL)
		dict->root = dict->root->right;
	else if (dict->root->right == NULL)
		dict->root = dict->root->left;
	else
	{
		/* Make the node with the next highest key the new root.
		 * This node has a NULL left pointer. */
		nextnode = delem->next;
		lrb_assert(nextnode->left == NULL);
		if (nextnode == delem->right)
		{
			dict->root = nextnode;
			dict->root->left = delem->left;
		}
		else
		{
			parentofnext = delem->right;
			while (parentofnext->left != NULL && parentofnext->left != nextnode)
				parentofnext = parentofnext->left;
			lrb_assert(parentofnext->left == nextnode);
			parentofnext->left = nextnode->right;
			dict->root = nextnode;
			dict->root->left = delem->left;
			dict->root->right = delem->right;
		}
	}

	/* linked list */
	if (delem->prev != NULL)
		delem->prev->next = delem->next;

	if (dict->head == delem)
		dict->head = delem->next;

	if (delem->next)
		delem->next->prev = delem->prev;

	if (dict->tail == delem)
		dict->tail = delem->prev;

	dict->count--;
}

/*
 * rb_dictionary_destroy(rb_dictionary *dtree,
 *     void (*destroy_cb)(dictionary_elem_t *delem, void *privdata),
 *     void *privdata);
 *
 * Recursively destroys all nodes in a dictionary tree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree and optionally it's children are destroyed.
 *
 * Notes:
 *     - if this is called without a callback, the objects bound to the
 *       DTree will not be destroyed.
 */
void rb_dictionary_destroy(rb_dictionary *dtree,
	void (*destroy_cb)(rb_dictionary_element *delem, void *privdata),
	void *privdata)
{
	rb_dictionary_element *n, *tn;

	lrb_assert(dtree != NULL);

	RB_DLINK_FOREACH_SAFE(n, tn, dtree->head)
	{
		if (destroy_cb != NULL)
			(*destroy_cb)(n, privdata);

		rb_free(n);
	}

	rb_dlinkDelete(&dtree->node, &dictionary_list);
	rb_free(dtree->id);
	rb_free(dtree);
}

/*
 * rb_dictionary_foreach(rb_dictionary *dtree,
 *     void (*destroy_cb)(dictionary_elem_t *delem, void *privdata),
 *     void *privdata);
 *
 * Iterates over all entries in a DTree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree is iterated
 */
void rb_dictionary_foreach(rb_dictionary *dtree,
	int (*foreach_cb)(rb_dictionary_element *delem, void *privdata),
	void *privdata)
{
	rb_dictionary_element *n, *tn;

	lrb_assert(dtree != NULL);

	RB_DLINK_FOREACH_SAFE(n, tn, dtree->head)
	{
		/* delem_t is a subclass of node_t. */
		rb_dictionary_element *delem = (rb_dictionary_element *) n;

		if (foreach_cb != NULL)
			(*foreach_cb)(delem, privdata);
	}
}

/*
 * rb_dictionary_search(rb_dictionary *dtree,
 *     void (*destroy_cb)(rb_dictionary_element *delem, void *privdata),
 *     void *privdata);
 *
 * Searches all entries in a DTree using a custom callback.
 *
 * Inputs:
 *     - dictionary tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - on success, the requested object
 *     - on failure, NULL.
 *
 * Side Effects:
 *     - a dtree is iterated until the requested conditions are met
 */
void *rb_dictionary_search(rb_dictionary *dtree,
	void *(*foreach_cb)(rb_dictionary_element *delem, void *privdata),
	void *privdata)
{
	rb_dictionary_element *n, *tn;
	void *ret = NULL;

	lrb_assert(dtree != NULL);

	RB_DLINK_FOREACH_SAFE(n, tn, dtree->head)
	{
		/* delem_t is a subclass of node_t. */
		rb_dictionary_element *delem = (rb_dictionary_element *) n;

		if (foreach_cb != NULL)
			ret = (*foreach_cb)(delem, privdata);

		if (ret)
			break;
	}

	return ret;
}

/*
 * rb_dictionary_foreach_start(rb_dictionary *dtree,
 *     rb_dictionary_iter *state);
 *
 * Initializes a static DTree iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is initialized.
 */
void rb_dictionary_foreach_start(rb_dictionary *dtree,
	rb_dictionary_iter *state)
{
	lrb_assert(dtree != NULL);
	lrb_assert(state != NULL);

	state->cur = NULL;
	state->next = NULL;

	/* find first item */
	state->cur = dtree->head;

	if (state->cur == NULL)
		return;

	/* make state->cur point to first item and state->next point to
	 * second item */
	state->next = state->cur;
	rb_dictionary_foreach_next(dtree, state);
}

/*
 * rb_dictionary_foreach_cur(rb_dictionary *dtree,
 *     rb_dictionary_iter *state);
 *
 * Returns the data from the current node being iterated by the
 * static iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - reference to data in the current dtree node being iterated
 *
 * Side Effects:
 *     - none
 */
void *rb_dictionary_foreach_cur(rb_dictionary *dtree __attribute__((unused)),
	rb_dictionary_iter *state)
{
	lrb_assert(dtree != NULL);
	lrb_assert(state != NULL);

	return state->cur != NULL ? state->cur->data : NULL;
}

/*
 * rb_dictionary_foreach_next(rb_dictionary *dtree,
 *     rb_dictionary_iter *state);
 *
 * Advances a static DTree iterator.
 *
 * Inputs:
 *     - dictionary tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is advanced to a new DTree node.
 */
void rb_dictionary_foreach_next(rb_dictionary *dtree,
	rb_dictionary_iter *state)
{
	lrb_assert(dtree != NULL);
	lrb_assert(state != NULL);

	if (state->cur == NULL)
	{
		rb_lib_log("rb_dictionary_foreach_next(): called again after iteration finished on dtree<%p>", (void *)dtree);
		return;
	}

	state->cur = state->next;

	if (state->next == NULL)
		return;

	state->next = state->next->next;
}

/*
 * rb_dictionary_find(rb_dictionary *dtree, const void *key)
 *
 * Looks up a DTree node by name.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the dtree node requested
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
rb_dictionary_element *rb_dictionary_find(rb_dictionary *dict, const void *key)
{
	lrb_assert(dict != NULL);

	/* retune for key, key will be the tree's root if it's available */
	rb_dictionary_retune(dict, key);

	if (dict->root && !dict->compare_cb(key, dict->root->key))
		return dict->root;

	return NULL;
}

/*
 * rb_dictionary_add(rb_dictionary *dtree, const void *key, void *data)
 *
 * Creates a new DTree node and binds data to it.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name for new DTree node
 *     - data to bind to the new DTree node
 *
 * Outputs:
 *     - on success, a new DTree node
 *     - on failure, NULL
 *
 * Side Effects:
 *     - data is inserted into the DTree.
 */
rb_dictionary_element *rb_dictionary_add(rb_dictionary *dict, const void *key, void *data)
{
	rb_dictionary_element *delem;

	lrb_assert(dict != NULL);
	lrb_assert(data != NULL);
	lrb_assert(rb_dictionary_find(dict, key) == NULL);

	delem = rb_malloc(sizeof(*delem));
	delem->key = key;
	delem->data = data;

	return rb_dictionary_link(dict, delem);
}

/*
 * rb_dictionary_delete(rb_dictionary *dtree, const void *key)
 *
 * Deletes data from a dictionary tree.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of DTree node to delete
 *
 * Outputs:
 *     - on success, the remaining data that needs to be rb_freed
 *     - on failure, NULL
 *
 * Side Effects:
 *     - data is removed from the DTree.
 *
 * Notes:
 *     - the returned data needs to be rb_freed/released manually!
 */
void *rb_dictionary_delete(rb_dictionary *dtree, const void *key)
{
	rb_dictionary_element *delem = rb_dictionary_find(dtree, key);
	void *data;

	if (delem == NULL)
		return NULL;

	data = delem->data;

	rb_dictionary_unlink_root(dtree);
	rb_free(delem);

	return data;
}

/*
 * rb_dictionary_retrieve(rb_dictionary *dtree, const void *key)
 *
 * Retrieves data from a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the data bound to the DTree node.
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
void *rb_dictionary_retrieve(rb_dictionary *dtree, const void *key)
{
	rb_dictionary_element *delem = rb_dictionary_find(dtree, key);

	if (delem != NULL)
		return delem->data;

	return NULL;
}

/*
 * rb_dictionary_size(rb_dictionary *dict)
 *
 * Returns the size of a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *
 * Outputs:
 *     - size of dictionary
 *
 * Side Effects:
 *     - none
 */
unsigned int rb_dictionary_size(rb_dictionary *dict)
{
	lrb_assert(dict != NULL);

	return dict->count;
}

/* returns the sum of the depths of the subtree rooted in delem at depth depth */
static int
stats_recurse(rb_dictionary_element *delem, int depth, int *pmaxdepth)
{
	int result;

	if (depth > *pmaxdepth)
		*pmaxdepth = depth;
	result = depth;
	if (delem && delem->left)
		result += stats_recurse(delem->left, depth + 1, pmaxdepth);
	if (delem && delem->right)
		result += stats_recurse(delem->right, depth + 1, pmaxdepth);
	return result;
}

/*
 * rb_dictionary_stats(rb_dictionary *dict, void (*cb)(const char *line, void *privdata), void *privdata)
 *
 * Returns the size of a dictionary.
 *
 * Inputs:
 *     - dictionary tree object
 *     - callback
 *     - data for callback
 *
 * Outputs:
 *     - none
 *
 * Side Effects:
 *     - callback called with stats text
 */
void rb_dictionary_stats(rb_dictionary *dict, void (*cb)(const char *line, void *privdata), void *privdata)
{
	char str[256];
	int sum, maxdepth;

	lrb_assert(dict != NULL);

	if (dict->count)
	{
		maxdepth = 0;
		sum = stats_recurse(dict->root, 0, &maxdepth);
		snprintf(str, sizeof str, "%-30s %-15s %-10u %-10d %-10d %-10d", dict->id, "DICT", dict->count, sum, sum / dict->count, maxdepth);
	}
	else
	{
		snprintf(str, sizeof str, "%-30s %-15s %-10s %-10s %-10s %-10s", dict->id, "DICT", "0", "0", "0", "0");
	}

	cb(str, privdata);
}

void rb_dictionary_stats_walk(void (*cb)(const char *line, void *privdata), void *privdata)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, dictionary_list.head)
	{
		rb_dictionary_stats(ptr->data, cb, privdata);
	}
}
