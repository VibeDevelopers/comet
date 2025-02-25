/*
 * Comet: a slightly advanced ircd
 * substitution.c: parses substitution-keyword expansions
 *
 * Copyright (c) 2006-2007 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include "stdinc.h"
#include "s_user.h"
#include "snomask.h"
#include "match.h"
#include "substitution.h"
#include "s_assert.h"

/*
 * Simple mappings for $foo -> 'bar'.
 * Everything is a string, so typing doesn't really matter too
 * horribly much right now.
 */
struct substitution_variable
{
	char *name;
	char *value;
};

/*
 * substitution_append_var
 *
 * Inputs       - A variable list (rb_dlink_list), name -> value for mapping to make
 * Output       - none
 * Side Effects - Adds a name->value mapping to a list.
 */
void substitution_append_var(rb_dlink_list *varlist, const char *name, const char *value)
{
	struct substitution_variable *tmp = rb_malloc(sizeof(struct substitution_variable));

	tmp->name = rb_strdup(name);
	tmp->value = rb_strdup(value);

	rb_dlinkAddAlloc(tmp, varlist);
}

/*
 * substitution_free
 *
 * Inputs       - A rb_dlink_list of markup variables to free.
 * Outputs      - none
 * Side Effects - Empties a list of markup variables.
 */
void substitution_free(rb_dlink_list *varlist)
{
	rb_dlink_node *nptr, *nptr2;

	RB_DLINK_FOREACH_SAFE(nptr, nptr2, varlist->head)
	{
		struct substitution_variable *tmp = (struct substitution_variable *) nptr->data;

		rb_dlinkDestroy(nptr, varlist);
		rb_free(tmp->name);
		rb_free(tmp->value);
		rb_free(tmp);
	}
}

/*
 * substitution_parse
 *
 * Inputs       - A markup string, rb_dlink-list of markup values
 * Output       - A string which has been markup-replaced.
 * Side Effects - Strings larger than BUFSIZE are terminated.
 */
char *substitution_parse(const char *fmt, rb_dlink_list *varlist)
{
	static char buf[BUFSIZE];
	const char *ptr;
	char *bptr = buf;

	for (ptr = fmt; *ptr != '\0' && bptr - buf < BUFSIZE; ptr++) {
		if (*ptr != '$') {
			*bptr++ = *ptr;
		} else if (*(ptr + 1) == '{') {
			char varname[BUFSIZE] = { 0 };
			char *vptr = varname;
			rb_dlink_node *nptr;

			/* break out ${var} */
			for (ptr += 2; *ptr != '\0'; ptr++) {
				if (*ptr == '$') {
					ptr--;
					break;
				} else if (*ptr == '}') {
					break;
				} else if (vptr < &varname[sizeof(varname) - 1]) {
					*vptr++ = *ptr;
				}
			}

			RB_DLINK_FOREACH(nptr, varlist->head) {
				struct substitution_variable *val = (struct substitution_variable *) nptr->data;

				if (!rb_strcasecmp(varname, val->name)) {
					rb_strlcpy(bptr, val->value, sizeof(buf) - (bptr - buf));
					bptr += strlen(val->value);
					if (bptr >= &buf[sizeof(buf)]) {
						bptr = &buf[sizeof(buf) - 1];
					}
					break;
				}
			}

			/* don't increment ptr into a following string if the '}' is missing */
			if (*ptr == '\0')
				break;
		}
	}

	*bptr = '\0';
	return buf;
}
