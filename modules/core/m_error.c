/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_error.c: Handles error messages from the other end.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 */

#include "stdinc.h"
#include "client.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "logger.h"
#include "s_conf.h"

static const char error_desc[] =
	"Provides the ERROR command for clients and servers";

static void m_error(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_error(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message error_msgtab = {
	"ERROR", 0, 0, 0, 0,
	{{m_error, 0}, mg_ignore, mg_ignore, {ms_error, 0}, mg_ignore, mg_ignore}
};

mapi_clist_av1 error_clist[] = {
	&error_msgtab, NULL
};

DECLARE_MODULE_AV2(error, NULL, NULL, error_clist, NULL, NULL, NULL, NULL, error_desc);

/* Determine whether an ERROR message is safe to show (no IP address in it) */
static bool
is_safe_error(const char *message)
{
	char prefix2[100];
	const char *p;

	if (!strncmp(message, "Closing Link: 127.0.0.1 (", 25))
		return true;
	snprintf(prefix2, sizeof prefix2,
			"Closing Link: 127.0.0.1 %s (", me.name);
	if (!strncmp(message, prefix2, strlen(prefix2)))
		return true;
	if (!strncmp(message, "Restart by ", 11))
		return true;
	if (!strncmp(message, "Terminated by ", 14))
		return true;

	if (!rb_strncasecmp(message, "Closing Link", 12))
		return false;
	if (strchr(message, '['))
		return false;
	p = strchr(message, '.');
	if (p != NULL && p[1] != '\0')
		return false;
	if (strchr(message, ':'))
		return false;

	return true;
}

/*
 * Note: At least at protocol level ERROR has only one parameter,
 * although this is called internally from other functions
 * --msa
 *
 *      parv[*] = parameters
 */
static void
m_error(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *para;
	int hideit = ConfigFileEntry.hide_error_messages;

	para = (parc > 1 && *parv[1] != '\0') ? parv[1] : "<>";

	if (IsAnyServer(client_p))
	{
		ilog(L_SERVER, "Received ERROR message from %s: %s",
		     log_client_name(source_p, SHOW_IP), para);
	}

	if(is_safe_error(para))
		hideit = 0;
	if(IsAnyServer(client_p))
	{
		if (hideit < 2)
			sendto_realops_snomask(SNO_GENERAL, hideit ? L_ADMIN : L_NETWIDE,
					"ERROR :from %s -- %s",
					client_p->name, para);
		if (hideit > 0)
			sendto_realops_snomask(SNO_GENERAL, hideit == 1 ? L_OPER | L_NETWIDE : L_NETWIDE,
					"ERROR :from %s -- <hidden>",
					client_p->name);
	}

	exit_client(client_p, source_p, source_p, "ERROR");
}

static void
ms_error(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *para;
	int hideit = ConfigFileEntry.hide_error_messages;

	para = (parc > 1 && *parv[1] != '\0') ? parv[1] : "<>";

	ilog(L_SERVER, "Received ERROR message from %s: %s",
	     log_client_name(source_p, SHOW_IP), para);

	if(is_safe_error(para))
		hideit = 0;
	if(hideit == 2)
		return;

	if(client_p == source_p)
	{
		sendto_realops_snomask(SNO_GENERAL, hideit ? L_ADMIN : L_NETWIDE, "ERROR :from %s -- %s",
				     client_p->name, para);
	}
	else
	{
		sendto_realops_snomask(SNO_GENERAL, hideit ? L_ADMIN : L_NETWIDE, "ERROR :from %s via %s -- %s",
				     source_p->name, client_p->name, para);
	}
}
