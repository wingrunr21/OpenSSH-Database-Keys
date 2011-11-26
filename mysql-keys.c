/*
 * Author: Matt Palmer <mpalmer@engineyard.com>
 * Copyright (C) 2008 Engineyard Inc.
 * All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WITH_MYSQL_KEYS

#include "mysql-keys.h"
#include "xmalloc.h"

#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <stdio.h>
#include <string.h>

/* Return an "empty" result set, so that callers don't get too upset */
#define MYSQL_KEYS_ERROR_RETURN  key_list = xmalloc(sizeof(mysql_key_t));	\
                                 key_list[0].key = NULL;			\
                                 return key_list;

/* Initialise the MySQL connection handle in ServerOptions.  Can be called
 * multiple times, whenever you want the connection to be recycled.
 *
 * We do not guarantee that when you come out of this function that you'll
 * have a working MySQL connection -- that part we leave up to the caller to
 * verify that everything is OK for their needs.  We do, however, log a message
 * so that someone knows why the connection failed.
 */
void mysql_keys_init(ServerOptions *opts)
{
	debug("[MyK] Initialising MySQL connection");
	/* Clean up if we're recycling an existing connection */
	if (opts->mysql_handle != NULL) {
		debug("[MyK] Closing an existing connection");
		mysql_close(opts->mysql_handle);
	}
	
	opts->mysql_handle = mysql_init(NULL);
	
	if (!mysql_real_connect(opts->mysql_handle,
	                        opts->mysql_dbhost,
	                        opts->mysql_dbuser,
	                        opts->mysql_dbpass,
	                        opts->mysql_dbname,
	                        0, NULL, 0)) {
		logit("[MyK] Failed to connect to MySQL server %s: %s",
		      opts->mysql_dbhost,
		      mysql_error(opts->mysql_handle));
	}
}

/* Shutdown the MySQL connection. */
void mysql_keys_shutdown(ServerOptions *opts)
{
	debug("[MyK] Closing MySQL connection");
	if (opts->mysql_handle != NULL) {
		mysql_close(opts->mysql_handle);
		opts->mysql_handle = NULL;
	}
}

/* Perform a search of the database for keys with the fingerprint of the
 * given key, and returns an array of all of the keys that match (if any).
 * The array is terminated by an entry with the key set to NULL.
 */
mysql_key_t *mysql_keys_search(ServerOptions *opts, Key *key, char *username)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	mysql_key_t *key_list;
	char query[1024], *fp, *qfp, *qusername;
	unsigned int qlen, i;
	int my_err;
	
	if (!opts->mysql_handle) {
		mysql_keys_init(opts);
	}
	
	if (mysql_ping(opts->mysql_handle) != 0) {
		mysql_keys_init(opts);
		if (mysql_ping(opts->mysql_handle) != 0) {
			logit("[MyK] Connection to the database server failed: %s", mysql_error(opts->mysql_handle));
			mysql_keys_shutdown(opts);
			MYSQL_KEYS_ERROR_RETURN
		}
	}
	
	fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
	qfp = xmalloc(strlen(fp) * 2 + 1);
	mysql_real_escape_string(opts->mysql_handle, qfp, fp, strlen(fp));
	xfree(fp);

	qusername = xmalloc(strlen(username) * 2 + 1);
	mysql_real_escape_string(opts->mysql_handle, qusername, username, strlen(username));
	
	qlen = snprintf(query, 1024, "SELECT `key`,`options` FROM `public_keys` WHERE `username`='%s' AND `fingerprint`='%s'", qusername, qfp);
	if (qlen >= 1024) {
		xfree(qfp);
		xfree(qusername);
		mysql_keys_shutdown(opts);
		fatal("[MyK] The impossible happened... snprintf overflowed my giant buffer!");
	}
	
	xfree(qfp);
	xfree(qusername);

	debug2("[MyK] Going to execute query: '%s'", query);
	
	if ((my_err = mysql_real_query(opts->mysql_handle, query, qlen)) != 0) {
		if ((my_err == CR_SERVER_GONE_ERROR || my_err == CR_SERVER_LOST)) {
			if (mysql_real_query(opts->mysql_handle, query, qlen) != 0) {
				error("[MyK] Failed to execute query '%s': %s", query, mysql_error(opts->mysql_handle));
				mysql_keys_shutdown(opts);
				MYSQL_KEYS_ERROR_RETURN
			}
		} else {
			error("[MyK] Failed to execute query '%s': %s", query, mysql_error(opts->mysql_handle));
			mysql_keys_shutdown(opts);
			MYSQL_KEYS_ERROR_RETURN
		}
	}
	
	/* So if we got through the gauntlet of error handling, the query
	 * must have succeeded, and we can retrieve some results.
	 */
	res = mysql_store_result(opts->mysql_handle);
	
	if (!res) {
		error("[MyK] Failed to retrieve result set: %s", mysql_error(opts->mysql_handle));
		mysql_keys_shutdown(opts);
		MYSQL_KEYS_ERROR_RETURN
	}
	
	debug2("[MyK] Query returned %u results", (unsigned int)mysql_num_rows(res));
	
	key_list = xmalloc(sizeof(mysql_key_t) * (mysql_num_rows(res) + 1));
	for (i = 0; (row = mysql_fetch_row(res)); i++) {
		key_list[i].key = xstrdup(row[0]);
		if (row[1]) {
			key_list[i].options = xstrdup(row[1]);
		} else {
			key_list[i].options = NULL;
		}
	}
	key_list[i].key = NULL;
	
	mysql_keys_shutdown(opts);
	return key_list;
}

/* Deallocate an array of mysql_key_t structures, including the
 * array itself.
 */
void mysql_keys_free(mysql_key_t *keys)
{
	unsigned i = 0;
	
	for (i = 0; keys[i].key; i++) {
		xfree(keys[i].key);
		
		if (keys[i].options) {
			xfree(keys[i].options);
		}
	}
	
	xfree(keys);
}

#endif  /* WITH_MYSQL_KEYS */
