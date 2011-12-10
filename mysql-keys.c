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

#include "database-keys.h"
#include "mysql-keys.h"
#include "xmalloc.h"

#include <mysql.h>
#include <errmsg.h>
#include <stdio.h>
#include <string.h>

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
	debug("[DBKeys] Initialising MySQL connection");
	
	/* Cleanup any existing connections */
  mysql_keys_shutdown();
	
	mysql_handle = mysql_init(NULL);
	
	if (opts->dbkeys_port < 0)
	{
    opts->dbkeys_port = 0;
	}
	
	if (!mysql_real_connect(mysql_handle,
	                        opts->dbkeys_host,
	                        opts->dbkeys_user,
	                        opts->dbkeys_password,
	                        opts->dbkeys_database,
	                        opts->dbkeys_port, NULL, 0)) {
		logit("[DBKeys] Failed to connect to MySQL server %s: %s",
		      opts->dbkeys_host,
		      mysql_error(mysql_handle));
	}
}

/* Shutdown the MySQL connection. */
void mysql_keys_shutdown()
{
	if (mysql_handle != NULL) {
	  debug("[DBKeys] Closing MySQL connection");
		mysql_close(mysql_handle);
		mysql_handle = NULL;
	}
}

/* Perform a search of the database for keys with the fingerprint of the
 * given key, and returns an array of all of the keys that match (if any).
 * The array is terminated by an entry with the key set to NULL.
 */
database_key_t *mysql_keys_search(ServerOptions *opts, Key *key, char *username)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	database_key_t *key_list;
	char query[1024], *fp, *qfp, *qusername;
	unsigned int qlen, i;
	int my_err;
	
	debug("SEARCH mysql_handle is NULL %s", mysql_handle == NULL ? "true" : "false");
	if (!mysql_handle) {
		mysql_keys_init(opts);
	}
	
	if (mysql_ping(mysql_handle) != 0) {
		mysql_keys_init(opts);
		if (mysql_ping(mysql_handle) != 0) {
			logit("[DBKeys] Connection to the database server failed: %s", mysql_error(mysql_handle));
			mysql_keys_shutdown();
			DATABASE_KEYS_ERROR_RETURN
		}
	}
	
	fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
	qfp = xmalloc(strlen(fp) * 2 + 1);
	mysql_real_escape_string(mysql_handle, qfp, fp, strlen(fp));
	xfree(fp);

	qusername = xmalloc(strlen(username) * 2 + 1);
	mysql_real_escape_string(mysql_handle, qusername, username, strlen(username));

  /* See macro definition in database-keys.h */
  qlen = snprintf(query, 1024, KEY_QUERY_TEMPLATE, qusername, qfp);

	if (qlen >= 1024) {
		xfree(qfp);
		xfree(qusername);
		mysql_keys_shutdown();
		fatal("[DBKeys] The impossible happened... snprintf overflowed my giant buffer!");
	}
	
	xfree(qfp);
	xfree(qusername);

	debug2("[DBKeys] Going to execute query: '%s'", query);
	
	if ((my_err = mysql_real_query(mysql_handle, query, qlen)) != 0) {
		if ((my_err == CR_SERVER_GONE_ERROR || my_err == CR_SERVER_LOST)) {
			if (mysql_real_query(mysql_handle, query, qlen) != 0) {
				error("[DBKeys] Failed to execute query '%s': %s", query, mysql_error(mysql_handle));
				mysql_keys_shutdown();
				DATABASE_KEYS_ERROR_RETURN
			}
		} else {
			error("[DBKeys] Failed to execute query '%s': %s", query, mysql_error(mysql_handle));
			mysql_keys_shutdown();
			DATABASE_KEYS_ERROR_RETURN
		}
	}
	
	/* So if we got through the gauntlet of error handling, the query
	 * must have succeeded, and we can retrieve some results.
	 */
	res = mysql_store_result(mysql_handle);
	
	if (!res) {
		error("[DBKeys] Failed to retrieve result set: %s", mysql_error(mysql_handle));
		mysql_keys_shutdown();
		DATABASE_KEYS_ERROR_RETURN
	}
	
	debug2("[DBKeys] Query returned %u results", (unsigned int)mysql_num_rows(res));
	
	key_list = xmalloc(sizeof(database_key_t) * (mysql_num_rows(res) + 1));
	for (i = 0; (row = mysql_fetch_row(res)); i++) {
		key_list[i].key = xstrdup(row[0]);
		if (row[1]) {
			key_list[i].options = xstrdup(row[1]);
		} else {
			key_list[i].options = NULL;
		}
	}
	key_list[i].key = NULL;
	
	mysql_keys_shutdown();
	return key_list;
}

#endif  /* WITH_MYSQL_KEYS */
