/*
 * Author: Matt Palmer <mpalmer@engineyard.com>
 * Modified: Stafford Brunk <stafford.brunk@gmail.com>
 * Copyright (C) 2011
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

#ifdef WITH_POSTGRESQL_KEYS

#include "database-keys.h"
#include "postgresql-keys.h"
#include "xmalloc.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <string.h>

#define POSTGRESQL_DEFAULT_PORT 5432

/* Initialise the PostgreSQL connection handle in ServerOptions.  Can be called
 * multiple times, whenever you want the connection to be recycled.
 *
 * We do not guarantee that when you come out of this function that you'll
 * have a working PostgreSQL connection -- that part we leave up to the caller to
 * verify that everything is OK for their needs.  We do, however, log a message
 * so that someone knows why the connection failed.
 */
void postgresql_keys_init(ServerOptions *opts)
{
  const char *conn_string_template, *conn_string;
  unsigned int conn_len;

  debug("[DBKeys] Initialising PostgreSQL connection");
  /* Clean up if there's an existing connection */
  postgresql_keys_shutdown();

  //Build the connection string
  conn_string_template = "host = '%s' port = '%u' dbname = '%s' user = '%s' password = '%s' connect_timeout = '10'";
  conn_string = xmalloc((strlen(opts->dbkeys_host) +
                    5 + /* Ports are at most 5 digits */
                    strlen(opts->dbkeys_user) +
                    strlen(opts->dbkeys_password) +
                    strlen(opts->dbkeys_database) +
                    strlen(conn_string_template)) * 2 + 1 );
                    
  /* Set port to default port if port number is invalid */
  if (opts->dbkeys_port <= 0 || opts->dbkeys_port > 65535)
  {
    opts->dbkeys_port = POSTGRESQL_DEFAULT_PORT;
  }

  conn_len = snprintf(conn_string, 1024, conn_string_template, opts->dbkeys_host, \
                                 ((unsigned int) opts->dbkeys_port), \
                                 opts->dbkeys_database, \
                                 opts->dbkeys_user, \
                                 opts->dbkeys_password);

  if (conn_len >= 1024) {
    xfree(conn_string);
    postgresql_keys_shutdown();
    fatal("[DBKeys] snprintf overflowed the connection string buffer!");
  }

  //Connect to PostgreSQL
  postgresql_handle = PQconnectdb(conn_string);
  if (!postgresql_handle) {
    logit ("[DBKeys] PQconnectdb returned NULL when connecting to %s", opts->dbkeys_host);
  }
  if (PQstatus(postgresql_handle) != CONNECTION_OK) {
    logit ("[DBKeys] Failed to connect to PostgreSQL server %s: %s", opts->dbkeys_host, PQerrorMessage(postgresql_handle));
  }

  xfree(conn_string);
}

/* Shutdown the PostgreSQL connection. */
void postgresql_keys_shutdown()
{
  if (postgresql_handle != NULL) {
    debug("[DBKeys] Closing PostgreSQL connection");
    PQfinish(postgresql_handle);
    postgresql_handle = NULL;
  }
}

/* Perform a search of the database for keys with the fingerprint of the
 * given key, and returns an array of all of the keys that match (if any).
 * The array is terminated by an entry with the key set to NULL.
 */
database_key_t *postgresql_keys_search(ServerOptions *opts, Key *key, char *username)
{
  PGresult *res;
  database_key_t *key_list;
  char query[1024], *fp, *qfp, *qusername;
  unsigned int qlen, i;
  int my_err;

  if (!postgresql_handle) {
    postgresql_keys_init(opts);
  }

  if (PQstatus(postgresql_handle) != CONNECTION_OK) {
    postgresql_keys_init(opts);
    if (PQstatus(postgresql_handle) != CONNECTION_OK) {
      logit ("[DBKeys] Failed to connect to PostgreSQL server %s: %s", opts->dbkeys_host, PQerrorMessage(postgresql_handle));
      postgresql_keys_shutdown();
      DATABASE_KEYS_ERROR_RETURN
    }
  }

  fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
  qfp = xmalloc(2*strlen(fp) + 1);
  PQescapeStringConn(postgresql_handle, qfp, fp, strlen(fp), NULL);
  xfree(fp);

  qusername = xmalloc(2*strlen(username) + 1);
  PQescapeStringConn(postgresql_handle, qusername, username, strlen(username), NULL);

  /* See macro definition in database-keys.h */
  qlen = snprintf(query, 1024, KEY_QUERY_TEMPLATE, qusername, qfp);
  
  xfree(qfp);
  xfree(qusername);
  
  if (qlen >= 1024) {
    postgresql_keys_shutdown();
    fatal("[DBKeys] snprintf overflowed the query string buffer!");
  }

  debug2("[DBKeys] Going to execute query: '%s'", query);
  res = PQexec(postgresql_handle, query);

  if (PQresultStatus(res) != PGRES_TUPLES_OK)
  {
    error("[DBKeys] Failed to execute query '%s': %s", query, PQerrorMessage(postgresql_handle));
    PQclear(res);
    postgresql_keys_shutdown();
    DATABASE_KEYS_ERROR_RETURN
  }

  /*
   * If we got here, query succeeded
   */
  debug2("[DBKeys] Query returned %u results", (unsigned int) PQntuples(res));

  key_list = xmalloc(sizeof(database_key_t) * (PQntuples(res) + 1));
  for (i = 0; i < PQntuples(res); i++)
  {
      key_list[i].key = xstrdup(PQgetvalue(res, i, 0));
      if (!PQgetisnull(res, i, 1)) {
        key_list[i].options = xstrdup(PQgetvalue(res, i, 1));
      } else {
        key_list[i].options = NULL;
      }
  }
  key_list[i].key = NULL;
  PQclear(res);

  postgresql_keys_shutdown();
  return key_list;
}

#endif  /* WITH_POSTGRESQL_KEYS */
