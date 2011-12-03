/*
 * Author: Stafford Brunk <stafford.brunk@gmail.com>
 * Copyright (C) 2011
 * All Rights Reserved
 *
 * Based on an original patch by Matt Palmer <mpalmer@engineyard.com>
 * https://github.com/tmm1/brew2deb/blob/master/packages/openssh/mysql_patch_5.8-p1-1.patch
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

#ifndef POSTGRESQL_KEYS_H
#define POSTGRESQL_KEYS_H

#include <libpq-fe.h>
#include "key.h"
#include "log.h"
#include "servconf.h"
#include "database-keys.h"

static PGconn *postgresql_handle;

void postgresql_keys_init(ServerOptions *);
void postgresql_keys_shutdown();
database_key_t *postgresql_keys_search(ServerOptions *, Key *, char *);

#endif  /* POSTGRESQL_KEYS_H */
	
