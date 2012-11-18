# OpenSSH Database Keys #

This repo contains patches to OpenSSH to allow the usage of pubkey lookups from a database. MySQL and PostgreSQL are supported right now with SQLite supported planned.

These patches are based on an original patch by Matt Palmer of EngineYard.

These patches are used at your own risk.

## Building ##

Apply the patch (if you haven't done so already), install the appropriate database
development libraries and headers, then add the --with-[dbname]-keys option to
./configure, followed by the usual building commands.

The following databases are supported:

* MySQL: ```--with-mysql-keys```
* PostgreSQL: ```--with-postgresql-keys```

## Setup and Configuration ##

The minimum table you need to have created is as follows:

```sql
CREATE TABLE public_keys (
  username VARCHAR(255) NOT NULL,  -- Unix username for the key --
  options VARCHAR(255),  -- Options for the key --
  key TEXT NOT NULL,  -- The key itself, exactly as it would be in --
                      -- authorized_keys, including the key type and ID --
  fingerprint CHAR(48) NOT NULL  -- Key fingerprint; see below --
);

CREATE INDEX public_keys_username_fingerprint ON public_keys(username, fingerprint);
```

Yes, the table and column names are hardcoded.  If you'd like to make them
all configurable, feel free to extend the patch.

Then you need to tell OpenSSH to use the database as a source of keys, with the
following options in sshd_config:

* ```UseDatabaseKeys``` (yes/no): Whether or not to even consider the database as a source of
	keys.  Default: no
* ```DatabaseKeystoreDriver``` (string): The name of the database driver to use.  Options
  right now are [mysql, postgresql]. No default.
* ```DatabaseKeystoreServer``` (string): The IP address or hostname of the database server to use.
	At present, only one server can be specified.  Default: localhost
* ```DatabaseKeystoreUsername``` (string): The username to login to the database server with.  No
	default.
* ```DatabaseKeystorePassword``` (string): The password to login to the database server with.  No
	default.
* ```DatabaseKeystoreDatabase``` (string) The name of the database to use.  No default.

Finally, you need to populate the database with your users.  I leave that as
an exercise for the reader, with one hint: the fingerprint of a key can be
obtained with the command:

```bash
ssh-keygen -l -f <file> | cut -d ' ' -f 2
```
