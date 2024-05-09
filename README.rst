git-nerps
=========

Tool to encrypt and manage secret files in git repository.

Uses libsodium_ (wrapped by libnacl_ / PyNaCl_) encryption
(`NaCl crypto_secretbox`_, see "Crypto details" section below for more info),
gitattributes and git-config for configuration storage, which is partly shared
with git and can be edited/adjusted by hand as well.

All the stuff is implemented as one python script
(python3, though repo history has python2 version as well),
which has different subcommands.
See --help output for a full list of these.

.. _libsodium: http://libsodium.org/
.. _libnacl: http://libnacl.readthedocs.io/
.. _PyNaCl: http://pynacl.readthedocs.io/
.. _NaCl crypto_secretbox: http://nacl.cr.yp.to/secretbox.html

|

.. contents::
  :backlinks: none

Repository URLs:

- https://github.com/mk-fg/git-nerps
- https://codeberg.org/mk-fg/git-nerps
- https://fraggod.net/code/git/git-nerps



Idea
----

Main purpose of the tool is to make it easy to store configuration that has
some secrets in it within branches of a git repository.

I.e. imagine a bunch of containers which share some/most configs and keep their
configuration in git branches.

You'd like to easily pull, push, merge and cherry-pick between these
repositories/branches, but each container has occasional bits that should not be
shared, e.g. passwords.txt file.

One solution is to keep such secret files out of repository or in a separate one,
another would be to transparently encrypt/decrypt these files in the repository.

Such secrets can even be shared between containers that have access to same key,
while remaining inaccessible without one.

That way, only one short bit of data (key) has to be unique for a host,
and presumably stored/backed-up in some trusted place(s) (e.g. dev machine),
while the rest of the host configuration can be shared, well-replicated and/or public.

Modifying .git/config and .gitattributes to facilitate that by hand gets old fast,
plus one needs to store keys and have a dedicated tool/wrapper for git filters anyway.

This tool can be used to do all that in a simple and relatively foolproof way.




Usage
-----

See ``git nerps --help`` for full list of all supported commands and common
options, and e.g. ``git nerps key-gen --help`` for args/opts to any particular
command.

"git-nerps" and "git nerps" commands be used interchangeably, when script is in $PATH.


Initialize repository configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Same as with most commands below, only makes sense to run in a git repository.

::

  % git nerps init

This is done automatically on any meaningful action (e.g. "key-gen"),
so can usually be skipped.

Repository config ".git/config" should have these additional sections after that::

  [filter "nerps"]
    clean = ~/.git-nerps git-clean
    smudge = ~/.git-nerps git-smudge
  [diff "nerps"]
    textconv = ~/.git-nerps git-diff
    cachetextconv = true
  [nerps]
    n-e-r-p-s = NERPS
    version = 1

| Any of these can be added and tweaked manually.
| See "git-config values" section below for details on each parameter.


Generate encryption keys
^^^^^^^^^^^^^^^^^^^^^^^^

::

  % git nerps key-gen

  % tail -2 .git/config
  [nerps "key"]
    alfa = d2rmvoMBcPAcs-otYtbRH_WIIztXtg7ONcbGgzwcpQo=

Generated key with auto-picked name "alfa" was stored in ".git/config", as
demonstrated above.

It will be used by default if it's the only key available.

With >1 keys, "key-set" command can be used to pick which one to use for new
files (and "key-unset" to reset that selection), otherwise first key found in
the config is used.

Decryption uses all available keys by default.

Key names get auto-picked from `phonetic alphabet`_, if not specified explicity -
i.e. alfa, bravo, charlie, etc - a set of words designed to be fairly distinctive.

Keys can also be stored in user's home directory (and selected via "key-set"
with -d/--homedir option), and these will be available for all repositories,
but key explicitly set as "default" in the current repo will take priority.

Extended example (from a fresh repository)::

  % git nerps key-gen
  % git nerps key-gen

  % git nerps key-gen -v
  Generated new key 'charlie':
    SZi85A55-RWKNFvDqTsq0T_ArANBoZw8DKEojtrLA8o=

  % git nerps key-gen --homedir homer

  % git nerps key-list
  alfa [default]
  bravo
  charlie
  homer

  % git nerps key-set bravo
  % git nerps key-list
  alfa
  bravo [default]
  charlie
  homer

  % git nerps key-gen --set-as-default
  % git nerps key-list
  alfa
  bravo
  charlie
  delta [default]
  homer

  % git nerps key-unset
  % git nerps key-set --homedir homer
  % git nerps key-list
  alfa
  bravo
  charlie
  delta
  homer [default]

If another often-used secret - ssh private key - is already present in user's
homedir, it might be a good idea to derive git key from that instead.

Tool supports parsing such keys and deriving new ones from from them in a
secure and fully deterministic fashion (using PBKDF2, see "Crypto details"
section below) via --from-ssh-key option::

  % git nerps key-gen -v --from-ssh-key
  Key:
    6ykkvuyS7gX9FpxtjGkntJFlGvk_t4oGsIJAPsy_Hn4=

Option --from-ssh-key-pbkdf2-params can be used to tweak PBKDF2 parameters to
e.g. derive several different keys from signle ssh key.

That way, while generated key will be stored in the config, it doesn't really
have to be preserved (e.g. can be removed with the repo or container), as it's
easy to generate it again from the same ssh key (but be sure to keep ssh key
safe, if that is the case!).

Scripts like ssh-keyparse_ can help to reduce modern ssh keys (ed25519) to a
short password-like strings - similar to ones git-nerps uses - for an easy backup.

.. _phonetic alphabet: https://en.wikipedia.org/wiki/NATO_phonetic_alphabet


Mark new files to be encrypted
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  % git ls-files
  backup_script.sh

  % cp ~/rsync_auth.txt .
  % git nerps taint rsync_auth.txt
  % git add rsync_auth.txt .gitattributes
  % git commit -a -m 'Add rsync auth data'

  % git ls-files
  .gitattributes
  backup_script.sh
  rsync_auth.txt

``git nerps taint`` will add ``/rsync_auth.txt filter=nerps diff=nerps`` line
to ".gitattributes" file (creating it, if necessary), so that contents of the
file in the repository will always be transparently encrypted.

This can be applied to files that are already in the repository, but that
command will NOT rebase whole commit history to wipe or encrypt that file
there - this can be done manually, but might be tricky (e.g. with many branches).

``git nerps taint`` also has -l/--local-only option to use
".git/info/attributes" (which is not shared between repo clones)
instead to the same effect.

``git nerps clear`` removes "taint" from file(s), if it's ever necessary.

Both "taint" and "clear" commands operate on gitattributes lines with patterns
matching repo-relative path to specified file(s), making sure that there's
exactly one such match (see also --force and --silent options), so it's
perfectly fine to add any valid patterns there by hand, these commands should
pick these up.

Note that neither "taint" nor "clear" touch contents of actual file's in the
local copy (i.e. on fs) at all - only set git attributes for future git commits.


Wipe accidentally-comitted secret from git repo
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Just ``git rm`` on the file obviously won't get it done, as previous commits
will still have the file in plaintext.

Rebasing can wipe it from those, but one'd still be able to recover old tree via
git-reflog, so that has to be cleaned-up as well, and then git's
garbage-collection mechanism should be run to purge unlinked blobs.

Removing file(s) from **local** branches can be done like this::

  % git filter-branch --index-filter \
    "git rm -rf --cached --ignore-unmatch $files" HEAD

  % git filter-branch --index-filter \
    "git rm -rf --cached --ignore-unmatch $files" some-other-branch
  ...

All combinations of branches and files should be processed by ``git
filter-branch`` above, including any branches that are currently present on
remotes only (i.e. pull/filter/push -f all these as well)!

But note that local ".git" dir will still contain these files in various caches
and refs (think reflog).

While it's possible to purge at least some of these with "git reflog expire" and
"git gc" and some "rm -rf" commands, there is no guarantee that something won't
remain (e.g. --textconv cache, unlinked file in objects, etc).

To get clean .git directory, cloning it anew from local or remote repo copy
should work.

Pushing rebase result to a *bare* remote repo (no local copy, as e.g. gitolite
creates these) might get rid of the file(s) there as well (or maybe with an
extra ``git gc --aggressive --prune=now`` command), as those don't keep reflog
history by default, but be sure to check for extra branches there and it can
still be unreliable and a subject to change.

One way to check for leftover secrets in the filtered/cloned repo branches can
be exporting it via "git fast-export", making sure data is not there (simple
grep should do it), and re-initializing both local and remote repos from that.


Encrypt/decrypt local file
^^^^^^^^^^^^^^^^^^^^^^^^^^

Note that this is the opposite of what "taint" does, where actual local file is
never touched, and it's only blobs in ".git" that get encrypted.

So doesn't need to be run manually along with "taint" or anything like that,
just an extra option for encrypting non-git stuff with the same key for whatever
other purposes.

This tool is only designed to operate on small files (up to a megabyte or a few),
for larger files I'd suggest using gpg with assymetric keys instead.

::

  % echo password >secret.conf
  % git nerps encrypt secret.conf
  % grep password secret.conf # encrypted file - no results

  % git nerps encrypt secret.conf
  % git nerps encrypt secret.conf # safe* to run multiple times

  % git nerps decrypt secret.conf
  % cat secret.conf
  password

  % git nerps decrypt secret.conf
  % git nerps decrypt secret.conf # safe* to run on plaintext
  % cat secret.conf
  password

One caveat here that also makes it "safe" to run encrypt/decrypt multiple times
is that both operations check "magic" at the start of a file and run/abort
depending on presence of those bytes.

This means that if file already has these weird bytes at the start (e.g. as a
result of some malicious tampering), "encrypt" won't do anything to it - see
"Crypto details" section below for more info.


Confirm that file was or will-be encrypted
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Git does not (and probably should not) track which filters are used in which
commit, so only reliable way to tell if the file is encrypted in git-log or
git-index is by its contents.

Most obvious ways to do that are:

* ``git show`` and ``--no-textconv`` option.

  For file from an arbitrary commit (e.g. 7b53fd0) in git history::

    % git show 7b53fd0:etc/cjdroute.conf
    ¯\_ʻnerpsʻ_/¯ 1
    ...binary data blob...

  ``--no-textconv`` option can be added here, but should be default.

  File added for commit in the working tree::

    % git diff --no-textconv HEAD -- /etc/cjdroute.conf
    diff --git a/etc/cjdroute.conf b/etc/cjdroute.conf
    new file mode 100644
    index 0000000..165fed5
    Binary files /dev/null and b/etc/cjdroute.conf differ

    % git show 165fed5
    ¯\_ʻnerpsʻ_/¯ 1
    ...binary data blob...

  Use ``diff --staged`` to see only changes that were queued via git-add.

  ``git log --no-textconv`` can also be used in a similar fashion.

* ``git log --stat`` / ``git diff --stat``.

  Encrypted files in ``--stat`` output show up as binary blobs, which can be
  easy enough to spot for an otherwise text files, without inspecting every file
  with git-show.

* ``git clone``.

  git-clone can be used to get copy of a repo (e.g. ``git clone ~/path/to/myrepo
  myrepo-copy``), as it is seen by someone without access to keys, where all
  files should always be in their encrypted form.

* There should probably be a git-nerps subcommand to make it easier.




Installation
------------

Requirements:

* Python 3.6+ (dig up repo history for an old 2.7 version)

* libnacl_ or PyNaCl_ python module - either one will work,
  and they're interoperable with each other (use same libsodium),
  so which one is used makes no difference whatsoever.

Both deps should be available in distro package repositories.
PyNaCl/libnacl can also be installed from PyPI via pip.

Install git-nerps.py script to PATH and test if it works from there::

  % install -m0755 git-nerps.py /usr/local/bin/git-nerps

  % git nerps -h
  usage: git nerps [-h] [-d] [-n key-name] [-s] ...
  ...

That's it.




Drawbacks, quirks and warnings
------------------------------


* DO NOT TRUST THIS TOOL TO BE UNIVERSALLY SECURE.

  | I (author) don't use it to store data that is valuable,
  | sensitive or can get me in trouble in any of my public git repositories.
  | Not a single such file on my public git server or github.
  | Think about it.

  My use-case is to have shared configuration repositories, to which -
  unless something goes wrong - there is no unsanctioned access anyway.

  Protection there is from accidental leaks, scraper bots or mildly curious
  hacker types, and it's fairly trivial to just change all secrets when/if
  ciphertext gets into wrong hands (assuming it gets detected).

  Secrets themselves are nothing valuable in my case too, just a PITA to rebuild
  compromised stuff from scratch at most, hence this added bit of security with
  little extra effort.

  | **Your** threat model can be drastically different!!!
  | Do not trust this tool with your life, it's not made for this at all.

  And if any tool/tech/practice gets advertised as "secure" for everything and
  against everything, please be first to call bullshit on that.

  Plus I'm no security expert or cyptographer anyway, just a random coder, so
  maybe don't trust me much either.


* When encrypted with the same key, two exact copies of the same file will
  produce exactly same ciphertext.

  This is intentional for a git filter, since mixing-in info from filename is
  kinda tricky, as it's not always available and can lead to some weird bugs
  (e.g. "git mv" producing broken files), and using entirely random nonce will
  produce spurious changes in ciphertext with no changes in plaintext.

  So if it is important to not leak info about two files being identical, only
  way with this tool is to actually make them non-identical - even one-bit
  difference (whitespace, padding, BOM, etc) should make them unrecognizable.

  It's not the same case as with "salt" in passwords at all though - should
  still be impossible to bruteforce these ciphertexts without bruteforcing whole
  symmetric cipher key, at which point one can use it to just decrypt the file.


* As noted in `this letter by Junio C Hamano`_, it is unwise to fully encrypt
  files that get modified all the time, as that defeats the whole purpose of git
  ("change" will always be "whole file") and especially its attrs mechanism
  (which is designed with almost opposite goals in mind).

  In addition to the above, git isn't well suited to store binary blobs in
  general, which encrypted files are.

  But keeping only secrets encrypted, which can be e.g. separate
  very-rarely-modified files of tiny size should be perfectly fine.


* This tool is for secrecy, not consistency (or authentication).

  While encrypted files will always be authenticated against tampering or
  accidental corruption, use usual gpg-signed commits or keep track of history
  hashes or such to make sure history/data in the repo is consistent with what
  is expected.


* If key is lost, encrypted data is useless.

  git makes it easy to replicate repository history over many remotes - just
  define a bunch of urls for "origin" and push.

  Keep in mind that for any valuable secrets, it might be wise to keep roughly
  same level of replication as with ciphertext itself, i.e. keep N copies of
  keys for N copies of data, just maybe in different (more private) places.

  This gets even more important consideration for git history - if any key will
  be lost (or e.g. changed and old one discarded) in the future, everything
  encrypted by it in the git-log will be lost forever.


* Encryption keys are stored in "repo/.git/config" or "~/.git-nerps-keys".

  It is very important to protect and NOT to loose or share/leak these files.

  Be sure to keep that in mind when copying repository without "git clone" or
  sharing dev copies/environments between users or machines.

  Tool changes modes on "repo/.git" and "repo/.git/config" to make sure there's
  no extra access there. Git should not mess these up, bit it might be worth to
  keep modes on these paths in mind when messing with them.

  Never allow access to "repo/.git" directory over http(s) - alas, fairly common
  security issue, for many different reasons, but here especially so.


* git caches plaintext --textconv results in local .git/objects/... files.

  So even after loosing or deleting the key, it might be possible to recover cached
  secrets from there, via ``git show --textconv`` or ``git log -u`` for example.

  Hence it's unwise to ever share raw local ".git" dir with anything, if any
  secret was ever added or comitted there, with or without git-nerps filtering.

  Clone/push/pull operations do not transfer or use these caches in any way.


* Name of the tool literally makes no sense. NERPS.


.. _this letter by Junio C Hamano: http://article.gmane.org/gmane.comp.version-control.git/113221




Affected files and git-config params
------------------------------------

All files are using git configuration formats,
more info on which can be found in `git-config(1)`_.


Files
^^^^^

* .git/config, $GIT_CONFIG or whatever git-config(1) detects.

* ~/.git-nerps - symlink to the script, to be used in git configs.

* ~/.git-nerps-keys - per-user git-config file for crypto keys only.


git-config values
^^^^^^^^^^^^^^^^^

git splits these into sections in the config file, but flat key-value output can
be produced by ``git config --list`` (add ``--file /path/to/config`` for any
random config path).

* ``nerps.n-e-r-p-s`` - placeholder key to work around `long-standing git-config
  bug with empty sections`_.

* ``nerps.version`` - integer version of configuration, for easy (and hands-off)
  future migrations from older ones when config format changes.

* ``nerps.key.X`` - individual crypto keys, where X is the key name.

* ``nerps.key-default`` - default crypto key **name** (stored as value).

* ``filter.nerps.clean``

  "nerps" filter driver command to "clean" files from local copy before
  comitting them to repository, which in this case means "encrypt".

  See `git-config(1)`_ and `gitattributes(5)`_ for more details on how these work.

* ``filter.nerps.smudge``

  Same as "filter.nerps.clean", but for decryption process when extracting file
  from repository to a local copy.

* ``diff.nerps.textconv``

  Similar to "filter.nerps.smudge", to display "git diff" correctly for
  plaintext instead of encryped blobs.

  See `git-config(1)`_ and `gitattributes(5)`_ for details on
  "diff.<driver>.textconv".

* ``diff.nerps.cachetextconv``

  Related to "diff.nerps.textconv" - enables caching of plaintext for diff
  purposes, which should be fine, as it's only done locally.

.. _long-standing git-config bug with empty sections: http://stackoverflow.com/questions/15935624/how-do-i-avoid-empty-sections-when-removing-a-setting-from-git-config
.. _git-config(1): https://git-scm.com/docs/git-config
.. _gitattributes(5): https://git-scm.com/docs/gitattributes




Crypto details
--------------

* File contents encryption.

  Encryption process in pseudocode::

    file_plaintext = git_input_data
    secretbox_key, version_ascii = git_config_data

    nonce_32b = HMAC(
      key = 'nerps',
      msg = file_plaintext,
      digest = sha256 )

    nonce = nonce_32b[:crypto_secretbox_NONCEBYTES]

    ciphertext = crypto_secretbox(
      key = secretbox_key,
      msg = file_plaintext,
      nonce = nonce )

    magic = '¯\_ʻnerpsʻ_/¯'
    header = magic || ' ' || version_ascii

    git_output_data = header || '\n' || ciphertext

  "crypto_secretbox()" corresponds to `NaCl crypto_secretbox`_ routine (with
  libsodium/PyNaCl/libnacl wrappers), which is a combination of Salsa20 stream
  cipher and and Poly1305 authenticatior in one easy-to-use and secure package,
  implemented and maintained by very smart and skilled people (djb being the
  main author).

  Nonce here is derived from plaintext hash, which should exclude possibility of
  reuse for different plaintexts, yet provide deterministic output for the same
  file.

  Note that key-id is not present in the output data, but since this is
  authenticated encryption, it's still possible to determine which key ciphertext
  should be decrypted with by just trying them all until authentication succeeds.

  "version_ascii" is just "1" or such, encoded in there in case encryption
  algorithm might change in the future.

  Weird unicode stuff in the "header" is an arbitrary magic string to be able to
  easily and kinda-reliably tell if file is encrypted by the presence of that.

* Symmetric encryption key derivation from OpenSSH key.

  Only used when running ``key-gen --from-ssh-key`` subcommand.

  OpenSSH key gets parsed according to openssh format described in PROTOCOL.key
  file (in OpenSSH repo), decrypting it beforehand by running "ssh-keygen -p" to
  a temporary file (with a big warning when that happens, in case it's undesirable),
  if necessary.

  Once raw private key is extracted, it gets processed in the following fashion::

    pbkdf2(
      pseudo_random_func = sha256,
      password = raw_private_key,
      salt = '¯\_ʻnerpsʻ_/¯',
      iterations = 500_000,
      derived_key_len = crypto_secretbox_KEYBYTES )

  I.e. PBKDF2-SHA256 (as implemented in python's hashlib.pbkdf2_hmac) is used
  with static salt (can be overidden via cli option) and 500k rounds (also
  controllable via cli option), result is truncated to crypto_secretbox key
  size.

  Currently only ed25519 keys are supported, but that's mostly because I don't
  see much reason to even allow other (mostly broken) types of keys - "BEGIN
  OPENSSH PRIVATE KEY" format should be roughly same for all types of keys.



Links
-----

(from ~2015 when project was created - make sure to lookup more up-to-date tools)

* `git-crypt project <https://www.agwa.name/projects/git-crypt/>`__

  Similar tool and a first thing I checked before writing this, probably the
  best one around.

  Crypto used there is AES-CTR with OpenSSL.

  Some blog posts and notes on its usage:

  * `Git Crypted <https://flatlinesecurity.com/posts/git-crypted/>`__

  * `Protect secret data in git repo
    <https://coderwall.com/p/kucyaw/protect-secret-data-in-git-repo>`__

  * `Storing sensitive data in a git repository using git-crypt
    <http://www.twinbit.it/en/blog/storing-sensitive-data-git-repository-using-git-crypt>`__

  * `HN comments on the previous post <https://news.ycombinator.com/item?id=7508734>`__

    These do have some useful info and feedback and comments from git-crypt
    author himself, incl. description of some of its internals.

  Decided against using it for variety of reasons - OpenSSL, not AEAD, somewhat
  different use-case and tools for that, C++.


* `git-encrypt <https://github.com/shadowhand/git-encrypt>`__ ("gitcrypt" tool).

  Look at "gitcrypt" bash script for these:

  * ``DEFAULT_CIPHER="aes-256-ecb"``

    AES-ECB is plain insecure (and has been used as a "doing it wrong" example
    for decades!!!), and there's no conceivable reason to ever use it for new
    projects except a total lack of knowledge in the area, malice or maybe a joke.

  * ``openssl enc -base64 -$CIPHER -S "$SALT" -k "$PASS"``

    Yep, and every pid running in the same namespace (i.e. on the system), can
    easily see this "$PASS" (e.g. run "ps" in a loop and you get it).

  Just these two are enough to know where this project stands, but it also has
  lacking and unusable trying-to-be-interactive interface and lot of other issues.

  It's really bad.


* `transcrypt <https://github.com/elasticdog/transcrypt>`__

  More competent "simple bash wrapper" implementation than git-encrypt above,
  but lacking good configuration management cli IMO, e.g.::

    ### Designate a File to be Encrypted

    ...

    $ cd <path-to-your-repo>/
    $ echo 'sensitive_file  filter=crypt diff=crypt' >> .gitattributes
    $ git add .gitattributes sensitive_file
    $ git commit -m 'Add encrypted version of a sensitive file'

  Such manual changes to .gitattributes are exactly the kind of thing I'd rather
  have the tool for, same as "git add" here doesn't require you to edit a few
  configs to include new file there.

  Key management is fairly easy and behind-the-scenes though, and code does
  crypto mostly right, despite all the openssl shortcomings and with some
  caveats (mentioned in the readme there).

  Upside is that it doesn't require python or extra crytpo modules like
  PyNaCl/libnacl - bash and openssl are available everywhere.


* `git-remote-gcrypt <https://github.com/bluss/git-remote-gcrypt>`__

  Designed to do very different thing from git-crypt or this project, which is
  to encrypt whole repository in bulk with gpg (when pushing to remote).

  Probably much better choice than this project for that particular task.


* `ejson <https://github.com/Shopify/ejson>`__,
  `jaeger <https://github.com/jyap808/jaeger>`__ and such.

  There's plenty of "encrypt values in JSON" tools, not really related to git,
  but can be (and generally are) used for secrets in JSON configurations shared
  between different machines/containers.


* `ssh-keyparse <https://github.com/mk-fg/fgtk/#ssh-keyparse>`_ script to
  convert ed25519 ssh keys to short strings (with just 32 bytes in them).


* `gitattributes(5) manpage <https://git-scm.com/docs/gitattributes>`__


* `Some other git filters that I use <https://github.com/mk-fg/fgtk/#dev>`__



TODO
----

* Taints for parts of file(s).

* Change key used for tainted file(s).

  Just re-comitting these should be enough, as old contents will be decrypted
  with the old key and new ones encrypted with new one.

* Command to find all encrypted files in local copy and auto-setup attrs.

* Command to show if stuff is/was/will-be encrypted.

* Address errors from e.g. git-show for commits in different-key branches,
  or maybe just make these look nicer.
