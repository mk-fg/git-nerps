git-nerps
=========

Tool to encrypt and manage selected files (or parts of files) under git repository.

Uses PyNaCl encryption (`NaCl crypto_secretbox`_), gitattributes and git-config
for configuration storage, which is partly shared with git and can be
edited/adjusted by hand as well.

All the stuff is implemented as one python (python2!) script, which has
different commands.  See --help output for a full list of these.

.. _NaCl crypto_secretbox: http://nacl.cr.yp.to/secretbox.html


.. contents::
  :backlinks: none



Idea
----

Main purpose of such tool is to make it easy to store configuration that has
some secrets in it within branches of a git repository.

I.e. imagine a bunch of containers which share some/most configs and keep their
configuration in git branches.

You'd like to easily pull, push, merge and cherry-pick between these
repositories/branches, but each container has bits that should not be shared.

One solution is to keep secret files out of repository or in a separate one,
another is to just have these encrypted.
Then these can even be shared between containers that have access to same key,
and not others.

That way, only one short bit of data (key) has to be unique for a host, and
presumably duplicated in some secure place, while the rest of the host's
configuration can be shared or even public.

Modifying .git/config and .gitattributes by hand gets old fast, plus one needs
to store keys and have a dedicated tool/wrapper anyway, hence this project.



Usage
-----

Below I frequently use shorthand "attrs" for git attributes (stored in
.gitattributes or .git/info/attributes files).

I'll also call "to be encrypted" mark on files "taint", because why not have one
word for it?

TODO: fill in stuff below

* Initialize keys and repository configuration.

  * cmd: key-gen
  * cmd: key-set
  * note on key names
  * note on files
  * unlock comitted key with gpg?

  * Specify key or keys.

    * cmd: key-set
    * note on key detection and names

  * .gitattributes vs .git/info/attributes.

  * Find all encrypted files and auto-setup attrs.

* Add and mark new files to be encrypted.

* Remove taint from files.

* Taint only specific part of a file(s).

* Change key used for tainted file(s).

* Remove accidentally comitted secret from a repository history.



Installation
------------

TODO: PyNaCl and ln -s to /usr/local/bin or something



Drawbacks, quirks and warnings
------------------------------


* DO NOT TRUST THIS TOOL TO BE UNIVERSALLY SECURE.

  | I (author) don't use it to store data that is valuable, sensitive
  | or can get me into trouble in any of my public git repositories.
  | Not a single such file on my git server or github.
  | Think about it.

  My use-case is to have shared configuration repositories, to which - if
  everything goes well - there is no unsanctioned acces anyway, ever.

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


* Encryption keys are stored in "repo/.git/config" or "~/.git-nerps-keys".

  It is very important to protect and NOT to loose or share/leak these files.

  Be sure to keep that in mind when copying repository without "git clone" or
  sharing dev copies/environments between users or machines.

  Tool changes modes on "repo/.git" and "repo/.git/config" to make sure there's
  no extra access there. Git should not mess these up, bit it might be worth to
  keep modes on these paths in mind when messing with them.

  Never allow access to "repo/.git" directory over http(s) - alas, fairly common
  security issue, for many different reasons, but here especially so.


* Name of the tool literally makes no sense. NERPS.


.. _this letter by Junio C Hamano: http://article.gmane.org/gmane.comp.version-control.git/113221



Affected files and git-config params
------------------------------------

All files are using git configuration formats - either gitconfig or
gitattributes, more info on which can be found in git-config(1).


Files
`````

* .git/config, $GIT_CONFIG or whatever git-config(1) detects.

* ~/.git-nerps - symlink to the script, to be used in git configs.

* ~/.git-nerps-keys - per-user git-config file for crypto keys only.


git-config values
`````````````````

* nerps.n-e-r-p-s - placeholder key to work around `long-standing git-config bug
  with empty sections`_.

* nerps.version - integer version of configuration, for easy (and hands-off)
  future migrations from older ones when config format changes.

* nerps.key.X - individual crypto keys, where X is the key name.

* nerps.key-default - default crypto key **name** (stored as value).

git splits these into sections inside the file, but flat key-value output can be
produced by ``git config --list`` (add ``--file /path/to/config`` for any random
config path).

.. _long-standing git-config bug with empty sections: http://stackoverflow.com/questions/15935624/how-do-i-avoid-empty-sections-when-removing-a-setting-from-git-config



Encryption details
------------------

Encryption process in pseudocode::

  file_plaintext = git_input_data
  secretbox_key, version_ascii = git_config_data

  nonce_32b = HMAC(
    key = 'nerps',
    msg = file_plaintext,
    digest = sha256 )

  nonce = nonce_32b[:nacl.SecretBox.NONCE_SIZE]

  ciphertext = crypto_secretbox(
    key = secretbox_key,
    msg = plaintext,
    nonce = nonce )

  ciphertext_base64 = base64_encode(ciphertext)

  header = '¯\_ʻnerpsʻ_/¯ ' || version_ascii

  git_output_data = header || '\n\n' || ciphertext_base64

Nonce here is derived from plaintext hash, which should exclude possibility of
reuse for different plaintexts, yet provide deterministic output for the same
file.

Note that no key id is present in the output data, but since this is
authenticated encryption, it is still possible to determine which key ciphertext
should be decrypted with by just trying them all until authentication succeeds.

"version_ascii" is just "1" or such, encoded in there in case encryption
algorithm might change in the future.



Links
-----


* `git-crypt project <https://www.agwa.name/projects/git-crypt/>`__

  | Similar tool and a first thing I checked before writing this.
  | Decided against using it for variety of reasons.

  Crypto used there is AES-CTR with OpenSSL, which is a huge red flag:

  * Every other thing on top of OpenSSL uses it in a very wrong way.

    `This HN comments thread <https://news.ycombinator.com/item?id=7556407>`__
    actually has a comment from git-crypt author (agwa) on top, highlighting the issue:

      I've done quite a bit of programming with the OpenSSL library and this
      article is only scratching the surface of the awfulness. Documentation is
      horrible to non-existent, you really do need to go spelunking into the
      source to figure out how things work, and the code really is that
      horrible.

      The worst thing is that error reporting is not consistent - sometimes -1
      means error, other times 0 means error, other times 0 means success, and
      sometimes it's a combination. This is really, really bad for a crypto
      library since properly detecting errors is usually critical to security.

    See also "OpenSSL is written by monkeys (2009)" parent link there and all
    related criticism and horrible bugs coming out of that crap.

    Willingly using that in a new project given the alternatives (like NaCl)
    seems just bizzare to me.

  * Listing all the issues with internals of OpenSSL is a form of public
    entertainment (see e.g. opensslrampage.org) - it'll always be hilariously
    bad, despite being worked on more lately.

  * Even without OpenSSL, using non-AEAD in 201x is just nonsense.

  * Shows remarkable commitment from author to do things very wrong.

  Doesn't offer proper tools for key and git configuration management that I
  want to have, lots of C++ code, has to be built/packaged.

  See also some blog posts and notes on its usage:

  * `Git Crypted <https://flatlinesecurity.com/posts/git-crypted/>`__

  * `Protect secret data in git repo
    <https://coderwall.com/p/kucyaw/protect-secret-data-in-git-repo>`__

  * `Storing sensitive data in a git repository using git-crypt
    <http://www.twinbit.it/en/blog/storing-sensitive-data-git-repository-using-git-crypt>`__

  * `HN comments on the previous post <https://news.ycombinator.com/item?id=7508734>`__

    These do have some useful info and feedback and comments from git-crypt
    author himself, incl. description of some of its internals.


* `git-encrypt <https://github.com/shadowhand/git-encrypt>`__ ("gitcrypt" tool).

  Look at "gitcrypt" bash script for these:

  * ``DEFAULT_CIPHER="aes-256-ecb"``

    AES-ECB is plain insecure (and has been used as a "doing it wrong" example
    for decades!!!), and there's no conceivable reason to ever use it for new
    projects except a total lack of knowledge in the area.

  * ``openssl enc -base64 -$CIPHER -S "$SALT" -k "$PASS"``

    Yep, and every pid running in the same namespace (i.e. on the system), can
    easily see this "$PASS" (i.e. run "ps" in a loop and you get it).

    See also comments on OpenSSL in git-crypt link above.

  Just these two are enough to know where this project stands, but it also has
  lacking and unusable trying-to-be-interactive interface and lot of other issues.

  It's really bad.


* `transcrypt <https://github.com/elasticdog/transcrypt>`__

  More competent "simple bash wrapper" implementation than git-encrypt above,
  but lacking good configuration management cli, e.g.::

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

  Upside is that it doesn't require python or extra crytpo modules like PyNaCl -
  bash and openssl are available anywhere.


* `git-remote-gcrypt <https://github.com/bluss/git-remote-gcrypt>`__

  Designed to do very different thing from git-crypt or this project, which is
  to encrypt whole repository in bulk with gpg (when pushing to remote).

  Probably much better choice than this project for that particular task.


* `ejson <https://github.com/Shopify/ejson>`__,
  `jaeger <https://github.com/jyap808/jaeger>`__ and such.

  There's plenty of "encrypt values in JSON" tools, not really related to git,
  but can be (and generally are) used for secrets in JSON configurations shared
  between different machines/containers.


* `gitattributes(5) manpage <https://git-scm.com/docs/gitattributes>`__


* `Some other git filters that I use <https://github.com/mk-fg/fgtk/#dev>`__
