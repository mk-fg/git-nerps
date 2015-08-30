git-nerps
=========

**In early stages of development, not usable yet.**

Tool to encrypt and manage selected files (or parts of files) under git repository.

Uses .gitattributes and git configuration options in general for configuration,
PyNaCl encryption (nacl crypto_box) and python scripts/tools to tie it all together.



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

* Initialize key(s).

* Initialize repository configuration.

  * Specify key or keys.

  * .gitattributes vs .git/info/attributes.

  * Find all encrypted files and auto-setup attrs.

* Add and mark new files to be encrypted.

* Remove taint from files.

* Taint only specific part of a file(s).

* Change key used for a tainted file(s).

* Remove accidentally comitted secret from a repository history.



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
  ("change" will always be "whole file") and especially its attrs mechanism.

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


* Name of the tool literally makes no sense. NERPS.


.. _this letter by Junio C Hamano: http://article.gmane.org/gmane.comp.version-control.git/113221
