#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import contextmanager
from os.path import join, expanduser, realpath, dirname
import os, sys, re, stat, logging
import tempfile, fcntl, subprocess


class Conf(object):

	key_name_pool = [ # NATO phonetic alphabet
		'dash', 'alfa', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf',
		'hotel', 'india', 'juliett', 'kilo', 'lima', 'mike', 'november', 'oscar',
		'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor',
		'whiskey', 'x-ray', 'yankee', 'zulu' ]

	umask = 0700 # for files where keys are stored

	def __repr__(self): return repr(vars(self))
	def get(self, *k): return getattr(self, '_'.join(k))


class NaCl(object):

	imports = dict(
		exceptions=['CryptoError', 'BadSignatureError'],
		encoding=['RawEncoder', 'URLSafeBase64Encoder'],
		secret=['SecretBox'], hash=['sha256'], utils=['random'] )

	def __init__(self):
		import warnings, importlib
		with warnings.catch_warnings(record=True): # cffi warnings
			for mod, keys in self.imports.viewitems():
				mod = importlib.import_module('nacl.{}'.format(mod))
				for k in keys: setattr(self, k, getattr(mod, k))


@contextmanager
def safe_replacement(path, mode=None):
	if mode is None:
		try: mode = stat.S_IMODE(os.lstat(path).st_mode)
		except (OSError, IOError): pass
	kws = dict( delete=False,
		dir=os.path.dirname(path), prefix=os.path.basename(path)+'.' )
	with tempfile.NamedTemporaryFile(**kws) as tmp:
		try:
			if mode is not None: os.fchmod(tmp.fileno(), mode)
			yield tmp
			if not tmp.closed: tmp.flush()
			os.rename(tmp.name, path)
		finally:
			try: os.unlink(tmp.name)
			except (OSError, IOError): pass

@contextmanager
def edit(path):
	with open(path, 'rb') as src, safe_replacement(path) as tmp:
		yield src, tmp

def with_src_lock(shared=False):
	lock = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
	def _decorator(func):
		@ft.wraps(func)
		def _wrapper(src, *args, **kws):
			fcntl.lockf(src, lock)
			try: return func(src, *args, **kws)
			finally:
				try: fcntl.lockf(src, fcntl.LOCK_UN)
				except (OSError, IOError) as err:
					log.exception('Failed to unlock file object: %s', err)
		return _wrapper
	return _decorator


def key_encode(key):
	return key.encode(nacl.URLSafeBase64Encoder)

def key_decode(key_str, t=None, raw=False):
	enc = nacl.URLSafeBase64Encoder if not raw else nacl.RawEncoder
	return (t or nacl.SecretBox)(key_str, enc)


def dev_null():
	if not hasattr(dev_null, 'cache'):
		dev_null.cache = open(os.devnull, 'wb')
	return dev_null.cache

def git(args=None, check=False, no_stderr=False, trap_code=None):
	kws = dict(close_fds=True)
	if no_stderr: kws['stderr'] = dev_null()
	args = ['git'] + list(args or list())
	if log.isEnabledFor(logging.DEBUG):
		opts = ', '.join( bytes(k) for k, v in
			{'check': check, 'no-stderr': no_stderr, 'trap': trap_code}.items() if v )
		log.debug('git-cmd: %s [%s]', ' '.join(args), opts or '-')
	try: res = subprocess.check_output(args, **kws).splitlines()
	except git.error as err:
		if check: return False
		if trap_code:
			if isinstance(trap_code, (int, long)): trap_code = [trap_code]
			if err.returncode in trap_code: err = res = None
		if err: raise
	return res if not check else True
git.error = subprocess.CalledProcessError

def git_check(args=['rev-parse'], no_stderr=True):
	return git(args, check=True, no_stderr=no_stderr)

def git_dir(*path):
	if not hasattr(git_dir, 'cache'):
		p = git(['rev-parse', '--show-toplevel'])
		assert len(p) == 1, [p, 'rev-cache --show-toplevel result']
		git_dir.cache = join(p[0], '.git')
	if not path: return git_dir.cache
	return join(git_dir.cache, *path)

def git_param(*path):
	assert path and all(path), path
	return 'nerps.{}'.format('.'.join(path))

def git_conf_home():
	if not hasattr(git_conf_home, 'cache'):
		git_conf_home.cache = expanduser(git_conf_home.base)
	return git_conf_home.cache
git_conf_home.base = '~/.git-nerps-keys'

def git_conf():
	if not hasattr(git_conf, 'cache'):
		is_git_repo = git_check()
		git_conf.cache = git_dir('config') if is_git_repo else git_conf_home()
		git_conf_init(git_conf.cache, chmod_dir=is_git_repo)
	return git_conf.cache
git_conf.version = 1

def git_conf_init(gitconfig, chmod_umask=None, chmod_dir=False):
	assert not hasattr(git_conf_init, 'lock')
	conf_id = nacl.sha256(realpath(gitconfig), nacl.URLSafeBase64Encoder)[:8]
	git_conf_init.lock = open(join(
		tempfile.gettempdir(), '.git-nerps.{}.lock'.format(conf_id) ), 'ab+')
	fcntl.lockf(git_conf_init.lock, fcntl.LOCK_EX)

	git_conf_cmd = ['config', '--file', gitconfig]
	ver_k = git_param('version')
	ver = git(git_conf_cmd + ['--get', ver_k], trap_code=1) or None
	if ver: ver = int(ver[0])
	if not ver or ver < git_conf.version:
		if not ver:
			# Placeholder item to work around long-standing bug with removing last value from a section
			# See: http://stackoverflow.com/questions/15935624/\
			#  how-do-i-avoid-empty-sections-when-removing-a-setting-from-git-config
			git(git_conf_cmd + ['--add', git_param('n-e-r-p-s'), 'NERPS'])
		else: git(git_conf_cmd + ['--unset-all', ver_k], trap_code=5)
		# Any future migrations go here
		git(git_conf_cmd + ['--add', ver_k, bytes(git_conf.version)])

	if chmod_umask is None: chmod_umask = conf.umask
	if chmod_dir:
		git_repo_dir = dirname(gitconfig)
		os.chmod(git_repo_dir, os.stat(git_repo_dir).st_mode & chmod_umask)
	os.chmod(gitconfig, os.stat(gitconfig).st_mode & chmod_umask)


def main(args=None, defaults=None):
	import argparse
	parser = argparse.ArgumentParser(description='Tool to manage encrypted files in a git repo.')

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')

	parser.add_argument('-n', '--name',
		help='Key name to use.'
			' Can be important or required for some commands (e.g. "key-set").'
			' For most commands, default key gets'
				' picked either as a first one or the one explicitly set as such.'
			' When generating new key, default is to pick some'
				' unused name from the phonetic alphabet letters.')

	cmds = parser.add_subparsers(
		dest='cmd', title='Actions',
		description='Supported actions (have their own suboptions as well)')


	cmd = 'Generate new encryption key and store or just print it.'
	cmd = cmds.add_parser('key-gen', help=cmd, description=cmd,
		epilog='Default is to store key in a git repository config'
				' (but dont set it as default if there are other ones already),'
				' if inside git repo, otherwise store in the home dir'
				' (also making it default only if there was none before it).'
			' Use "key-set" command to pick default key for git repo, user or file.'
			' System-wide and per-user gitconfig files are never used for key storage,'
				' as these are considered to be a bad place to store anything private.')

	cmd.add_argument('-p', '--print', action='store_true',
		help='Only print the generated key, do not store anywhere.')
	cmd.add_argument('-v', '--verbose', action='store_true',
		help='Print generated key in addition to storing it.')

	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help='Store new key in the {} file (in user home directory).'.format(git_conf_home.base))

	cmd.add_argument('-s', '--set-as-default', action='store_true',
		help='Set generated key as default in whichever config it will be stored.')


	cmd = 'Set default encryption key for a repo/homedir config.'
	cmd = cmds.add_parser('key-set', help=cmd, description=cmd,
		epilog='Same try-repo-then-home config order as with key-gen command.'
			' Key name should be specified with the --name option.'
			' If no --name will be specified and there is no default key set'
				' or it no longer available, first (any) available key will be set as default.')

	cmd.add_argument('name_arg', nargs='?',
		help='Same as using global --name option, but overrides it if both are used.')


	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log, nacl, conf
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()
	nacl = NaCl()
	conf = defaults or Conf()

	# To avoid influence from any of the system-wide aliases
	os.environ['GIT_CONFIG_NOSYSTEM'] = 'true'


	if opts.cmd == 'key-gen':
		key_raw = nacl.random(nacl.SecretBox.KEY_SIZE)
		key = key_decode(key_raw, raw=True)
		key_str = key_encode(key)

		if opts.print or opts.verbose:
			print('Key:\n  ', key_str, '\n')
			if opts.print: return

		gitconfig = git_conf()
		git_conf_cmd = ['config', '--file', gitconfig]

		name = opts.name
		if not name:
			for name in conf.key_name_pool:
				k = git_param('key', name)
				if not git_check(git_conf_cmd + ['--get', k]): break
			else:
				raise parser.error('Failed to find unused'
					' key name, specify one explicitly with --name.')
		k = git_param('key', name)

		log.info('Adding key %r to gitconfig (k: %s): %r', name, k, gitconfig)

		# To avoid flashing key on command line (which can be seen by any
		#  user in same pid ns), "git config --add" is used with unique tmp_token
		#  here, which is then replaced (in the config file) by actual key.

		with open(gitconfig, 'rb') as src: gitconfig_str = src.read()
		while True:
			tmp_token = os.urandom(18).encode('base64').strip()
			if tmp_token not in gitconfig_str: break

		commit = False
		try:
			git(git_conf_cmd + ['--add', k, tmp_token])
			with edit(gitconfig) as (src, tmp):
				gitconfig_str = src.read()
				assert tmp_token in gitconfig_str, tmp_token
				tmp.write(gitconfig_str.replace(tmp_token, key_str))
			commit = True
		finally:
			if not commit: git(git_conf_cmd + ['--unset', k])

		if opts.set_as_default:
			k = git_param('key-default')
			git(git_conf_cmd + ['--unset-all', k], trap_code=5)
			git(git_conf_cmd + ['--add', k, name])


	elif opts.cmd == 'key-set':
		if opts.name_arg: opts.name = opts.name_arg

		gitconfig = git_conf()
		git_conf_cmd = ['config', '--file', gitconfig]
		k_dst = git_param('key-default')

		k = git(git_conf_cmd + ['--get', k_dst])

		if k: # make sure default key is the right one and is available
			k, = k
			k_updated = opts.name and k != opts.name and opts.name
			if k_updated: k = opts.name
			v = git(git_conf_cmd + ['--get', git_param('key', k)])
			if not v and opts.name:
				parser.error('Key %r was not found in config file: %r', k, gitconfig)
			k = None if not v else (k_updated or True) # True - already setup

		if not k: # pick first random key
			key_re = re.compile(r'^{}\.(.*)$'.format(re.escape(git_param('key'))))
			for line in git(git_conf_cmd + ['--list']):
				k, v = line.split('=', 1)
				m = key_re.search(k)
				if not m: continue
				k = m.group(1)
			else: k = None

		if k and k is not True:
			git(git_conf_cmd + ['--unset-all', k_dst], trap_code=5)
			git(git_conf_cmd + ['--add', k_dst, k])


	else: parser.error('Unrecognized command: {}'.format(opts.cmd))


if __name__ == '__main__': sys.exit(main())
