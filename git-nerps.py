#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import contextmanager
from os.path import ( join, expanduser, isdir, basename,
	realpath, dirname, abspath, exists, samefile, normpath )
import os, sys, io, re, types, logging
import stat, tempfile, fcntl, subprocess
import hmac, hashlib


class Conf(object):

	key_name_pool = [ # NATO phonetic alphabet
		'alfa', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf',
		'hotel', 'india', 'juliett', 'kilo', 'lima', 'mike', 'november', 'oscar',
		'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor',
		'whiskey', 'x-ray', 'yankee', 'zulu' ]

	umask = 0700 # for files where keys are stored

	script_link = '~/.git-nerps'
	git_conf_home = '~/.git-nerps-keys'
	git_conf_version = 1

	enc_magic = '¯\_ʻnerpsʻ_/¯'
	nonce_key = enc_magic
	pbkdf2_salt = enc_magic
	pbkdf2_rounds = int(5e5)

	def nonce_func(self, plaintext):
		raw = hmac.new(self.nonce_key, plaintext, hashlib.sha256).digest()
		return raw[:self.nacl.SecretBox.NONCE_SIZE]

	def __init__(self, nacl): self.nacl = nacl
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

	def key_encode(self, key):
		return key.encode(self.URLSafeBase64Encoder).strip()

	def key_decode(self, key_str, t=None, raw=False):
		enc = self.URLSafeBase64Encoder if not raw else self.RawEncoder
		return (t or self.SecretBox)(key_str, enc)


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
		except CancelFileReplacement: pass
		finally:
			try: os.unlink(tmp.name)
			except (OSError, IOError): pass

class CancelFileReplacement(Exception): pass
safe_replacement.cancel = CancelFileReplacement

@contextmanager
def edit(path):
	with safe_replacement(path) as tmp:
		if not exists(path): yield None, tmp
		else:
			with open(path, 'rb') as src: yield src, tmp

edit.cancel = CancelFileReplacement

def dev_null():
	if not hasattr(dev_null, 'cache'):
		dev_null.cache = open(os.devnull, 'wb+')
	return dev_null.cache

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

def relpath(path, from_path):
	path, from_path = it.imap(abspath, (path, from_path))
	if isdir(from_path): from_path += os.sep
	from_path = dirname(from_path)
	path, from_path = it.imap(lambda x: x.split(os.sep), (path, from_path))
	for i in xrange(min(len(from_path), len(path))):
		if from_path[i] != path[i]: break
		else: i +=1
	return join(*([os.pardir] * (len(from_path)-i) + path[i:]))

def path_escape(path):
	assert path.strip() == path, repr(path) # trailing spaces should be escaped
	for c in '#!':
		if path.startswith(c): path = r'\{}{}'.format(c, path[1:])
	return path.replace('*', r'\*')

def filter_git_patterns(src, tmp, path_rel, _ree=re.escape):
	if not src: src = io.BytesIO()
	for n, line in enumerate(iter(src.readline, ''), 1):
		ls = line.strip()
		assert not ls.endswith('\\'), repr(line) # not handling these escapes
		if ls and not ls.startswith('#'):
			pat, filters = ls.split(None, 1)
			pat_re = _ree(pat.lstrip('/')).replace(_ree('**'), r'(.+)').replace(_ree('*'), r'([^\/]+)')
			if '/' in pat: pat_re = '^{}'.format(pat_re)
			if re.search(pat_re, path_rel):
				act = yield n, line, pat, filters
		if not act: tmp.write('{}\n'.format(line.rstrip()))
		elif isinstance(act, bytes): tmp.write('{}\n'.format(act.rstrip()))
		elif act is filter_git_patterns.remove: pass
		else: raise ValueError(act)

filter_git_patterns.remove = object()

def cached_result(key_or_func=None, _key=None):
	if callable(key_or_func):
		_key = _key or key_or_func.func_name
		@ft.wraps(key_or_func)
		def _wrapper(self, *args, **kws):
			if _key not in self.c:
				self.c[_key] = key_or_func(self, *args, **kws)
			return self.c[_key]
		return _wrapper
	return ft.partial(cached_result, _key=key_or_func)


class GitWrapperError(Exception): pass

class GitWrapper(object):

	def __init__(self, conf, nacl):
		self.conf, self.nacl, self.c, self.lock = conf, nacl, dict(), None
		self.log = logging.getLogger('git')

	def __enter__(self):
		self.init()
		return self
	def __exit__(self, *err): self.destroy()
	def __del__(self): self.destroy()


	def init(self): pass # done lazily

	def init_lock(self, gitconfig):
		if self.lock: return
		lock = self.nacl.sha256(realpath(gitconfig), self.nacl.URLSafeBase64Encoder)[:8]
		lock = join(tempfile.gettempdir(), '.git-nerps.{}.lock'.format(lock))
		self.lock = open(lock, 'ab+')
		self.log.debug('Acquiring lock: %r', lock)
		fcntl.lockf(self.lock, fcntl.LOCK_EX)

	def destroy(self):
		if self.lock:
			self.log.debug('Releasing lock: %r', self.lock.name)
			self.lock.close()
			self.lock = None


	@property
	def dev_null(self): return dev_null()

	run_error = subprocess.CalledProcessError

	def run(self, args=None, check=False, no_stderr=False, trap_code=None):
		kws = dict(close_fds=True)
		if no_stderr: kws['stderr'] = self.dev_null
		args = ['git'] + list(args or list())
		if self.log.isEnabledFor(logging.DEBUG):
			opts = ', '.join( bytes(k) for k, v in
				{'check': check, 'no-stderr': no_stderr, 'trap': trap_code}.items() if v )
			self.log.debug('run: %s [%s]', ' '.join(args), opts or '-')
		try: res = subprocess.check_output(args, **kws).splitlines()
		except self.run_error as err:
			if check: return False
			if trap_code:
				if trap_code is True: pass
				elif isinstance(trap_code, (int, long)): trap_code = [trap_code]
				if trap_code is True or err.returncode in trap_code: err = res = None
			if err: raise
		return res if not check else True

	def check(self, args=['rev-parse'], no_stderr=True):
		return self.run(args, check=True, no_stderr=no_stderr)

	def run_conf(self, args, gitconfig=None, **run_kws):
		gitconfig = gitconfig or self.path_conf
		return self.run(['config', '--file', gitconfig] + args, **run_kws)

	def sub(self, *path):
		if not self.c.get('git-dir'):
			p = self.run(['rev-parse', '--show-toplevel'])
			assert len(p) == 1, [p, 'rev-cache --show-toplevel result']
			self.c['git-dir'] = join(p[0], '.git')
		if not path: return self.c['git-dir']
		return join(self.c['git-dir'], *path)

	def param(self, *path):
		assert path and all(path), path
		return 'nerps.{}'.format('.'.join(path))

	@property
	def force_conf_home(self):
		return self.c.get('force-conf-home')
	@force_conf_home.setter
	def force_conf_home(self, v):
		assert not (self.c.get('path_conf') or self.lock)
		self.c['force-conf-home'] = v

	@property
	@cached_result
	def path_conf_home(self):
		return expanduser(self.conf.git_conf_home)

	@property
	@cached_result
	def path_conf(self):
		is_git_repo = not self.force_conf_home and self.check()
		gitconfig = self.sub('config') if is_git_repo else self.path_conf_home
		self.path_conf_init(gitconfig, chmod_dir=is_git_repo)
		return gitconfig

	def path_conf_init(self, gitconfig=None, chmod_umask=None, chmod_dir=False):
		assert not self.lock
		if not gitconfig:
			assert self.check()
			gitconfig = self.c['path_conf'] = self.sub('config')
			chmod_dir = True
		self.init_lock(gitconfig)

		run_conf = ft.partial(self.run_conf, gitconfig=gitconfig)
		ver_k = self.param('version')
		ver = run_conf(['--get', ver_k], trap_code=1) or None
		if ver: ver = int(ver[0])
		if not ver or ver < self.conf.git_conf_version:

			if not ver:
				if not os.access(__file__, os.X_OK):
					self.log.warn( 'This script (%r) must be executable'
						' (e.g. run "chmod +x" on it) for git filters to work!' )
				script_link_abs = expanduser(self.conf.script_link)
				if not exists(script_link_abs) or not samefile(script_link_abs, __file__):
					try: os.unlink(script_link_abs)
					except (OSError, IOError): pass
					os.symlink(abspath(__file__), script_link_abs)

				run_conf(['--remove-section', 'filter.nerps'], trap_code=True, no_stderr=True)
				run_conf(['--remove-section', 'diff.nerps'], trap_code=True, no_stderr=True)

				script_cmd = ft.partial('{} {}'.format, self.conf.script_link)
				run_conf(['--add', 'filter.nerps.clean', script_cmd('git-clean')])
				run_conf(['--add', 'filter.nerps.smudge', script_cmd('git-smudge')])
				run_conf(['--add', 'diff.nerps.textconv', script_cmd('git-diff')])

				# See "Performing text diffs of binary files" in gitattributes(5)
				run_conf([ '--add', 'diff.nerps.cachetextconv', 'true'])

				# Placeholder item to work around long-standing bug with removing last value from a section
				# See: http://stackoverflow.com/questions/15935624/\
				#  how-do-i-avoid-empty-sections-when-removing-a-setting-from-git-config
				run_conf(['--add', self.param('n-e-r-p-s'), 'NERPS'])

			else: run_conf(['--unset-all', ver_k], trap_code=5)
			# Any future migrations go here
			run_conf(['--add', ver_k, bytes(self.conf.git_conf_version)])

		if chmod_umask is None: chmod_umask = self.conf.umask
		if chmod_dir:
			git_repo_dir = dirname(gitconfig)
			os.chmod(git_repo_dir, os.stat(git_repo_dir).st_mode & chmod_umask)
		os.chmod(gitconfig, os.stat(gitconfig).st_mode & chmod_umask)


	def _key_iter(self):
		key_re = re.compile(r'^{}\.(.*)$'.format(re.escape(self.param('key'))))
		for gitconfig in self.sub('config'), self.path_conf_home:
			for line in self.run_conf(['--list'], gitconfig):
				k, v = line.split('=', 1)
				m = key_re.search(k)
				if not m: continue
				yield gitconfig, m.group(1), v.strip()

	@property
	@cached_result
	def key_name_default(self):
		for gitconfig in self.sub('config'), self.path_conf_home:
			name = self.run_conf(['--get', self.param('key-default')], gitconfig, trap_code=1)
			if name:
				name, = name
				break
		else: name = self.key_name_any
		return name

	@property
	@cached_result
	def key_name_any(self):
		try: gitconfig, k, v = next(self._key_iter())
		except StopIteration: return
		return k

	@property
	@cached_result
	def key_all(self):
		keys = list()
		for gitconfig, name, key in self._key_iter():
			key = self.nacl.key_decode(key)
			key.gitconfig, key.name = gitconfig, name
			keys.append(key)
		return keys

	def key(self, name=None):
		name = name or self.key_name_default
		if not name:
			raise GitWrapperError('No keys found in config: {!r}'.format(self.path_conf))
		for key in reversed(self.key_all):
			if key.name == name: break
		else:
			raise GitWrapperError(( 'Key {!r} is set as default'
				' but is unavailable (in config: {!r})' ).format(name, self.path_conf))
		self.log.debug('Using key: %s', name)
		return key


class SSHKeyError(Exception): pass

def ssh_key_hash(conf, nacl, path):
	# See PROTOCOL.key and sshkey.c in openssh sources
	import struct
	log = logging.getLogger('ssh-key-hash')

	with tempfile.NamedTemporaryFile(
			delete=True, dir=dirname(path), prefix=basename(path)+'.' ) as tmp:
		tmp.write(open(path).read())
		tmp.flush()
		with tempfile.TemporaryFile() as stderr:
			cmd = ['ssh-keygen', '-p', '-P', '', '-N', '', '-f', tmp.name]
			p = subprocess.Popen( cmd, stdin=dev_null(),
				stdout=subprocess.PIPE, stderr=stderr, close_fds=True )
			stdout = p.stdout.read().splitlines()
			err = p.wait()
			stderr.seek(0)
			stderr = stderr.read().splitlines()

		if err:
			if stdout: sys.stderr.write('\n'.join(stdout + ['']))
			key_enc = False
			for line in stderr:
				if re.search( r'^Failed to load key .*:'
						r' incorrect passphrase supplied to decrypt private key$', line ):
					key_enc = True
				else: sys.stderr.write('{}\n'.format(line))
			if key_enc:
				print('WARNING:')
				print( 'WARNING: !!! ssh key will be decrypted'
					' (via ssh-keygen) to a temporary file {!r} in the next step !!!'.format(tmp.name) )
				print('WARNING: DO NOT enter key passphrase'
					' and ABORT operation (^C) if that is undesirable.')
				print('WARNING:')
				cmd = ['ssh-keygen', '-p', '-N', '', '-f', tmp.name]
				log.debug('Running interactive ssh-keygen to decrypt key: %s', ' '.join(cmd))
				err, stdout = None, subprocess.check_output(cmd, close_fds=True)

		if err or 'Your identification has been saved with the new passphrase.' not in stdout:
			for lines in stdout, stderr: sys.stderr.write('\n'.join(lines + ['']))
			raise SSHKeyError(( 'ssh-keygen failed to process key {!r},'
				' see stderr output above for details, command: {}' ).format(path, ' '.join(cmd)))

		tmp.seek(0)
		lines, key, done = tmp.read().splitlines(), list(), False
		for line in lines:
			if line == '-----END OPENSSH PRIVATE KEY-----': done = True
			if key and not done: key.append(line)
			if line == '-----BEGIN OPENSSH PRIVATE KEY-----':
				if done:
					raise SSHKeyError( 'More than one private'
						' key detected in file, aborting: {!r}'.format(path) )
				assert not key
				key.append('')
		if not done: raise SSHKeyError('Incomplete or missing key in file: {!r}'.format(path))
		key_str = ''.join(key).decode('base64')
		key = io.BytesIO(key_str)

		def key_read_str(src=None):
			if src is None: src = key
			n, = struct.unpack('>I', src.read(4))
			return src.read(n)

		def key_assert(chk, err, *fmt_args, **fmt_kws):
			if fmt_args or fmt_kws: err = err.format(*fmt_args, **fmt_kws)
			err += ' [key file: {!r}, decoded: {!r}]'.format(path, key_str)
			if not chk: raise SSHKeyError(err)

		def key_assert_read(field, val, fixed=False):
			pos, chk = key.tell(), key.read(len(val)) if fixed else key_read_str()
			key_assert( chk == val, 'Failed to match key field'
				' {!r} (offset: {}) - expected {!r} got {!r}', field, pos, val, chk )

		key_assert_read('AUTH_MAGIC', 'openssh-key-v1\0', True)
		key_assert_read('ciphername', 'none')
		key_assert_read('kdfname', 'none')
		key_assert_read('kdfoptions', '')
		(pubkey_count,), pubkeys = struct.unpack('>I', key.read(4)), list()
		for n in xrange(pubkey_count):
			line = key_read_str()
			key_assert(line, 'Empty public key #{}', n)
			line = io.BytesIO(line)
			key_t = key_read_str(line)
			key_assert(key_t == 'ssh-ed25519', 'Unsupported pubkey type: {!r}', key_t)
			ed2519_pk = key_read_str(line)
			line = line.read()
			key_assert(not line, 'Garbage data after pubkey: {!r}', line)
			pubkeys.append(ed2519_pk)
		privkey = io.BytesIO(key_read_str())
		pos, tail = key.tell(), key.read()
		key_assert( not tail,
			'Garbage data after private key (offset: {}): {!r}', pos, tail )

		key = privkey
		n1, n2 = struct.unpack('>II', key.read(8))
		key_assert(n1 == n2, 'checkint values mismatch in private key spec: {!r} != {!r}', n1, n2)
		key_t = key_read_str()
		key_assert(key_t == 'ssh-ed25519', 'Unsupported key type: {!r}', key_t)
		ed2519_pk = key_read_str()
		key_assert(ed2519_pk in pubkeys, 'Pubkey mismatch - {!r} not in {}', ed2519_pk, pubkeys)
		ed2519_sk = key_read_str()
		key_assert(
			len(ed2519_pk) == 32 and len(ed2519_sk) == 64,
			'Key length mismatch: {}/{} != 32/64', len(ed2519_pk), len(ed2519_sk) )
		comment = key_read_str()
		padding = key.read()
		padding, padding_chk = list(bytearray(padding)), range(1, len(padding) + 1)
		key_assert(padding == padding_chk, 'Invalid padding: {} != {}', padding, padding_chk)
		log.debug('Parsed %s key, comment: %r', key_t, comment)

	return hashlib.pbkdf2_hmac( 'sha256', ed2519_sk,
		conf.pbkdf2_salt, conf.pbkdf2_rounds, nacl.SecretBox.KEY_SIZE )


def is_encrypted(conf, src_or_line, rewind=True):
	if not isinstance(src_or_line, types.StringTypes):
		pos = src_or_line.tell()
		line = src_or_line.readline()
		src_or_line.seek(pos)
		src_or_line = line
	nerps = src_or_line.strip().split(None, 1)
	return nerps and nerps[0] == conf.enc_magic

def encrypt(conf, nacl, git, log, name, src=None, dst=None):
	key = git.key(name)
	plaintext = src.read()
	nonce = conf.nonce_func(plaintext)
	ciphertext = key.encrypt(plaintext, nonce)
	dst_stream = io.BytesIO() if not dst else dst
	dst_stream.write('{} {}\n'.format(conf.enc_magic, conf.git_conf_version))
	dst_stream.write(ciphertext)
	if not dst: return dst_stream.getvalue()

def decrypt(conf, nacl, git, log, name, src=None, dst=None, strict=False):
	key = git.key(name)
	header = src.readline()
	nerps, ver = header.strip().split(None, 2)[:2]
	assert nerps == conf.enc_magic, nerps
	assert int(ver) <= conf.git_conf_version, ver
	ciphertext = src.read()
	try: plaintext = key.decrypt(ciphertext)
	except nacl.CryptoError:
		if strict: raise
		err_t, err, err_tb = sys.exc_info()
		log.debug( 'Failed to decrypt with %s key %r: %s',
			'default' if not name else 'specified', key.name, err )
		for key_chk in git.key_all:
			if key_chk.name == key.name: continue
			log.debug('Trying key: %s', key_chk.name)
			try: plaintext = key_chk.decrypt(ciphertext)
			except nacl.CryptoError: pass
			else: break
		else: raise err_t, err, err_tb
	if dst: dst.write(plaintext)
	else: return plaintext



def run_command(opts, conf, nacl, git):
	log = logging.getLogger(opts.cmd)
	exit_code = 0


	##########
	if opts.cmd == 'init':
		if not git.check(): opts.parser.error('Can only be run inside git repository')
		git.path_conf_init()


	##########
	elif opts.cmd == 'key-gen':
		if opts.from_ssh_key is False:
			key_raw = nacl.random(nacl.SecretBox.KEY_SIZE)
		else:
			key_path = opts.from_ssh_key
			if not key_path or key_path in ['ed25519']:
				key_path = list(
					expanduser('~/.ssh/id_{}'.format(p))
					for p in ([key_path] if key_path else ['ed25519']) )
				key_path = filter(exists, key_path)
				if len(key_path) != 1:
					opts.parser.error(( 'Key spec must match exactly'
						' one key path, matched: {}' ).format(', '.join(key_path)))
				key_path, = key_path
			if opts.from_ssh_key_pbkdf2_params:
				rounds, salt = opts.from_ssh_key_pbkdf2_params.split('/', 1)
				conf.pbkdf2_rounds, conf.pbkdf2_salt = int(rounds), salt
			key_raw = ssh_key_hash(conf, nacl, key_path)
		key = nacl.key_decode(key_raw, raw=True)
		key_str = nacl.key_encode(key)

		if opts.print:
			print('Key:\n  ', key_str, '\n')
			return

		if opts.name_arg: opts.name = opts.name_arg
		if opts.homedir:
			git.force_conf_home = True
		elif opts.git and not git.check():
			opts.parser.error('Not in a git repository and --git option was specified.')

		gitconfig = git.path_conf
		run_conf = ft.partial(git.run_conf, gitconfig=gitconfig)

		name = opts.name
		if not name:
			for name in conf.key_name_pool:
				k = git.param('key', name)
				if not run_conf(['--get', k], check=True, no_stderr=True): break
			else:
				raise opts.parser.error('Failed to find unused'
					' key name, specify one explicitly with --name.')
		k = git.param('key', name)

		log.info('Adding key %r to gitconfig (k: %s): %r', name, k, gitconfig)
		if opts.verbose: print('Generated new key {!r}:\n  {}\n'.format(name, key_str))

		# To avoid flashing key on command line (which can be seen by any
		#  user in same pid ns), "git config --add" is used with unique tmp_token
		#  here, which is then replaced (in the config file) by actual key.

		with open(gitconfig, 'rb') as src: gitconfig_str = src.read()
		while True:
			tmp_token = os.urandom(18).encode('base64').strip()
			if tmp_token not in gitconfig_str: break

		commit = False
		try:
			run_conf(['--add', k, tmp_token])
			with edit(gitconfig) as (src, tmp):
				gitconfig_str = src.read()
				assert tmp_token in gitconfig_str, tmp_token
				tmp.write(gitconfig_str.replace(tmp_token, key_str))
			commit = True
		finally:
			if not commit: run_conf(['--unset', k])

		if opts.set_as_default:
			k = git.param('key-default')
			run_conf(['--unset-all', k], trap_code=5)
			run_conf(['--add', k, name])


	##########
	elif opts.cmd == 'key-set':
		if opts.name_arg: opts.name = opts.name_arg
		if opts.homedir:
			git.force_conf_home = True
		elif opts.git and not git.check():
			opts.parser.error('Not in a git repository and --git option was specified.')

		k_dst = git.param('key-default')
		k = git.run_conf(['--get', k_dst], trap_code=1)

		if k: # make sure default key is the right one and is available
			k, = k
			k_updated = opts.name and k != opts.name and opts.name
			if k_updated: k = opts.name
			v = git.run_conf(['--get', git.param('key', k)])
			if not v and opts.name:
				opts.parser.error('Key %r was not found in config file: %r', k, git.path_conf)
			k = None if not v else (k_updated or True) # True - already setup

		if not k: k = git.key_name_any # pick first random key

		if k and k is not True:
			git.run_conf(['--unset-all', k_dst], trap_code=5)
			git.run_conf(['--add', k_dst, k])


	##########
	elif opts.cmd == 'key-unset':
		if opts.homedir:
			git.force_conf_home = True
		elif opts.git and not git.check():
			opts.parser.error('Not in a git repository and --git option was specified.')
		git.run_conf(['--unset-all', git.param('key-default')], trap_code=5)


	##########
	elif opts.cmd == 'key-list':
		if opts.homedir:
			git.force_conf_home = True
		elif opts.git and not git.check():
			opts.parser.error('Not in a git repository and --git option was specified.')
		key_names = map(op.attrgetter('name'), git.key_all)
		for n_def, name in reversed(list(enumerate(key_names))):
			if name == git.key_name_default: break
		for n, name in enumerate(key_names):
			print('{}{}'.format(name, ' [default]' if n == n_def else ''))


	##########
	elif opts.cmd == 'git-clean':
		src = io.BytesIO(sys.stdin.read())
		if is_encrypted(conf, src):
			log.error( '(Supposedly) plaintext file contents'
				' seem to be already encrypted, refusing to encrypt: %r', opts.path)
			return 1
		encrypt(conf, nacl, git, log, opts.name, src=src, dst=sys.stdout)
		sys.stdout.close() # to make sure no garbage data will end up there

	##########
	elif opts.cmd in ['git-smudge', 'git-diff']:
		if opts.cmd == 'git-diff': src = open(opts.path, 'rb')
		else: src = io.BytesIO(sys.stdin.read())
		try:
			if not is_encrypted(conf, src):
				if opts.cmd != 'git-diff':
					# XXX: filter history or at least detect whether that's the case
					log.warn( '%s - file seem to be unencrypted in the repo'
						' (ignore this error when marking files with history): %r', opts.cmd, opts.path )
				sys.stdout.write(src.read())
			else:
				decrypt( conf, nacl, git, log, opts.name,
					src=src, dst=sys.stdout, strict=opts.name_strict )
			sys.stdout.close() # to make sure no garbage data will end up there
		finally: src.close()


	##########
	elif opts.cmd == 'encrypt':
		if opts.path:
			with edit(opts.path) as (src, tmp):
				if not opts.force and is_encrypted(conf, src): raise edit.cancel
				encrypt(conf, nacl, git, log, opts.name, src=src, dst=tmp)
		else: encrypt(conf, nacl, git, log, opts.name, src=sys.stdin, dst=sys.stdout)

	##########
	elif opts.cmd == 'decrypt':
		if opts.path:
			with edit(opts.path) as (src, tmp):
				if not opts.force and not is_encrypted(conf, src): raise edit.cancel
				decrypt( conf, nacl, git, log, opts.name,
					src=src, dst=tmp, strict=opts.name_strict )
		else:
			decrypt( conf, nacl, git, log, opts.name,
				src=sys.stdin, dst=sys.stdout, strict=opts.name_strict )


	##########
	elif opts.cmd in ('taint', 'clear'):
		if not git.check(): opts.parser.error('Can only be run inside git repository')

		for path in opts.path:
			path_rel = relpath(path, git.sub('..'))
			assert not re.search(r'^(\.|/)', path_rel), path_rel
			attrs_file = normpath(git.sub(
				'../.gitattributes' if not opts.local_only else 'info/attributes' ))

			with edit(attrs_file) as (src, tmp):
				n, matches_mark, matches = None, dict(), filter_git_patterns(src, tmp, path_rel)
				while True:
					try: n, line, pat, filters = next(matches) if n is None else matches.send(act)
					except StopIteration: break
					act = None
					if opts.cmd == 'taint':
						if not opts.force:
							if not opts.silent:
								log.error( 'gitattributes (%r) already has matching'
									' pattern for path %r, not adding another one (line %s): %r',
									attrs_file, path_rel, n, line )
								# XXX: check if that line also has matching filter, add one
								exit_code = 1
							raise edit.cancel
					if opts.cmd == 'clear':
						# XXX: check if line has actually **matching** filter
						matches_mark[n] = line

				if opts.cmd == 'taint':
					tmp.write('/{} filter=nerps diff=nerps\n'.format(path_escape(path_rel)))

				if opts.cmd == 'clear':
					if not matches_mark:
						if not opts.silent:
							log.error( 'gitattributes (%r) pattern'
								' for path %r was not found', attrs_file, path_rel )
							exit_code = 1
						raise edit.cancel
					if not opts.force and len(matches_mark) > 1:
						log.error( 'More than one gitattributes (%r) pattern was'
							' found for path %r, aborting: %r', attrs_file, path_rel, matches_mark.values() )
						exit_code = 1
						raise edit.cancel
					src.seek(0)
					tmp.seek(0)
					tmp.truncate()
					for n, line in enumerate(iter(src.readline, ''), 1):
						if n not in matches_mark: tmp.write(line)

		# Make sure git detects tainted files as "changed"
		# XXX: there's probably some command to reset hashes in index
		renames, success = list(), False
		try:
			for path in opts.path:
				with tempfile.NamedTemporaryFile(delete=False,
						dir=dirname(path), prefix=basename(path)+'.') as tmp:
					os.rename(path, tmp.name)
					renames.append((tmp.name, path))
			git.run(['status'])
			success = True
		finally:
			for src, dst in reversed(renames):
				try: os.rename(src, dst)
				except:
					log.exception( 'Failed to restore original'
						' name for path: %r (tmp-name: %r)', dst, src )
		if success: git.run(['status'])



	else: opts.parser.error('Unrecognized command: {}'.format(opts.cmd))
	return exit_code


def main(args=None, defaults=None):
	nacl, args = NaCl(), sys.argv[1:] if args is None else args
	conf = defaults or Conf(nacl)

	import argparse
	parser = argparse.ArgumentParser(description='Tool to manage encrypted files in a git repo.')

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')

	parser.add_argument('-n', '--name', metavar='key-name',
		help='Key name to use.'
			' Can be important or required for some commands (e.g. "key-set").'
			' For most commands, default key gets'
				' picked either as a first one or the one explicitly set as such.'
			' When generating new key, default is to pick some'
				' unused name from the phonetic alphabet letters.')

	parser.add_argument('-s', '--name-strict', action='store_true',
		help='Only try specified or default key for decryption.'
			' Default it to try other ones if that one fails, to see if any of them work for a file.')

	cmds = parser.add_subparsers(
		dest='cmd', title='Actions',
		description='Supported actions (have their own suboptions as well)')


	cmd = 'Initialize repository configuration.'
	cmd = cmds.add_parser('init', help=cmd, description=cmd,
		epilog='Will be done automatically on any'
			' other action (e.g. "key-gen"), so can usually be skipped.')


	cmd = 'Generate new encryption key and store or just print it.'
	cmd = cmds.add_parser('key-gen', help=cmd, description=cmd,
		epilog='Default is to store key in a git repository config'
				' (but dont set it as default if there are other ones already),'
				' if inside git repo, otherwise store in the home dir'
				' (also making it default only if there was none before it).'
			' Use "key-set" command to pick default key for git repo, user or file.'
			' System-wide and per-user gitconfig files are never used for key storage,'
				' as these are considered to be a bad place to store anything private.')
	cmd.add_argument('name_arg', nargs='?',
		help='Same as using global --name option, but overrides it if both are used.')

	cmd.add_argument('-p', '--print', action='store_true',
		help='Only print the generated key, do not store anywhere.')
	cmd.add_argument('-v', '--verbose', action='store_true',
		help='Print generated key in addition to storing it.')

	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help='Store new key in the {} file (in user home directory).'.format(conf.git_conf_home))

	cmd.add_argument('-k', '--from-ssh-key',
		nargs='?', metavar='ed25519 | path', default=False,
		help='Derive key from openssh private key'
				' using PBKDF2-SHA256 with static salt (by default,'
				' see --from-ssh-key-pbkdf2-params).'
			' If key is encrypted, error will be raised'
				' (use "ssh-keygen -p" to provide non-encrypted version).'
			' Optional argument can specify type of the key'
				' (only ed25519 is supported though)'
				' to pick from default location (i.e. ~/.ssh/id_*) or path to the key.'
			' If optional arg is not specified, any default key will be picked,'
				' but only if there is exactly one, otherwise error will be raised.')
	cmd.add_argument('--from-ssh-key-pbkdf2-params', metavar='rounds/salt',
		help='Number of PBKDF2 rounds and salt to use for --from-ssh-key derivation.'
			' It is probably a good idea to not use any valuable secret'
				' as "salt", especially when specifying it on the command line.'
			' Defaults are: {}/{}'.format(conf.pbkdf2_rounds, conf.pbkdf2_salt))

	cmd.add_argument('-s', '--set-as-default', action='store_true',
		help='Set generated key as default in whichever config it will be stored.')

	# XXX: option to generate from ssh private key


	cmd = 'Set default encryption key for a repo/homedir config.'
	cmd = cmds.add_parser('key-set', help=cmd, description=cmd,
		epilog='Same try-repo-then-home config order as with key-gen command.'
			' Key name should be specified with the --name option.'
			' If no --name will be specified and there is no default key set'
				' or it no longer available, first (any) available key will be set as default.')
	cmd.add_argument('name_arg', nargs='?',
		help='Same as using global --name option, but overrides it if both are used.')
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help='Store new key in the {} file (in user home directory).'.format(conf.git_conf_home))


	cmd = 'Unset default encryption key for a repo/homedir config.'
	cmd = cmds.add_parser('key-unset', help=cmd, description=cmd)
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help='Store new key in the {} file (in user home directory).'.format(conf.git_conf_home))


	cmd = 'List available crypto keys.'
	cmd = cmds.add_parser('key-list', help=cmd, description=cmd)
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help='Store new key in the {} file (in user home directory).'.format(conf.git_conf_home))


	cmd = 'Encrypt file in-place or process stdin to stdout.'
	cmd = cmds.add_parser('encrypt', help=cmd, description=cmd)
	cmd.add_argument('path', nargs='?', help='Path to a file to encrypt.'
		' If not specified, stdin/stdout streams will be used instead.')
	cmd.add_argument('-f', '--force', action='store_true',
		help='Encrypt even if file appears to be encrypted already.')

	cmd = 'Decrypt file in-place or process stdin to stdout.'
	cmd = cmds.add_parser('decrypt', help=cmd, description=cmd)
	cmd.add_argument('path', nargs='?', help='Path to a file to decrypt.'
		' If not specified, stdin/stdout streams will be used instead.')
	cmd.add_argument('-f', '--force', action='store_true',
		help='Decrypt even if file does not appear to be encrypted.')


	cmd = 'Mark file(s) to be transparently encrypted in the current git repo.'
	cmd = cmds.add_parser('taint', help=cmd, description=cmd,
		epilog='Adds files to .gitattributes (default)'
				' or .git/info/attributes (see --local-only option).')

	cmd.add_argument('path', nargs='+', help='Path of a file to mark.')

	cmd.add_argument('-f', '--force', action='store_true',
		help='Add pattern to gitattributes even if'
			' there are matching ones already, skip extra checks.')
	cmd.add_argument('-s', '--silent', action='store_true',
		help='Do not print any errors if file is already marked.')

	cmd.add_argument('-l', '--local-only', action='store_true',
		help='Add file to .git/info/attributes (which'
			' does not usually get shared) instead of .gitattributes.')


	cmd = 'Remove transparent encryption mark from a file(s).'
	cmd = cmds.add_parser('clear', help=cmd, description=cmd,
		epilog='Removes file(s) from .gitattributes (default)'
				' or .git/info/attributes (see --local-only option).')

	cmd.add_argument('path', nargs='+', help='Path of a file to unmark.')

	cmd.add_argument('-f', '--force', action='store_true',
		help='Remove any number of any matching patterns from gitattributes, skip extra checks.')
	cmd.add_argument('-s', '--silent', action='store_true',
		help='Do not print any errors if file does not seem to be marked.')

	cmd.add_argument('-l', '--local-only', action='store_true',
		help='Remove pattern from .git/info/attributes (which'
			' does not usually get shared) instead of .gitattributes.')


	cmd = 'Encrypt file before comitting it into git repository - "clean" from secrets.'
	cmd = cmds.add_parser('git-clean', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "encrypt" command from terminal instead.')
	cmd.add_argument('path', nargs='?',
		help='Filename suppled by git.'
			' Not used, since git supplies file contents'
				' to stdin and expects processing results from stdout.')

	cmd = 'Decrypt file when getting it from git repository - "smudge" it with secrets.'
	cmd = cmds.add_parser('git-smudge', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "decrypt" command from terminal instead.')
	cmd.add_argument('path', nargs='?',
		help='Filename suppled by git.'
			' Not used, since git supplies file contents'
				' to stdin and expects processing results from stdout.')

	cmd = 'Decrypt file when getting it from git repository for diff generation purposes.'
	cmd = cmds.add_parser('git-diff', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "decrypt" command from terminal instead.')
	cmd.add_argument('path', help='Filename suppled by git.')


	opts = parser.parse_args(args)

	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger('main')

	# To avoid influence from any of the system-wide aliases
	os.environ['GIT_CONFIG_NOSYSTEM'] = 'true'

	with GitWrapper(conf, nacl) as git:
		opts.parser = parser
		return run_command(opts, conf, nacl, git)


if __name__ == '__main__': sys.exit(main())
