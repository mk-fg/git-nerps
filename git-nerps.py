#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
import os, sys, io, re, types, logging, pathlib as pl
import stat, tempfile, fcntl, subprocess as sp
import contextlib, hmac, hashlib, struct, base64


b64_encode = lambda s: base64.urlsafe_b64encode(s).decode()
b64_decode = lambda s: ( base64.urlsafe_b64decode
	if '-' in s or '_' in s else base64.standard_b64decode )(s)

class Conf:

	key_name_pool = [ # NATO phonetic alphabet
		'alfa', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf',
		'hotel', 'india', 'juliett', 'kilo', 'lima', 'mike', 'november', 'oscar',
		'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor',
		'whiskey', 'x-ray', 'yankee', 'zulu' ]

	umask = 0o0700 # for files where keys are stored

	script_link = '~/.git-nerps'
	git_conf_home = '~/.git-nerps-keys'
	git_conf_version = 1

	enc_magic = '¯\_ʻnerpsʻ_/¯'.encode()
	nonce_key = enc_magic
	pbkdf2_salt = enc_magic
	pbkdf2_rounds = int(5e5)

	def nonce_func(self, plaintext):
		raw = hmac.new(self.nonce_key, plaintext, hashlib.sha256).digest()
		return raw[:self.nacl.nonce_size]

	def __init__(self, nacl): self.nacl = nacl
	def __repr__(self): return repr(vars(self))
	def get(self, *k): return getattr(self, '_'.join(k))


err_fmt = lambda err: '[{}] {}'.format(err.__class__.__name__, err)

class LogMessage:
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self): return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None):
		super(LogStyleAdapter, self).__init__(logger, extra or {})
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), **log_kws)

get_logger = lambda name: LogStyleAdapter(logging.getLogger(name))


class NaCl:

	nonce_size = key_size = key_encode = key_decode = random = error = None

	def __init__(self):
		libnacl = nacl = None
		try: import libnacl
		except ImportError:
			try: import nacl
			except ImportError:
				raise ImportError( 'Either libnacl or pynacl module'
					' is required for this tool, neither one can be imported.' )

		if libnacl:
			from libnacl.secret import SecretBox
			self.nonce_size = libnacl.crypto_secretbox_NONCEBYTES
			self.key_size = libnacl.crypto_secretbox_KEYBYTES
			self.key_encode = lambda key: b64_encode(key.sk)
			self.key_decode = lambda key_str, raw=False:\
				SecretBox(key_str if raw else b64_decode(key_str))
			self.random = libnacl.randombytes
			self.error = ValueError

		if nacl:
			import warnings
			with warnings.catch_warnings(record=True): # cffi warnings
				from nacl.exceptions import CryptoError
				from nacl.encoding import RawEncoder, URLSafeBase64Encoder
				from nacl.secret import SecretBox
				from nacl.utils import random
			self.nonce_size = SecretBox.NONCE_SIZE
			self.key_size = SecretBox.KEY_SIZE
			self.key_encode = lambda key: key.encode(URLSafeBase64Encoder).decode().strip()
			self.key_decode = lambda key_str, raw=False:\
				SecretBox(key_str, URLSafeBase64Encoder if not raw else RawEncoder)
			self.random = random
			self.error = CryptoError

	def test( self, msg=b'test',
			key_enc='pbb6wrDXlLWOFMXYH4a9YHh7nGGD1VnStVYQBe9MyVU=' ):
		key = self.key_decode(self.random(self.key_size), raw=True)
		assert key.decrypt(key.encrypt(msg, self.random(self.nonce_size)))
		key = self.key_decode(key_enc)
		assert self.key_encode(key) == key_enc
		msg_enc = key.encrypt(msg, key_enc[:self.nonce_size].encode())
		msg_dec = key.decrypt(msg_enc)
		assert msg_dec == msg
		print(hashlib.sha256(b''.join([
			str(self.key_size).encode(), str(self.nonce_size).encode(),
			self.key_encode(key).encode(), msg, msg_enc, msg_dec ])).hexdigest())


@contextlib.contextmanager
def safe_replacement(path, *open_args, mode=None, **open_kws):
	path = str(path)
	if mode is None:
		with contextlib.suppress(OSError):
			mode = stat.S_IMODE(os.lstat(path).st_mode)
	open_kws.update( delete=False,
		dir=os.path.dirname(path), prefix=os.path.basename(path)+'.' )
	if not open_args: open_kws['mode'] = 'w'
	with tempfile.NamedTemporaryFile(*open_args, **open_kws) as tmp:
		try:
			if mode is not None: os.fchmod(tmp.fileno(), mode)
			yield tmp
			if not tmp.closed: tmp.flush()
			os.rename(tmp.name, path)
		except CancelFileReplacement: pass
		finally:
			try: os.unlink(tmp.name)
			except OSError: pass

class CancelFileReplacement(Exception): pass
safe_replacement.cancel = CancelFileReplacement

@contextlib.contextmanager
def edit(path, text=False):
	mb = 'b' if not text else ''
	with safe_replacement(path, f'w{mb}') as tmp:
		if not os.path.exists(path): yield None, tmp
		else:
			with open(path, f'r{mb}') as src: yield src, tmp

edit.cancel = CancelFileReplacement

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
					log.exception('Failed to unlock file object: {}', err)
		return _wrapper
	return _decorator

def path_escape(path):
	assert path.strip() == path, repr(path) # trailing spaces should be escaped
	for c in '#!':
		if path.startswith(c): path = rf'\{c}{path[1:]}'
	return path.replace('*', r'\*')

def filter_git_patterns(src, tmp, path_rel, _ree=re.escape):
	if not src: src = io.StringIO()
	for n, line in enumerate(iter(src.readline, ''), 1):
		ls, act = line.strip(), None
		assert not ls.endswith('\\'), repr(line) # not handling these escapes
		if ls and not ls.startswith('#'):
			pat, filters = ls.split(None, 1)
			pat_re = _ree(pat.lstrip('/')).replace(_ree('**'), r'(.+)').replace(_ree('*'), r'([^\/]+)')
			if '/' in pat: pat_re = f'^{pat_re}'
			if re.search(pat_re, path_rel): act = yield n, line, pat, filters
		if not act: tmp.write(f'{line.rstrip()}\n')
		elif isinstance(act, bytes): tmp.write(f'{act.rstrip()}\n')
		elif act is filter_git_patterns.remove: pass
		else: raise ValueError(act)

filter_git_patterns.remove = object()

def cached_result(key_or_func=None, _key=None):
	if callable(key_or_func):
		_key = _key or key_or_func.__name__
		@ft.wraps(key_or_func)
		def _wrapper(self, *args, **kws):
			if _key not in self.c:
				self.c[_key] = key_or_func(self, *args, **kws)
			return self.c[_key]
		return _wrapper
	return ft.partial(cached_result, _key=key_or_func)


class GitWrapperError(Exception): pass

class GitWrapper:

	def __init__(self, conf, nacl):
		self.conf, self.nacl, self.c, self.lock = conf, nacl, dict(), None
		self.log = get_logger('git')

	def __enter__(self):
		self.init()
		return self
	def __exit__(self, *err): self.destroy()
	def __del__(self): self.destroy()


	def init(self): pass # done lazily

	def init_lock(self, gitconfig):
		if self.lock: return
		lock = b64_encode(hashlib.sha256(bytes(gitconfig.resolve(True))).digest())[:8]
		lock = pl.Path(tempfile.gettempdir()) / f'.git-nerps.{lock}.lock'
		self.lock = lock.open('ab+')
		self.log.debug('Acquiring lock: {}', lock)
		fcntl.lockf(self.lock, fcntl.LOCK_EX)

	def destroy(self):
		if self.lock:
			self.log.debug('Releasing lock: {}', self.lock.name)
			self.lock.close()
			self.lock = None


	def run(self, args=None, check=False, no_stderr=False, trap_code=None):
		kws = dict(check=True, stdout=sp.PIPE)
		if no_stderr: kws['stderr'] = sp.DEVNULL
		args = ['git'] + list(args or list())
		if self.log.isEnabledFor(logging.DEBUG):
			opts = ', '.join( str(k) for k, v in
				{'check': check, 'no-stderr': no_stderr, 'trap': trap_code}.items() if v )
			self.log.debug('run: {} [{}]', ' '.join(args), opts or '-')
		try: res = sp.run(args, **kws).stdout.decode().splitlines()
		except sp.CalledProcessError as err:
			if check: return False
			if trap_code:
				if trap_code is True: pass
				elif isinstance(trap_code, int): trap_code = [trap_code]
				if trap_code is True or err.returncode in trap_code: err = res = None
			if err: raise
		return res if not check else True

	def check(self, args=['rev-parse'], no_stderr=True):
		return self.run(args, check=True, no_stderr=no_stderr)

	def run_conf(self, args, gitconfig=None, **run_kws):
		gitconfig = gitconfig or self.path_conf
		return self.run(['config', '--file', str(gitconfig)] + args, **run_kws)

	def sub(self, *path):
		if not self.c.get('git-dir'):
			p = self.run(['rev-parse', '--show-toplevel'])
			assert len(p) == 1, [p, 'rev-cache --show-toplevel result']
			self.c['git-dir'] = pl.Path(p[0]) / '.git'
		if not path: return self.c['git-dir']
		p = self.c['git-dir']
		for s in path: p /= s
		return p

	def param(self, *path):
		assert path and all(path), path
		return f'nerps.{".".join(path)}'

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
		return pl.Path(self.conf.git_conf_home).expanduser()

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
					self.log.warn( 'This script ({}) must be executable'
						' (e.g. run "chmod +x" on it) for git filters to work!' )
				script_link_abs = pl.Path(self.conf.script_link).expanduser()
				if not script_link_abs.exists() or not script_link_abs.samefile(__file__):
					with contextlib.suppress(OSError): script_link_abs.unlink()
					script_link_abs.symlink_to(os.path.abspath(__file__))

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
			run_conf(['--add', ver_k, str(self.conf.git_conf_version)])

		if chmod_umask is None: chmod_umask = self.conf.umask
		if chmod_dir:
			git_repo_dir = gitconfig.parent
			git_repo_dir.chmod(git_repo_dir.stat().st_mode & chmod_umask)
		gitconfig.chmod(gitconfig.stat().st_mode & chmod_umask)


	def _key_iter(self):
		key_re = re.compile(r'^{}\.(.*)$'.format(re.escape(self.param('key'))))
		for gitconfig in self.sub('config'), self.path_conf_home:
			if not gitconfig.exists(): continue
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
			raise GitWrapperError(f'No keys found in config: {self.path_conf}')
		for key in reversed(self.key_all):
			if key.name == name: break
		else:
			raise GitWrapperError(( 'Key {!r} is set as default'
				' but is unavailable (in config: {})' ).format(name, self.path_conf))
		self.log.debug('Using key: {}', name)
		return key


class SSHKeyError(Exception): pass

def ssh_key_hash(conf, nacl, path):
	# See PROTOCOL.key and sshkey.c in openssh sources
	log = get_logger('ssh-key-hash')

	with tempfile.NamedTemporaryFile(
			delete=True, dir=path.parent, prefix=path.name+'.' ) as tmp:
		tmp.write(path.read_bytes())
		tmp.flush()
		cmd = ['ssh-keygen', '-p', '-P', '', '-N', '', '-f', tmp.name]
		p = sp.run( cmd, encoding='utf-8', errors='replace',
			stdin=sp.DEVNULL, stdout=sp.PIPE, stderr=sp.PIPE )
		stdout, stderr = p.stdout.splitlines(), p.stderr.splitlines()
		err = p.returncode

		if err:
			if stdout: print('\n'.join(stdout), file=sys.stderr)
			key_enc = False
			for line in stderr:
				if re.search( r'^Failed to load key .*:'
						r' incorrect passphrase supplied to decrypt private key$', line ):
					key_enc = True
				else: print(line, file=sys.stderr)
			if key_enc:
				print('WARNING:')
				print( 'WARNING: !!! ssh key will be decrypted'
					f' (via ssh-keygen) to a temporary file {tmp.name!r} in the next step !!!' )
				print('WARNING: DO NOT enter key passphrase'
					' and ABORT operation (^C) if that is undesirable.')
				print('WARNING:')
				cmd = ['ssh-keygen', '-p', '-N', '', '-f', tmp.name]
				log.debug('Running interactive ssh-keygen to decrypt key: {}', ' '.join(cmd))
				err, p = None, sp.run( cmd, check=True,
					encoding='utf-8', errors='replace', stdout=sp.PIPE, stderr=sp.PIPE )
				stdout, stderr = p.stdout.splitlines(), p.stderr.splitlines()

		if err or 'Your identification has been saved with the new passphrase.' not in stdout:
			for lines in stdout, stderr: print('\n'.join(lines).decode(), file=sys.stderr)
			raise SSHKeyError(( 'ssh-keygen failed to process key {},'
				' see stderr output above for details, command: {}' ).format(path, ' '.join(cmd)))

		tmp.seek(0)
		lines, key, done = tmp.read().decode().splitlines(), list(), False
		for line in lines:
			if line == '-----END OPENSSH PRIVATE KEY-----': done = True
			if key and not done: key.append(line)
			if line == '-----BEGIN OPENSSH PRIVATE KEY-----':
				if done:
					raise SSHKeyError( 'More than one'
						f' private key detected in file, aborting: {path!r}' )
				assert not key
				key.append('')
		if not done: raise SSHKeyError(f'Incomplete or missing key in file: {path!r}')
		key_bytes = b64_decode(''.join(key))
		key = io.BytesIO(key_bytes)

		def key_read_bytes(src=None):
			if src is None: src = key
			n, = struct.unpack('>I', src.read(4))
			return src.read(n)

		def key_assert(chk, err, *fmt_args, **fmt_kws):
			if chk: return
			if fmt_args or fmt_kws: err = err.format(*fmt_args, **fmt_kws)
			err += f' [key file: {path!r}, decoded: {key_bytes!r}]'
			raise SSHKeyError(err)

		def key_assert_read(field, val, fixed=False):
			pos, chk = key.tell(), key.read(len(val)) if fixed else key_read_bytes()
			key_assert( chk == val, 'Failed to match key field'
				' {!r} (offset: {}) - expected {!r} got {!r}', field, pos, val, chk )

		key_assert_read('AUTH_MAGIC', b'openssh-key-v1\0', True)
		key_assert_read('ciphername', b'none')
		key_assert_read('kdfname', b'none')
		key_assert_read('kdfoptions', b'')
		(pubkey_count,), pubkeys = struct.unpack('>I', key.read(4)), list()
		for n in range(pubkey_count):
			line = key_read_bytes()
			key_assert(line, 'Empty public key #{}', n)
			line = io.BytesIO(line)
			key_t = key_read_bytes(line).decode()
			key_assert(key_t == 'ssh-ed25519', 'Unsupported pubkey type: {!r}', key_t)
			ed25519_pk = key_read_bytes(line)
			line = line.read()
			key_assert(not line, 'Garbage data after pubkey: {!r}', line)
			pubkeys.append(ed25519_pk)
		privkey = io.BytesIO(key_read_bytes())
		pos, tail = key.tell(), key.read()
		key_assert( not tail,
			'Garbage data after private key (offset: {}): {!r}', pos, tail )

		key = privkey
		n1, n2 = struct.unpack('>II', key.read(8))
		key_assert(n1 == n2, 'checkint values mismatch in private key spec: {!r} != {!r}', n1, n2)
		key_t = key_read_bytes().decode()
		key_assert(key_t == 'ssh-ed25519', 'Unsupported key type: {!r}', key_t)
		ed25519_pk = key_read_bytes()
		key_assert(ed25519_pk in pubkeys, 'Pubkey mismatch - {!r} not in {}', ed25519_pk, pubkeys)
		ed25519_sk = key_read_bytes()
		key_assert(
			len(ed25519_pk) == 32 and len(ed25519_sk) == 64,
			'Key length mismatch: {}/{} != 32/64', len(ed25519_pk), len(ed25519_sk) )
		comment = key_read_bytes()
		padding = key.read()
		padding, padding_chk = bytearray(padding), bytearray(range(1, len(padding) + 1))
		key_assert(padding == padding_chk, 'Invalid padding: {!r} != {!r}', padding, padding_chk)
		log.debug('Parsed {} key, comment: {!r}', key_t, comment)

	return hashlib.pbkdf2_hmac( 'sha256', ed25519_sk,
		conf.pbkdf2_salt, conf.pbkdf2_rounds, nacl.key_size )


def is_encrypted(conf, src_or_line, rewind=True):
	if not isinstance(src_or_line, bytes):
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
	dst_stream.write( conf.enc_magic + b' '
		+ str(conf.git_conf_version).encode() + b'\n' )
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
	except nacl.error as err:
		if strict: raise
		err_t, err, err_tb = sys.exc_info()
		log.debug( 'Failed to decrypt with {} key {}: {}',
			'default' if not name else 'specified', key.name, err )
		for key_chk in git.key_all:
			if key_chk.name == key.name: continue
			log.debug('Trying key: {}', key_chk.name)
			try: plaintext = key_chk.decrypt(ciphertext)
			except nacl.error: pass
			else: break
		else: raise err.with_traceback(err_tb)
	if dst: dst.write(plaintext)
	else: return plaintext



def run_command(opts, conf, nacl, git):
	log = get_logger(opts.cmd)
	bin_stdin = open(sys.stdin.fileno(), 'rb')
	bin_stdout = open(sys.stdout.fileno(), 'wb')
	exit_code = 0


	##########
	if opts.cmd == 'init':
		if not git.check(): opts.parser.error('Can only be run inside git repository')
		git.path_conf_init()


	##########
	elif opts.cmd == 'key-gen':
		key_ssh = False # checked to pick more suitable key name
		if opts.from_ssh_key is False:
			key_raw = nacl.random(nacl.key_size)
		else:
			key_path = opts.from_ssh_key
			if not key_path or key_path in ['ed25519']:
				key_path = list(
					pl.Path(f'~/.ssh/id_{p}').expanduser()
					for p in ([key_path] if key_path else ['ed25519']) )
				key_path = list(p for p in key_path if p.exists())
				if len(key_path) != 1:
					opts.parser.error(( 'Key spec must match'
						f' exactly one key path, matched: {", ".join(key_path)}' ))
				key_path, = key_path
			if opts.from_ssh_key_pbkdf2_params:
				rounds, salt = opts.from_ssh_key_pbkdf2_params.split('/', 1)
				conf.pbkdf2_rounds, conf.pbkdf2_salt = int(rounds), salt
			key_ssh, key_raw = True, ssh_key_hash(conf, nacl, key_path)
		key = nacl.key_decode(key_raw, raw=True)
		key_str = nacl.key_encode(key)

		if opts.print:
			print(f'Key:\n  {key_str}\n')
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
			pool = conf.key_name_pool
			if key_ssh: pool = it.chain(['ssh'], pool)
			for name in pool:
				k = git.param('key', name)
				if not run_conf(['--get', k], check=True, no_stderr=True): break
			else:
				raise opts.parser.error('Failed to find unused'
					' key name, specify one explicitly with --name.')
		k = git.param('key', name)

		log.info('Adding key {!r} to gitconfig (k: {}): {}', name, k, gitconfig)
		if opts.verbose: print(f'Generated new key {name!r}:\n  {key_str}\n')

		# To avoid flashing key on command line (which can be seen by any
		#  user in same pid ns), "git config --add" is used with unique tmp_token
		#  here, which is then replaced (in the config file) by actual key.

		gitconfig_str = gitconfig.read_text()
		while True:
			tmp_token = b64_encode(os.urandom(18)).strip()
			if tmp_token not in gitconfig_str: break

		commit = False
		try:
			run_conf(['--add', k, tmp_token])
			with edit(gitconfig, text=True) as (src, tmp):
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

		if k or opts.name_arg: # make sure default key is the right one and is available
			if k: k, = k
			k_updated = opts.name and k != opts.name and opts.name
			if k_updated: k = opts.name
			v = git.run_conf(['--get', git.param('key', k)])
			if not v and opts.name:
				opts.parser.error('Key {!r} was not found in config file: {}', k, git.path_conf)
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
		key_names = list(k.name for k in git.key_all)
		for n_def, name in reversed(list(enumerate(key_names))):
			if name == git.key_name_default: break
		for n, name in enumerate(key_names):
			print(name + (' [default]' if n == n_def else ''))


	##########
	elif opts.cmd == 'git-clean':
		src = io.BytesIO(bin_stdin.read())
		if is_encrypted(conf, src):
			log.error( '(Supposedly) plaintext file contents'
				' seem to be already encrypted, refusing to encrypt: {}', opts.path)
			return 1
		encrypt(conf, nacl, git, log, opts.name, src=src, dst=bin_stdout)
		bin_stdout.close() # to make sure no garbage data will end up there

	##########
	elif opts.cmd in ['git-smudge', 'git-diff']:
		if opts.cmd == 'git-diff': src = opts.path.open('rb')
		else: src = io.BytesIO(bin_stdin.read())
		try:
			if not is_encrypted(conf, src):
				if opts.cmd != 'git-diff':
					# XXX: filter history or at least detect whether that's the case
					log.warn( '{} - file seem to be unencrypted in the repo'
						' (ignore this error when marking files with history): {}', opts.cmd, opts.path )
				bin_stdout.write(src.read())
			else:
				decrypt( conf, nacl, git, log, opts.name,
					src=src, dst=bin_stdout, strict=opts.name_strict )
			bin_stdout.close() # to make sure no garbage data will end up there
		finally: src.close()


	##########
	elif opts.cmd == 'encrypt':
		if opts.path:
			with edit(opts.path) as (src, tmp):
				if not opts.force and is_encrypted(conf, src): raise edit.cancel
				encrypt(conf, nacl, git, log, opts.name, src=src, dst=tmp)
		else: encrypt(conf, nacl, git, log, opts.name, src=bin_stdin, dst=bin_stdout)

	##########
	elif opts.cmd == 'decrypt':
		if opts.path:
			with edit(opts.path) as (src, tmp):
				if not opts.force and not is_encrypted(conf, src): raise edit.cancel
				decrypt( conf, nacl, git, log, opts.name,
					src=src, dst=tmp, strict=opts.name_strict )
		else:
			decrypt( conf, nacl, git, log, opts.name,
				src=bin_stdin, dst=bin_stdout, strict=opts.name_strict )


	##########
	elif opts.cmd in ('taint', 'clear'):
		if not git.check(): opts.parser.error('Can only be run inside git repository')

		for path in opts.path:
			path_rel = os.path.relpath(path, git.sub('..'))
			assert not re.search(r'^(\.|/)', path_rel), path_rel
			attrs_file = git.sub( '../.gitattributes'
				if not opts.local_only else 'info/attributes' ).resolve()

			with edit(attrs_file, text=True) as (src, tmp):
				n, matches_mark, matches = None, dict(), filter_git_patterns(src, tmp, path_rel)
				while True:
					try: n, line, pat, filters = next(matches) if n is None else matches.send(act)
					except StopIteration: break
					act = None
					if opts.cmd == 'taint':
						if not opts.force:
							if not opts.silent:
								log.error( 'gitattributes ({}) already has matching'
									' pattern for path {}, not adding another one (line {}): {!r}',
									attrs_file, path_rel, n, line )
								# XXX: check if that line also has matching filter, add one
								exit_code = 1
							raise edit.cancel
					if opts.cmd == 'clear':
						# XXX: check if line has actually **matching** filter
						matches_mark[n] = line

				if opts.cmd == 'taint':
					tmp.write(f'/{path_escape(path_rel)} filter=nerps diff=nerps\n')

				if opts.cmd == 'clear':
					if not matches_mark:
						if not opts.silent:
							log.error( 'gitattributes ({}) pattern'
								' for path {} was not found', attrs_file, path_rel )
							exit_code = 1
						raise edit.cancel
					if not opts.force and len(matches_mark) > 1:
						log.error( 'More than one gitattributes ({}) pattern was found'
							' for path {}, aborting: {!r}', attrs_file, path_rel, matches_mark.values() )
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
				with tempfile.NamedTemporaryFile(
						delete=False, dir=path.parent, prefix=path.name+'.' ) as tmp:
					path.rename(tmp.name)
					renames.append((tmp.name, path))
			git.run(['status'])
			success = True
		finally:
			for src, dst in reversed(renames):
				try: os.rename(src, dst)
				except:
					log.exception( 'Failed to restore original'
						' name for path: {} (tmp-name: {})', dst, src )
		if success: git.run(['status'])



	else:
		if not opts.cmd:
			opts.parser.error( 'Specify subcommand'
				' or use -h/--help to see the list and info on these.' )
		opts.parser.error(f'Unrecognized command: {opts.cmd}')
	return exit_code


def main(args=None, defaults=None):
	nacl, args = NaCl(), sys.argv[1:] if args is None else args
	conf = defaults or Conf(nacl)

	import argparse, textwrap
	dedent = lambda text: (textwrap.dedent(text).strip('\n') + '\n').replace('\t', '  ')
	text_fill = lambda s,w=100,ind='\t',ind_next=None,**k: textwrap.fill(
		s, w, initial_indent=ind, subsequent_indent=ind if ind_next is None else ind_next, **k )
	class SmartHelpFormatter(argparse.HelpFormatter):
		def __init__(self, *args, **kws):
			return super().__init__(*args, **kws, width=100)
		def _fill_text(self, text, width, indent):
			if '\n' not in text: return super()._fill_text(text, width, indent)
			return ''.join( indent + line
				for line in text.replace('\t', '  ').splitlines(keepends=True) )
		def _split_lines(self, text, width):
			return super()._split_lines(text, width)\
				if '\n' not in text else dedent(text).splitlines()

	parser = argparse.ArgumentParser(
		formatter_class=SmartHelpFormatter,
		description='Tool to manage encrypted files in a git repo.' )

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')

	parser.add_argument('-n', '--name', metavar='key-name',
		help='''
			Key name to use.
			Can be important or required for some commands (e.g. "key-set").
			For most commands, default key gets
				picked either as a first one or the one explicitly set as such.
			When generating new key, default is to pick some
				unused name from the phonetic alphabet letters.''')

	parser.add_argument('-s', '--name-strict', action='store_true',
		help='''
			Only try specified or default key for decryption.
			Default it to try other ones if that one fails, to see if any of them work for a file.''')

	cmds = parser.add_subparsers(
		dest='cmd', title='Actions',
		description='Supported actions (have their own suboptions as well)')
	cmds_add_parser = ft.partial(cmds.add_parser, formatter_class=SmartHelpFormatter)


	cmd = 'Initialize repository configuration.'
	cmd = cmds_add_parser('init', help=cmd, description=cmd,
		epilog='Will be done automatically on any'
			' other action (e.g. "key-gen"), so can usually be skipped.')


	cmd = 'Generate new encryption key and store or just print it.'
	cmd = cmds_add_parser('key-gen', help=cmd, description=cmd,
		epilog=dedent('''
			Default is to store key in a git repository config
				(but dont set it as default if there are other ones already),
				if inside git repo, otherwise store in the home dir'
				(also making it default only if there was none before it).
			Use "key-set" command to pick default key for git repo, user or file.
			System-wide and per-user gitconfig files are never used for key storage,
				as these are considered to be a bad place to store anything private.'''))
	cmd.add_argument('name_arg', nargs='?',
		help='Same as using global --name option, but overrides it if both are used.')

	cmd.add_argument('-p', '--print', action='store_true',
		help='Only print the generated key, do not store anywhere.')
	cmd.add_argument('-v', '--verbose', action='store_true',
		help='Print generated key in addition to storing it.')

	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help=f'Store new key in the {conf.git_conf_home} file (in user home directory).')

	cmd.add_argument('-k', '--from-ssh-key',
		nargs='?', metavar='ed25519 | path', default=False,
		help='''
			Derive key from openssh private key
				using PBKDF2-SHA256 with static salt
				(by default, see --from-ssh-key-pbkdf2-params).
			If key is encrypted, error will be raised
				(use "ssh-keygen -p" to provide non-encrypted version).
			Optional argument can specify type of the key
				(only ed25519 is supported though)
				to pick from default location (i.e. ~/.ssh/id_*) or path to the key.
			If optional arg is not specified, any default key will be picked,
				but only if there is exactly one, otherwise error will be raised.''')
	cmd.add_argument('--from-ssh-key-pbkdf2-params', metavar='rounds/salt',
		help=f'''
			Number of PBKDF2 rounds and salt to use for --from-ssh-key derivation.
			It is probably a good idea to not use any valuable secret
				as "salt", especially when specifying it on the command line.
			Defaults are: {conf.pbkdf2_rounds}/{conf.pbkdf2_salt.decode()}''')

	cmd.add_argument('-s', '--set-as-default', action='store_true',
		help='Set generated key as default in whichever config it will be stored.')


	cmd = 'Set default encryption key for a repo/homedir config.'
	cmd = cmds_add_parser('key-set', help=cmd, description=cmd,
		epilog=dedent('''
			Same try-repo-then-home config order as with key-gen command.
			Key name should be specified with the --name option.
			If no --name will be specified and there is no default key set
				or it no longer available, first (any) available key will be set as default.'''))
	cmd.add_argument('name_arg', nargs='?',
		help='Same as using global --name option, but overrides it if both are used.')
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help=f'Store new key in the {conf.git_conf_home} file (in user home directory).')


	cmd = 'Unset default encryption key for a repo/homedir config.'
	cmd = cmds_add_parser('key-unset', help=cmd, description=cmd)
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help=f'Store new key in the {conf.git_conf_home} file (in user home directory).')


	cmd = 'List available crypto keys.'
	cmd = cmds_add_parser('key-list', help=cmd, description=cmd)
	cmd.add_argument('-g', '--git', action='store_true',
		help='Store new key in git-config, or exit with error if not in git repo.')
	cmd.add_argument('-d', '--homedir', action='store_true',
		help=f'Store new key in the {conf.git_conf_home} file (in user home directory).')


	cmd = 'Encrypt file in-place or process stdin to stdout.'
	cmd = cmds_add_parser('encrypt', help=cmd, description=cmd)
	cmd.add_argument('path', nargs='?',
		help='Path to a file to encrypt.'
			' If not specified, stdin/stdout streams will be used instead.')
	cmd.add_argument('-f', '--force', action='store_true',
		help='Encrypt even if file appears to be encrypted already.')

	cmd = 'Decrypt file in-place or process stdin to stdout.'
	cmd = cmds_add_parser('decrypt', help=cmd, description=cmd)
	cmd.add_argument('path', nargs='?',
		help='Path to a file to decrypt.'
			' If not specified, stdin/stdout streams will be used instead.')
	cmd.add_argument('-f', '--force', action='store_true',
		help='Decrypt even if file does not appear to be encrypted.')


	cmd = 'Mark file(s) to be transparently encrypted in the current git repo.'
	cmd = cmds_add_parser('taint', help=cmd, description=cmd,
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
	cmd = cmds_add_parser('clear', help=cmd, description=cmd,
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
	cmd = cmds_add_parser('git-clean', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "encrypt" command from terminal instead.')
	cmd.add_argument('path', nargs='?',
		help='Filename suppled by git.'
			' Not used, since git supplies file contents'
				' to stdin and expects processing results from stdout.')

	cmd = 'Decrypt file when getting it from git repository - "smudge" it with secrets.'
	cmd = cmds_add_parser('git-smudge', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "decrypt" command from terminal instead.')
	cmd.add_argument('path', nargs='?',
		help='Filename suppled by git.'
			' Not used, since git supplies file contents'
				' to stdin and expects processing results from stdout.')

	cmd = 'Decrypt file when getting it from git repository for diff generation purposes.'
	cmd = cmds_add_parser('git-diff', help=cmd, description=cmd,
		epilog='Intended to be only used by git, use "decrypt" command from terminal instead.')
	cmd.add_argument('path', help='Filename suppled by git.')


	opts = parser.parse_args(args)

	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = get_logger('main')

	# To avoid influence from any of the system-wide aliases
	os.environ['GIT_CONFIG_NOSYSTEM'] = 'true'

	with GitWrapper(conf, nacl) as git:
		opts.parser = parser
		if getattr(opts, 'path', None):
			opts.path = ( list(map(pl.Path, opts.path))
				if isinstance(opts.path, list) else pl.Path(opts.path) )
		return run_command(opts, conf, nacl, git)


if __name__ == '__main__': sys.exit(main())
