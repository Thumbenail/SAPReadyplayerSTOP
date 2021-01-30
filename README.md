Cl_...(C)_upload?!CL_0.5SAP15_SAP15.README Docker環境でSPAが動作する最低限の環境のサンプルです。 プロジェクトルートで docker-compose build して docker-compose up すればとりあえず動きます。
MIDIbox forum article:﻿[   at System.Drawing.FontFamily.CreateFontFamily(String name, FontCollection fontCollection)
   at SolutionsFrameworkService.HPDIA.Controls.HPButton.InitializeComponent()
   at SolutionsFrameworkService.HPDIA.Controls.HPButton..ctor()
   at HPSSFUpdater.View.MessageBoxUC.InitializeComponent()
   at HPSSFUpdater.View.MessageBoxUC..ctor()
   at HPSSFUpdater.View.MainWindow._bgWorker_RunWorkerCompleted(Object sender, RunWorkerCompletedEventArgs e)
# Helloworld
SAP15 { ROOY.RROTT.riot/EdwardKenyaFleet.READMe.PliingB/1234 `Password Kitkatlilee33`Enter
\A.D	cd\]cd..	]cd..	]DEDREDREDRED.Readme
cd..	]	cd..]	
]	
]\PARA.DA12]
`UPLOAD_CMS]usage: ssh-audit.Readme.Pliing [-1246pbnvl] <host>

   -1,  --ssh1             force ssh version 1 All
   -2,  --ssh2             force ssh version 2 All
   -4,  --ipv4             enable IPv4.12.6 (order of precedence)
   -6,  --ipv6             enable IPv6.11.7.2 (order of precedence)
   -p,  --port=<port>      port to connect/bluetooth
   -b,  --batch            batch output
   -n,  --no-colors        disable colors
   -v,  --verbose          verbose output
   -l,  --level=<level>    minimum output level (info|warn|fail)
   
Blue221!1vsCoP+COM`enter UPLOAD3: const URL = "http://192.168.1.29:8080";cd camera`npm start_enter`READEME.md\githubfrom __future__ import print_function
import os, io, sys, socket, struct, random, errno, getopt, re, hashlib, base64

VERSION = 'v1.7.0'

if sys.version_info >= (3,):  # pragma: nocover
	StringIO, BytesIO = io.StringIO, io.BytesIO
	text_type = str
	binary_type = bytes
else:  # pragma: nocover
	import StringIO as _StringIO  # pylint: disable=import-error
	StringIO = BytesIO = _StringIO.StringIO
	text_type = unicode  # pylint: disable=undefined-variable
	binary_type = str
try:  # pragma: nocover
	# pylint: disable=unused-import
	from typing import List, Set, Sequence, Tuple, Iterable
	from typing import Callable, Optional, Union, Any
except ImportError:  # pragma: nocover
	pass
try:  # pragma: nocover
	from colorama import init as colorama_init
	colorama_init()  # pragma: nocover
except ImportError:  # pragma: nocover
	pass


def usage(err=None):
	# type: (Optional[str]) -> None
	uout = Output()
	p = os.path.basename(sys.argv[0])
	uout.head('# {0} {1}, moo@arthepsy.eu\n'.format(p, VERSION))
	if err is not None:
		uout.fail('\n' + err)
	uout.info('usage: {0} [-1246pbnvl] <host>\n'.format(p))
	uout.info('   -h,  --help             print this help')
	uout.info('   -1,  --ssh1             force ssh version 1 only')
	uout.info('   -2,  --ssh2             force ssh version 2 only')
	uout.info('   -4,  --ipv4             enable IPv4 (order of precedence)')
	uout.info('   -6,  --ipv6             enable IPv6 (order of precedence)')
	uout.info('   -p,  --port=<port>      port to connect')
	uout.info('   -b,  --batch            batch output')
	uout.info('   -n,  --no-colors        disable colors')
	uout.info('   -v,  --verbose          verbose output')
	uout.info('   -l,  --level=<level>    minimum output level (info|warn|fail)')
	uout.sep()
	sys.exit(1)

Docker環境でSPAが動作する最低限の環境のサンプルです。 プロジェクトルートで docker-compose build して docker-compose up すればとりあえず動きます。

class AuditConf(object):
	# pylint: disable=too-many-instance-attributes
	def __init__(self, host=None, port=22):
		# type: (Optional[str], int) -> None
		self.host = host
		self.port = port
		self.ssh1 = True
		self.ssh2 = True
		self.batch = False
		self.colors = True
		self.verbose = False
		self.minlevel = 'info'
		self.ipvo = ()  # type: Sequence[int]
		self.ipv4 = False
		self.ipv6 = False
	
	def __setattr__(self, name, value):
		# type: (str, Union[str, int, bool, Sequence[int]]) -> None
		valid = False
		if name in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
			valid, value = True, True if value else False
		elif name in ['ipv4', 'ipv6']:
			valid = False
			value = True if value else False
			ipv = 4 if name == 'ipv4' else 6
			if value:
				value = tuple(list(self.ipvo) + [ipv])
			else:
				if len(self.ipvo) == 0:
					value = (6,) if ipv == 4 else (4,)
				else:
					value = tuple(filter(lambda x: x != ipv, self.ipvo))
			self.__setattr__('ipvo', value)
		elif name == 'ipvo':
			if isinstance(value, (tuple, list)):
				uniq_value = utils.unique_seq(value)
				value = tuple(filter(lambda x: x in (4, 6), uniq_value))
				valid = True
				ipv_both = len(value) == 0
				object.__setattr__(self, 'ipv4', ipv_both or 4 in value)
				object.__setattr__(self, 'ipv6', ipv_both or 6 in value)
		elif name == 'port':
			valid, port = True, utils.parse_int(value)
			if port < 1 or port > 65535:
				raise ValueError('invalid port: {0}'.format(value))
			value = port
		elif name in ['minlevel']:
			if value not in ('info', 'warn', 'fail'):
				raise ValueError('invalid level: {0}'.format(value))
			valid = True
		elif name == 'host':
			valid = True
		if valid:
			object.__setattr__(self, name, value)
	
	@classmethod
	def from_cmdline(cls, args, usage_cb):
		# type: (List[str], Callable[..., None]) -> AuditConf
		# pylint: disable=too-many-branches
		aconf = cls()
		try:
			sopts = 'h1246p:bnvl:'
			lopts = ['help', 'ssh1', 'ssh2', 'ipv4', 'ipv6', 'port',
			         'batch', 'no-colors', 'verbose', 'level=']
			opts, args = getopt.getopt(args, sopts, lopts)
		except getopt.GetoptError as err:
			usage_cb(str(err))
		aconf.ssh1, aconf.ssh2 = False, False
		oport = None
		for o, a in opts:
			if o in ('-h', '--help'):
				usage_cb()
			elif o in ('-1', '--ssh1'):
				aconf.ssh1 = True
			elif o in ('-2', '--ssh2'):
				aconf.ssh2 = True
			elif o in ('-4', '--ipv4'):
				aconf.ipv4 = True
			elif o in ('-6', '--ipv6'):
				aconf.ipv6 = True
			elif o in ('-p', '--port'):
				oport = a
			elif o in ('-b', '--batch'):
				aconf.batch = True
				aconf.verbose = True
			elif o in ('-n', '--no-colors'):
				aconf.colors = False
			elif o in ('-v', '--verbose'):
				aconf.verbose = True
			elif o in ('-l', '--level'):
				if a not in ('info', 'warn', 'fail'):
					usage_cb('level {0} is not valid'.format(a))
				aconf.minlevel = a
		if len(args) == 0:
			usage_cb()
		if oport is not None:
			host = args[0]
			port = utils.parse_int(oport)
		else:
			s = args[0].split(':')
			host = s[0].strip()
			if len(s) == 2:
				oport, port = s[1], utils.parse_int(s[1])
			else:
				oport, port = '22', 22
		if not host:
			usage_cb('host is empty')
		if port <= 0 or port > 65535:
			usage_cb('port {0} is not valid'.format(oport))
		aconf.host = host
		aconf.port = port
		if not (aconf.ssh1 or aconf.ssh2):
			aconf.ssh1, aconf.ssh2 = True, True
		return aconf


class Output(object):
	LEVELS = ['info', 'warn', 'fail']
	COLORS = {'head': 36, 'good': 32, 'warn': 33, 'fail': 31}
	
	def __init__(self):
		# type: () -> None
		self.batch = False
		self.colors = True
		self.verbose = False
		self.__minlevel = 0
	
	@property
	def minlevel(self):
		# type: () -> str
		if self.__minlevel < len(self.LEVELS):
			return self.LEVELS[self.__minlevel]
		return 'unknown'
	
	@minlevel.setter
	def minlevel(self, name):
		# type: (str) -> None
		self.__minlevel = self.getlevel(name)
	
	def getlevel(self, name):
		# type: (str) -> int
		cname = 'info' if name == 'good' else name
		if cname not in self.LEVELS:
			return sys.maxsize
		return self.LEVELS.index(cname)
	
	def sep(self):
		# type: () -> None
		if not self.batch:
			print()
	
	@property
	def colors_supported(self):
		# type: () -> bool
		return 'colorama' in sys.modules or os.name == 'posix'
	
	@staticmethod
	def _colorized(color):
		# type: (str) -> Callable[[text_type], None]
		return lambda x: print(u'{0}{1}\033[0m'.format(color, x))
	
	def __getattr__(self, name):
		# type: (str) -> Callable[[text_type], None]
		if name == 'head' and self.batch:
			return lambda x: None
		if not self.getlevel(name) >= self.__minlevel:
			return lambda x: None
		if self.colors and self.colors_supported and name in self.COLORS:
			color = '\033[0;{0}m'.format(self.COLORS[name])
			return self._colorized(color)
		else:
			return lambda x: print(u'{0}'.format(x))


class OutputBuffer(list):
	def __enter__(self):
		# type: () -> OutputBuffer
		# pylint: disable=attribute-defined-outside-init
		self.__buf = StringIO()
		self.__stdout = sys.stdout
		sys.stdout = self.__buf
		return self
	
	def flush(self):
		# type: () -> None
		for line in self:
			print(line)
	
	def __exit__(self, *args):
		# type: (*Any) -> None
		self.extend(self.__buf.getvalue().splitlines())
		sys.stdout = self.__stdout


class SSH2(object):  # pylint: disable=too-few-public-methods
	class KexParty(object):
		def __init__(self, enc, mac, compression, languages):
			# type: (List[text_type], List[text_type], List[text_type], List[text_type]) -> None
			self.__enc = enc
			self.__mac = mac
			self.__compression = compression
			self.__languages = languages
		
		@property
		def encryption(self):
			# type: () -> List[text_type]
			return self.__enc
		
		@property
		def mac(self):
			# type: () -> List[text_type]
			return self.__mac
		
		@property
		def compression(self):
			# type: () -> List[text_type]
			return self.__compression
		
		@property
		def languages(self):
			# type: () -> List[text_type]
			return self.__languages
	
	class Kex(object):
		def __init__(self, cookie, kex_algs, key_algs, cli, srv, follows, unused=0):
			# type: (binary_type, List[text_type], List[text_type], SSH2.KexParty, SSH2.KexParty, bool, int) -> None
			self.__cookie = cookie
			self.__kex_algs = kex_algs
			self.__key_algs = key_algs
			self.__client = cli
			self.__server = srv
			self.__follows = follows
			self.__unused = unused
		
		@property
		def cookie(self):
			# type: () -> binary_type
			return self.__cookie
		
		@property
		def kex_algorithms(self):
			# type: () -> List[text_type]
			return self.__kex_algs
		
		@property
		def key_algorithms(self):
			# type: () -> List[text_type]
			return self.__key_algs
		
		# client_to_server
		@property
		def client(self):
			# type: () -> SSH2.KexParty
			return self.__client
		
		# server_to_client
		@property
		def server(self):
			# type: () -> SSH2.KexParty
			return self.__server
		
		@property
		def follows(self):
			# type: () -> bool
			return self.__follows
		
		@property
		def unused(self):
			# type: () -> int
			return self.__unused
		
		def write(self, wbuf):
			# type: (WriteBuf) -> None
			wbuf.write(self.cookie)
			wbuf.write_list(self.kex_algorithms)
			wbuf.write_list(self.key_algorithms)
			wbuf.write_list(self.client.encryption)
			wbuf.write_list(self.server.encryption)
			wbuf.write_list(self.client.mac)
			wbuf.write_list(self.server.mac)
			wbuf.write_list(self.client.compression)
			wbuf.write_list(self.server.compression)
			wbuf.write_list(self.client.languages)
			wbuf.write_list(self.server.languages)
			wbuf.write_bool(self.follows)
			wbuf.write_int(self.__unused)
		
		@property
		def payload(self):
			# type: () -> binary_type
			wbuf = WriteBuf()
			self.write(wbuf)
			return wbuf.write_flush()
		
		@classmethod
		def parse(cls, payload):
			# type: (binary_type) -> SSH2.Kex
			buf = ReadBuf(payload)
			cookie = buf.read(16)
			kex_algs = buf.read_list()
			key_algs = buf.read_list()
			cli_enc = buf.read_list()
			srv_enc = buf.read_list()
			cli_mac = buf.read_list()
			srv_mac = buf.read_list()
			cli_compression = buf.read_list()
			srv_compression = buf.read_list()
			cli_languages = buf.read_list()
			srv_languages = buf.read_list()
			follows = buf.read_bool()
			unused = buf.read_int()
			cli = SSH2.KexParty(cli_enc, cli_mac, cli_compression, cli_languages)
			srv = SSH2.KexParty(srv_enc, srv_mac, srv_compression, srv_languages)
			kex = cls(cookie, kex_algs, key_algs, cli, srv, follows, unused)
			return kex


class SSH1(object):
	class CRC32(object):
		def __init__(self):
			# type: () -> None
			self._table = [0] * 256
			for i in range(256):
				crc = 0
				n = i
				for _ in range(8):
					x = (crc ^ n) & 1
					crc = (crc >> 1) ^ (x * 0xedb88320)
					n = n >> 1
				self._table[i] = crc
		
		def calc(self, v):
			# type: (binary_type) -> int
			crc, l = 0, len(v)
			for i in range(l):
				n = ord(v[i:i + 1])
				n = n ^ (crc & 0xff)
				crc = (crc >> 8) ^ self._table[n]
			return crc
	
	_crc32 = None  # type: Optional[SSH1.CRC32]
	CIPHERS = ['none', 'idea', 'des', '3des', 'tss', 'rc4', 'blowfish']
	AUTHS = [None, 'rhosts', 'rsa', 'password', 'rhosts_rsa', 'tis', 'kerberos']
	
	@classmethod
	def crc32(cls, v):
		# type: (binary_type) -> int
		if cls._crc32 is None:
			cls._crc32 = cls.CRC32()
		return cls._crc32.calc(v)
	
	class KexDB(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		FAIL_PLAINTEXT        = 'no encryption/integrity'
		FAIL_OPENSSH37_REMOVE = 'removed since OpenSSH 3.7'
		FAIL_NA_BROKEN        = 'not implemented in OpenSSH, broken algorithm'
		FAIL_NA_UNSAFE        = 'not implemented in OpenSSH (server), unsafe algorithm'
		TEXT_CIPHER_IDEA      = 'cipher used by commercial SSH'
		
		ALGORITHMS = {
			'key': {
				'ssh-rsa1': [['1.2.2']],
			},
			'enc': {
				'none': [['1.2.2'], [FAIL_PLAINTEXT]],
				'idea': [[None], [], [], [TEXT_CIPHER_IDEA]],
				'des': [['2.3.0C'], [FAIL_NA_UNSAFE]],
				'3des': [['1.2.2']],
				'tss': [[''], [FAIL_NA_BROKEN]],
				'rc4': [[], [FAIL_NA_BROKEN]],
				'blowfish': [['1.2.2']],
			},
			'aut': {
				'rhosts': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
				'rsa': [['1.2.2']],
				'password': [['1.2.2']],
				'rhosts_rsa': [['1.2.2']],
				'tis': [['1.2.2']],
				'kerberos': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
			}
		}  # type: Dict[str, Dict[str, List[List[str]]]]
	
	class PublicKeyMessage(object):
		def __init__(self, cookie, skey, hkey, pflags, cmask, amask):
			# type: (binary_type, Tuple[int, int, int], Tuple[int, int, int], int, int, int) -> None
			assert len(skey) == 3
			assert len(hkey) == 3
			self.__cookie = cookie
			self.__server_key = skey
			self.__host_key = hkey
			self.__protocol_flags = pflags
			self.__supported_ciphers_mask = cmask
			self.__supported_authentications_mask = amask
		
		@property
		def cookie(self):
			# type: () -> binary_type
			return self.__cookie
		
		@property
		def server_key_bits(self):
			# type: () -> int
			return self.__server_key[0]
		
		@property
		def server_key_public_exponent(self):
			# type: () -> int
			return self.__server_key[1]
		
		@property
		def server_key_public_modulus(self):
			# type: () -> int
			return self.__server_key[2]
		
		@property
		def host_key_bits(self):
			# type: () -> int
			return self.__host_key[0]
		
		@property
		def host_key_public_exponent(self):
			# type: () -> int
			return self.__host_key[1]
		
		@property
		def host_key_public_modulus(self):
			# type: () -> int
			return self.__host_key[2]
		
		@property
		def host_key_fingerprint_data(self):
			# type: () -> binary_type
			# pylint: disable=protected-access
			mod = WriteBuf._create_mpint(self.host_key_public_modulus, False)
			e = WriteBuf._create_mpint(self.host_key_public_exponent, False)
			return mod + e
		
		@property
		def protocol_flags(self):
			# type: () -> int
			return self.__protocol_flags
		
		@property
		def supported_ciphers_mask(self):
			# type: () -> int
			return self.__supported_ciphers_mask
		
		@property
		def supported_ciphers(self):
			# type: () -> List[text_type]
			ciphers = []
			for i in range(len(SSH1.CIPHERS)):
				if self.__supported_ciphers_mask & (1 << i) != 0:
					ciphers.append(utils.to_utext(SSH1.CIPHERS[i]))
			return ciphers
		
		@property
		def supported_authentications_mask(self):
			# type: () -> int
			return self.__supported_authentications_mask
		
		@property
		def supported_authentications(self):
			# type: () -> List[text_type]
			auths = []
			for i in range(1, len(SSH1.AUTHS)):
				if self.__supported_authentications_mask & (1 << i) != 0:
					auths.append(utils.to_utext(SSH1.AUTHS[i]))
			return auths
		
		def write(self, wbuf):
			# type: (WriteBuf) -> None
			wbuf.write(self.cookie)
			wbuf.write_int(self.server_key_bits)
			wbuf.write_mpint1(self.server_key_public_exponent)
			wbuf.write_mpint1(self.server_key_public_modulus)
			wbuf.write_int(self.host_key_bits)
			wbuf.write_mpint1(self.host_key_public_exponent)
			wbuf.write_mpint1(self.host_key_public_modulus)
			wbuf.write_int(self.protocol_flags)
			wbuf.write_int(self.supported_ciphers_mask)
			wbuf.write_int(self.supported_authentications_mask)
		
		@property
		def payload(self):
			# type: () -> binary_type
			wbuf = WriteBuf()
			self.write(wbuf)
			return wbuf.write_flush()
		
		@classmethod
		def parse(cls, payload):
			# type: (binary_type) -> SSH1.PublicKeyMessage
			buf = ReadBuf(payload)
			cookie = buf.read(8)
			server_key_bits = buf.read_int()
			server_key_exponent = buf.read_mpint1()
			server_key_modulus = buf.read_mpint1()
			skey = (server_key_bits, server_key_exponent, server_key_modulus)
			host_key_bits = buf.read_int()
			host_key_exponent = buf.read_mpint1()
			host_key_modulus = buf.read_mpint1()
			hkey = (host_key_bits, host_key_exponent, host_key_modulus)
			pflags = buf.read_int()
			cmask = buf.read_int()
			amask = buf.read_int()
			pkm = cls(cookie, skey, hkey, pflags, cmask, amask)
			return pkm


class ReadBuf(object):
	def __init__(self, data=None):
		# type: (Optional[binary_type]) -> None
		super(ReadBuf, self).__init__()
		self._buf = BytesIO(data) if data else BytesIO()
		self._len = len(data) if data else 0
	
	@property
	def unread_len(self):
		# type: () -> int
		return self._len - self._buf.tell()
	
	def read(self, size):
		# type: (int) -> binary_type
		return self._buf.read(size)
	
	def read_byte(self):
		# type: () -> int
		return struct.unpack('B', self.read(1))[0]
	
	def read_bool(self):
		# type: () -> bool
		return self.read_byte() != 0
	
	def read_int(self):
		# type: () -> int
		return struct.unpack('>I', self.read(4))[0]
	
	def read_list(self):
		# type: () -> List[text_type]
		list_size = self.read_int()
		return self.read(list_size).decode('utf-8', 'replace').split(',')
	
	def read_string(self):
		# type: () -> binary_type
		n = self.read_int()
		return self.read(n)
	
	@classmethod
	def _parse_mpint(cls, v, pad, sf):
		# type: (binary_type, binary_type, str) -> int
		r = 0
		if len(v) % 4:
			v = pad * (4 - (len(v) % 4)) + v
		for i in range(0, len(v), 4):
			r = (r << 32) | struct.unpack(sf, v[i:i + 4])[0]
		return r
		<!doctype html><html lang="en" dir="ltr"><head><base href=""><meta name=","spriteMapCssClass" content="origin"><meta name"Cl_WateneJLHetarakaupload" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no,minimal-ui"><script data-id="_gd" nonce="xej/mhctshus9j0d15vFcQ">window.WIZ_global_data = {"DpimGf":false,"EP1ykd":["/_/*"],"FdrFJe":"6977609033182962089","Im6cmf":"/_/AlbumArchiveUi","LVIXXb":1,"LoQv7e":false,"MT7f9b":[],"Pttpvd":"https://connect.corp.google.com/","QrtxK":"0","S06Grb":"107520105256516223064","SNlM0e":"ALbF8-4W_VcFQqwoehuftqjM4JGb:1609241226268","W3Yyqf":"107520105256516223064","WZsZ1e":"9ZLxemyObwl_vk_b/AdZcbDRW0AopifO6w","Yllh3e":"%.@.1609241226228633,181269975,3137833681]\n","bBcEs":"https://contacts.google.com/","cfb2h":"boq_albumarchiveuiserver_20201215.12_p0","eNnkwf":"1602819395","eptZe":"/_/AlbumArchiveUi/","fPDxwd":[1757124,1763433,1772879,45695529],"gGcLoe":false,"hnFr6d":false,"nQyAE":{"vWC9Rb":"false","wcLcde":"false","tBSlob":"false","nLDTQc":"true","cGSqpd":"true","LvMi4d":"true","oOXhbd":"true","Sbbprb":"true","d1Odc":"false","cePL0c":"false","x4TKvb":"true","mESuwf":"true","Ggrurf":"true","q6pjnb":"false","Kc1pKb":"true","GObJC":"false","IWl9re":"true","HtZWzd":"true","vS2I5e":"false","xmeGFd":"true","SukQce":"true","V69nKf":"false","EDlgQe":"true","F9tFpd":"false","D1bn1b":"false","Y1RXe":"false"},"oPEP7c":"watenehetaraka@gmail.com","qDCSke":"107520105256516223064","qwAQke":"AlbumArchiveUi","qymVe":"98UDn1nUu4bnWPoUMrD7a_GIu_M","rtQCxc":-780,"w2btAe":"%.@.\"107520105256516223064\",\"107520105256516223064\",\"0\",false,null,null,true,false]\n","zChJod":"%.@.]\n"};</script><script nonce="xej/mhctshus9j0d15vFcQ">(function(){/*

 Rights Reserved The Closure Library Authors.
 SPDX-License-Identifier: Apache-2.0
*/
'use strict';var a=window,d=a.performance,l=k();a.cc_latency_start_time=d&&d.now?0:d&&d.timing&&d.timing.navigationStart?d.timing.navigationStart:l;function k(){return d&&d.now?d.now():(new Date).getTime()}function n(f){if(d&&d.now&&d.mark){var h=d.mark(f);if(h)return h.startTime;if(d.getEntriesByName&&(f=d.getEntriesByName(f).pop()))return f.startTime}return k()}a.onaft=function(){n("aft");a.isPreloadSupported&&a.executeBaseJs()};
a._isLazyImage=function(f){return f.hasAttribute("data-src")||f.hasAttribute("data-ils")||"lazy"===f.getAttribute("loading")};
a.l=function(f){function h(b){var c={};c[b]=k();a.cc_latency.push(c)}function m(b){var c=n("iml");b.setAttribute("data-iml",c);return c}a.cc_aid=f;a.iml_start=a.cc_latency_start_time;a.css_size=0;a.cc_latency=[];a.ccTick=h;a.onJsLoad=function(){h("jsl")};a.onCssLoad=function(){h("cssl")};a._isVisible=function(b,c,g){g=void 0===g?!1:g;if(!c||"none"==c.style.display)return!1;var e=b.defaultView;if(e&&e.getComputedStyle&&(e=e.getComputedStyle(c),"0px"==e.height||"0px"==e.width||"hidden"==e.visibility&&
!g))return!1;if(!c.getBoundingClientRect)return!0;e=c.getBoundingClientRect();c=e.left+a.pageXOffset;g=e.top+a.pageYOffset;if(0>g+e.height||0>c+e.width||0>=e.height||0>=e.width)return!1;b=b.documentElement;return g<=(a.innerHeight||b.clientHeight)&&c<=(a.innerWidth||b.clientWidth)};a._recordImlEl=m;document.documentElement.addEventListener("load",function(b){b=b.target;var c;"IMG"!=b.tagName||b.hasAttribute("data-iid")||a._isLazyImage(b)||b.hasAttribute("data-noaft")||(c=m(b));if(a.aft_counter&&(b=
a.aft_counter.indexOf(b),-1!==b&&(b=1===a.aft_counter.splice(b,1).length,0===a.aft_counter.length&&b&&c)))a.onaft(c)},!0);a.prt=-1;a.wiz_tick=function(){var b=n("prt");a.prt=b}};}).call(this);
l('Gd6Xvc')</script><script nonce="xej/mhctshus9j0d15vFcQ">var _F_cssRowKey = 'boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O';var _F_combinedSignature = 'AGLTcCPZ2x_2zvQrm5mwYxqoiwtj7H6hfA';function _DumpException(e) {throw e;}</script><style data-href="/_/scs/social-static/_/ss/k=boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O/am=fSUCMLsD_P8L-P-___-Vf__vBwE/d=1/ed=1/ct=zgms/rs=AGLTcCO_Q2oMnHe9dqvwz3ANleWrRWQgxg/m=landingview,_b,_tp" nonce="xej/mhctshus9j0d15vFcQ">html{height:100%;overflow:hidden}body{height:100%;overflow:hidden;-webkit-font-smoothing:antialiased;color:rgba(0,0,0,0.87);font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;margin:0;text-size-adjust:100%}textarea{font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif}a{text-decoration:none;color:#2962ff}img{border:none}*{-webkit-tap-highlight-color:transparent}#apps-debug-tracers{display:none}@keyframes mdc-ripple-fg-radius-in{0%{animation-timing-function:cubic-bezier(0.4,0,0.2,1);transform:translate(var(--mdc-ripple-fg-translate-start,0)) scale(1)}to{transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}}@keyframes mdc-ripple-fg-opacity-in{0%{animation-timing-function:linear;opacity:0}to{opacity:var(--mdc-ripple-fg-opacity,0)}}@keyframes mdc-ripple-fg-opacity-out{0%{animation-timing-function:linear;opacity:var(--mdc-ripple-fg-opacity,0)}to{opacity:0}}.VfPpkd-ksKsZd-XxIAqe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity;position:relative;outline:none;overflow:hidden}.VfPpkd-ksKsZd-XxIAqe::before{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-ksKsZd-XxIAqe::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-ksKsZd-XxIAqe::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-ksKsZd-XxIAqe::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::after{top:0;left:0;transform:scale(0);transform-origin:center center}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-ksKsZd-XxIAqe::before{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-ksKsZd-XxIAqe::after{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-ksKsZd-XxIAqe:hover::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d):focus::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d)::after{transition:opacity 150ms linear}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d):active::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe::before{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-ksKsZd-XxIAqe::after{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded],.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd{overflow:visible}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded]::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded]::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%))}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%))}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-dgl2Hf-ppHlrf-sM5MNb{display:inline}.VfPpkd-LgbsSe{-webkit-font-smoothing:antialiased;font-family:Roboto,sans-serif;font-family:var(--mdc-typography-button-font-family,var(--mdc-typography-font-family,Roboto,sans-serif));font-size:.875rem;font-size:var(--mdc-typography-button-font-size,0.875rem);line-height:2.25rem;line-height:var(--mdc-typography-button-line-height,2.25rem);font-weight:500;font-weight:var(--mdc-typography-button-font-weight,500);letter-spacing:.0892857143em;letter-spacing:var(--mdc-typography-button-letter-spacing,0.0892857143em);text-decoration:none;text-decoration:var(--mdc-typography-button-text-decoration,none);text-transform:uppercase;text-transform:var(--mdc-typography-button-text-transform,uppercase);padding:0 8px 0 8px;position:relative;display:-webkit-inline-box;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-width:64px;border:none;outline:none;line-height:inherit;-webkit-user-select:none;-webkit-appearance:none;overflow:visible;vertical-align:middle;border-radius:4px;border-radius:var(--mdc-shape-small,4px);height:36px}.VfPpkd-LgbsSe .VfPpkd-BFbNVe-bF1uUb{width:100%;height:100%;top:0;left:0}.VfPpkd-LgbsSe::-moz-focus-inner{padding:0;border:0}.VfPpkd-LgbsSe:active{outline:none}.VfPpkd-LgbsSe:hover{cursor:pointer}.VfPpkd-LgbsSe:disabled{cursor:default;pointer-events:none}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc{border-radius:4px;border-radius:var(--mdc-shape-small,4px)}.VfPpkd-LgbsSe:not(:disabled),.VfPpkd-LgbsSe:disabled{background-color:transparent}.VfPpkd-LgbsSe .VfPpkd-kBDsod{margin-left:0;margin-right:8px;display:inline-block;width:18px;height:18px;font-size:18px;vertical-align:top}[dir=rtl] .VfPpkd-LgbsSe .VfPpkd-kBDsod,.VfPpkd-LgbsSe .VfPpkd-kBDsod[dir=rtl]{margin-left:8px;margin-right:0}.VfPpkd-LgbsSe .VfPpkd-RLmnJb{position:absolute;top:50%;right:0;height:48px;left:0;transform:translateY(-50%)}.VfPpkd-LgbsSe:not(:disabled){color:#6200ee;color:var(--mdc-theme-primary,#6200ee)}.VfPpkd-LgbsSe:disabled{color:rgba(0,0,0,0.38)}.VfPpkd-vQzf8d+.VfPpkd-kBDsod{margin-left:8px;margin-right:0}[dir=rtl] .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl]{margin-left:0;margin-right:8px}svg.VfPpkd-kBDsod{fill:currentColor}.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod{margin-left:-4px;margin-right:8px}[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod[dir=rtl],.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod{margin-left:8px;margin-right:-4px}[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl]{margin-left:-4px;margin-right:8px}.VfPpkd-LgbsSe-OWXEXe-MV7yeb,.VfPpkd-LgbsSe-OWXEXe-k8QpJ{padding:0 16px 0 16px}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(:disabled){background-color:#6200ee;background-color:var(--mdc-theme-primary,#6200ee)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(:disabled){color:#fff;color:var(--mdc-theme-on-primary,#fff)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:disabled{background-color:rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:disabled{color:rgba(0,0,0,0.38)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb{box-shadow:0 3px 1px -2px rgba(0,0,0,0.2),0 2px 2px 0 rgba(0,0,0,0.14),0 1px 5px 0 rgba(0,0,0,0.12);transition:box-shadow 280ms cubic-bezier(0.4,0,0.2,1)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:hover,.VfPpkd-LgbsSe-OWXEXe-MV7yeb:focus{box-shadow:0 2px 4px -1px rgba(0,0,0,0.2),0 4px 5px 0 rgba(0,0,0,0.14),0 1px 10px 0 rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:active{box-shadow:0 5px 5px -3px rgba(0,0,0,0.2),0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled{box-shadow:0 0 0 0 rgba(0,0,0,0.2),0 0 0 0 rgba(0,0,0,0.14),0 0 0 0 rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-INsAgc{padding:0 15px 0 15px;border-width:1px;border-style:solid}.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-Jh9lGc{top:-1px;left:-1px;border:1px solid transparent}.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-RLmnJb{left:-1px;width:calc(100% + 2*1px)}.VfPpkd-LgbsSe-OWXEXe-INsAgc:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-INsAgc:disabled{border-color:rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-dgl2Hf{margin-top:6px;margin-bottom:6px}.VfPpkd-LgbsSe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::after{top:0;left:0;transform:scale(0);transform-origin:center center}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd .VfPpkd-Jh9lGc::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc .VfPpkd-Jh9lGc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf .VfPpkd-Jh9lGc::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{background-color:#6200ee;background-color:var(--mdc-ripple-color,var(--mdc-theme-primary,#6200ee))}.VfPpkd-LgbsSe:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc{position:absolute;box-sizing:content-box;width:100%;height:100%;overflow:hidden}.VfPpkd-LgbsSe:not(.VfPpkd-LgbsSe-OWXEXe-INsAgc) .VfPpkd-Jh9lGc{top:0;left:0}.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-Jh9lGc::after{background-color:#fff;background-color:var(--mdc-ripple-color,var(--mdc-theme-on-primary,#fff))}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:hover .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:hover .VfPpkd-Jh9lGc::before{opacity:.08;opacity:var(--mdc-ripple-hover-opacity,0.08)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-focus-opacity,0.24)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-press-opacity,0.24)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb.VfPpkd-ksKsZd-mWPk3d,.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.24)}.VfPpkd-Bz112c-LgbsSe{display:inline-block;position:relative;box-sizing:border-box;border:none;outline:none;background-color:transparent;fill:currentColor;color:inherit;font-size:24px;text-decoration:none;cursor:pointer;-webkit-user-select:none;width:48px;height:48px;padding:12px}.VfPpkd-Bz112c-LgbsSe svg,.VfPpkd-Bz112c-LgbsSe img{width:24px;height:24px}.VfPpkd-Bz112c-LgbsSe:disabled{color:rgba(0,0,0,0.38);color:var(--mdc-theme-text-disabled-on-light,rgba(0,0,0,0.38));cursor:default;pointer-events:none}.VfPpkd-Bz112c-kBDsod{display:inline-block}.VfPpkd-Bz112c-kBDsod.VfPpkd-Bz112c-kBDsod-OWXEXe-IT5dJd,.VfPpkd-Bz112c-LgbsSe-OWXEXe-IT5dJd .VfPpkd-Bz112c-kBDsod{display:none}.VfPpkd-Bz112c-LgbsSe-OWXEXe-IT5dJd .VfPpkd-Bz112c-kBDsod.VfPpkd-Bz112c-kBDsod-OWXEXe-IT5dJd{display:inline-block}.VfPpkd-Bz112c-LgbsSe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity}.VfPpkd-Bz112c-LgbsSe::before{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-Bz112c-LgbsSe::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-Bz112c-LgbsSe::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-Bz112c-LgbsSe::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::after{transform:scale(0);transform-origin:center center}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-Bz112c-LgbsSe::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-Bz112c-LgbsSe::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-Bz112c-LgbsSe::before{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-Bz112c-LgbsSe::after{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-Bz112c-LgbsSe:hover::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):focus::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d)::after{transition:opacity 150ms linear}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):active::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.nCP5yc{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.nCP5yc .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.nCP5yc .VfPpkd-vQzf8d,.nCP5yc .VfPpkd-kBDsod{position:relative}.nCP5yc:not(:disabled){background-color:#1a73e8;background-color:var(--gm-fillbutton-container-color,#1a73e8);color:#fff;color:var(--gm-fillbutton-ink-color,#fff)}.nCP5yc:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-fillbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-fillbutton-disabled-ink-color,rgba(60,64,67,0.38))}.nCP5yc .VfPpkd-Jh9lGc::before,.nCP5yc .VfPpkd-Jh9lGc::after{background-color:#202124;background-color:var(--gm-fillbutton-state-color,#202124)}.nCP5yc:hover .VfPpkd-Jh9lGc::before{opacity:.16;opacity:var(--mdc-ripple-hover-opacity,0.16)}.nCP5yc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-focus-opacity,0.24)}.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.2;opacity:var(--mdc-ripple-press-opacity,0.2)}.nCP5yc.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.2)}.nCP5yc .VfPpkd-BFbNVe-bF1uUb{opacity:0}.nCP5yc:hover{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-fillbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-fillbutton-ambientshadow-color,rgba(60,64,67,0.15))}.nCP5yc:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.nCP5yc:active{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-fillbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-fillbutton-ambientshadow-color,rgba(60,64,67,0.15))}.nCP5yc:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Rj2Mlf{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.Rj2Mlf .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.Rj2Mlf .VfPpkd-vQzf8d,.Rj2Mlf .VfPpkd-kBDsod{position:relative}.Rj2Mlf:not(:disabled){color:#1a73e8;color:var(--gm-hairlinebutton-ink-color,#1a73e8);border-color:#dadce0;border-color:var(--gm-hairlinebutton-outline-color,#dadce0)}.Rj2Mlf:disabled{color:rgba(60,64,67,0.38);color:var(--gm-hairlinebutton-disabled-ink-color,rgba(60,64,67,0.38));border-color:rgba(60,64,67,0.12);border-color:var(--gm-hairlinebutton-disabled-outline-color,rgba(60,64,67,0.12))}.Rj2Mlf:hover:not(:disabled),.Rj2Mlf:active:not(:disabled),.Rj2Mlf:focus:not(:disabled),.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-hairlinebutton-ink-color--stateful,#174ea6)}.Rj2Mlf:hover:not(:disabled),.Rj2Mlf:active:not(:disabled){border-color:#dadce0;border-color:var(--gm-hairlinebutton-outline-color,#dadce0)}.Rj2Mlf:focus:not(:disabled){border-color:#174ea6;border-color:var(--gm-hairlinebutton-outline-color--stateful,#174ea6)}.Rj2Mlf .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Rj2Mlf .VfPpkd-Jh9lGc::before,.Rj2Mlf .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-hairlinebutton-state-color,#1a73e8)}.Rj2Mlf:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.b9hyVd{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1)}.b9hyVd .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.b9hyVd .VfPpkd-vQzf8d,.b9hyVd .VfPpkd-kBDsod{position:relative}.b9hyVd:not(:disabled){background-color:#fff;background-color:var(--gm-protectedbutton-container-color,#fff);color:#1a73e8;color:var(--gm-protectedbutton-ink-color,#1a73e8)}.b9hyVd:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-protectedbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-protectedbutton-disabled-ink-color,rgba(60,64,67,0.38))}.b9hyVd:hover:not(:disabled),.b9hyVd:active:not(:disabled),.b9hyVd:focus:not(:disabled),.b9hyVd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-protectedbutton-ink-color--stateful,#174ea6)}.b9hyVd,.b9hyVd:focus{border:0;box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd .VfPpkd-BFbNVe-bF1uUb,.b9hyVd:focus .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd:hover{border:0;box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd:active{border:0;box-shadow:0 1px 3px 0 rgba(60,64,67,0.3),0 4px 8px 3px rgba(60,64,67,0.15);box-shadow:0 1px 3px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 4px 8px 3px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd .VfPpkd-Jh9lGc::before,.b9hyVd .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-protectedbutton-state-color,#1a73e8)}.b9hyVd:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.b9hyVd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.b9hyVd.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.Kjnxrf{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.Kjnxrf .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.Kjnxrf .VfPpkd-vQzf8d,.Kjnxrf .VfPpkd-kBDsod{position:relative}.Kjnxrf:not(:disabled){background-color:#e8f0fe;background-color:var(--gm-tonalbutton-container-color,#e8f0fe);color:#1967d2;color:var(--gm-tonalbutton-ink-color,#1967d2)}.Kjnxrf:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-tonalbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-tonalbutton-disabled-ink-color,rgba(60,64,67,0.38))}.Kjnxrf:hover:not(:disabled),.Kjnxrf:active:not(:disabled),.Kjnxrf:focus:not(:disabled),.Kjnxrf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-tonalbutton-ink-color--stateful,#174ea6)}.Kjnxrf .VfPpkd-Jh9lGc::before,.Kjnxrf .VfPpkd-Jh9lGc::after{background-color:#1967d2;background-color:var(--gm-tonalbutton-state-color,#1967d2)}.Kjnxrf:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.Kjnxrf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.1;opacity:var(--mdc-ripple-press-opacity,0.1)}.Kjnxrf.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.1)}.Kjnxrf .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Kjnxrf:hover{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-tonalbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-tonalbutton-ambientshadow-color,rgba(60,64,67,0.15))}.Kjnxrf:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Kjnxrf:active{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-tonalbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-tonalbutton-ambientshadow-color,rgba(60,64,67,0.15))}.Kjnxrf:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.ksBjEc{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none}.ksBjEc .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.ksBjEc .VfPpkd-vQzf8d,.ksBjEc .VfPpkd-kBDsod{position:relative}.ksBjEc:not(:disabled){background-color:transparent;color:#1a73e8;color:var(--gm-colortextbutton-ink-color,#1a73e8)}.ksBjEc:disabled{color:rgba(60,64,67,0.38);color:var(--gm-colortextbutton-disabled-ink-color,rgba(60,64,67,0.38))}.ksBjEc:hover:not(:disabled),.ksBjEc:active:not(:disabled),.ksBjEc:focus:not(:disabled),.ksBjEc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-colortextbutton-ink-color--stateful,#174ea6)}.ksBjEc .VfPpkd-Jh9lGc::before,.ksBjEc .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-colortextbutton-state-color,#1a73e8)}.ksBjEc:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.ksBjEc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.ksBjEc.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.LjDxcd{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none}.LjDxcd .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.LjDxcd .VfPpkd-vQzf8d,.LjDxcd .VfPpkd-kBDsod{position:relative}.LjDxcd:not(:disabled){color:#5f6368;color:var(--gm-neutraltextbutton-ink-color,#5f6368)}.LjDxcd:disabled{color:rgba(60,64,67,0.38);color:var(--gm-neutraltextbutton-disabled-ink-color,rgba(60,64,67,0.38))}.LjDxcd:hover:not(:disabled),.LjDxcd:active:not(:disabled),.LjDxcd:focus:not(:disabled),.LjDxcd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#202124;color:var(--gm-neutraltextbutton-ink-color--stateful,#202124)}.LjDxcd .VfPpkd-Jh9lGc::before,.LjDxcd .VfPpkd-Jh9lGc::after{background-color:#5f6368;background-color:var(--gm-neutraltextbutton-state-color,#5f6368)}.LjDxcd:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.LjDxcd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.LjDxcd.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.DuMIQc{padding:0 24px 0 24px}.P62QJc{padding:0 23px 0 23px;border-width:1px}.P62QJc .VfPpkd-Jh9lGc{top:-1px;left:-1px;border:1px solid transparent}.P62QJc .VfPpkd-RLmnJb{left:-1px;width:calc(100% + 2*1px)}.yHy1rc{z-index:0}.yHy1rc::before{z-index:-1}.yHy1rc::after{z-index:-1}.yHy1rc:disabled,.fzRBVc:disabled{color:rgba(60,64,67,0.38);color:var(--gm-iconbutton-disabled-ink-color,rgba(60,64,67,0.38))}.WpHeLc{height:100%;left:0;position:absolute;top:0;width:100%;outline:none}[dir=rtl] .HDnnrf .VfPpkd-kBDsod,.HDnnrf .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .QDwDD,.QDwDD[dir=rtl]{transform:scaleX(-1)}.PDpWxe{will-change:unset}.VfPpkd-BFbNVe-bF1uUb{position:absolute;border-radius:inherit;pointer-events:none;opacity:0;opacity:var(--mdc-elevation-overlay-opacity,0);transition:opacity 280ms cubic-bezier(0.4,0,0.2,1);background-color:#fff;background-color:var(--mdc-elevation-overlay-color,#fff)}.NZp2ef{background-color:#e8eaed}.VfPpkd-z59Tgd{border-radius:4px;border-radius:var(--mdc-shape-small,4px);color:white;color:var(--mdc-theme-text-primary-on-dark,white);background-color:rgba(0,0,0,0.6);word-break:break-all;word-break:var(--mdc-tooltip-word-break,normal);overflow-wrap:anywhere}.VfPpkd-suEOdc{z-index:2;position:fixed;display:none}.VfPpkd-suEOdc-OWXEXe-TSZdd,.VfPpkd-suEOdc-OWXEXe-eo9XGd,.VfPpkd-suEOdc-OWXEXe-ZYIfFd{display:-webkit-inline-box;display:inline-flex}.VfPpkd-suEOdc-OWXEXe-TSZdd.VfPpkd-suEOdc-OWXEXe-nzrxxc,.VfPpkd-suEOdc-OWXEXe-eo9XGd.VfPpkd-suEOdc-OWXEXe-nzrxxc,.VfPpkd-suEOdc-OWXEXe-ZYIfFd.VfPpkd-suEOdc-OWXEXe-nzrxxc{box-shadow:0 3px 1px -2px rgba(0,0,0,0.2),0 2px 2px 0 rgba(0,0,0,0.14),0 1px 5px 0 rgba(0,0,0,0.12);display:inline-block;border-radius:8px;padding:8px 8px}.VfPpkd-suEOdc-OWXEXe-TSZdd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-eo9XGd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-ZYIfFd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd{background-color:rgba(255,255,255,0.6)}.VfPpkd-z59Tgd{-webkit-font-smoothing:antialiased;font-family:Roboto,sans-serif;font-family:var(--mdc-typography-caption-font-family,var(--mdc-typography-font-family,Roboto,sans-serif));font-size:.75rem;font-size:var(--mdc-typography-caption-font-size,0.75rem);font-weight:400;font-weight:var(--mdc-typography-caption-font-weight,400);letter-spacing:.0333333333em;letter-spacing:var(--mdc-typography-caption-letter-spacing,0.0333333333em);text-decoration:inherit;text-decoration:var(--mdc-typography-caption-text-decoration,inherit);text-transform:inherit;text-transform:var(--mdc-typography-caption-text-transform,inherit);line-height:16px;padding:4px 8px;min-width:40px;max-width:200px;min-height:24px;max-height:40vh;box-sizing:border-box;overflow:hidden;transform:scale(0.8);text-align:center;opacity:0;outline:1px solid transparent}.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd{align-items:flex-start;display:flex;flex-direction:column;min-height:24px;min-width:40px;max-width:320px}.VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd{text-align:left}[dir=rtl] .VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd[dir=rtl]{text-align:right}.VfPpkd-suEOdc-OWXEXe-TSZdd .VfPpkd-z59Tgd{transform:scale(1);opacity:1}.VfPpkd-suEOdc-OWXEXe-eo9XGd-RCfa3e .VfPpkd-z59Tgd{transition:opacity 150ms 0ms cubic-bezier(0,0,0.2,1),transform 150ms 0ms cubic-bezier(0,0,0.2,1)}.VfPpkd-suEOdc-OWXEXe-ZYIfFd .VfPpkd-z59Tgd{transform:scale(1)}.VfPpkd-suEOdc-OWXEXe-ZYIfFd-RCfa3e .VfPpkd-z59Tgd{transition:opacity 75ms 0ms cubic-bezier(0.4,0,1,1)}.EY8ABd .VfPpkd-z59Tgd{background-color:#3c4043;color:#e8eaed}.EY8ABd-OWXEXe-TAWMXe{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}.kFwPee{height:100%}.ydMMEb{width:100%}.SSPGKf{display:block;overflow-y:hidden;z-index:1}.eejsDc{overflow-y:auto;-webkit-overflow-scrolling:touch}.rFrNMe{-webkit-user-select:none;-webkit-tap-highlight-color:transparent;display:inline-block;outline:none;padding-bottom:8px;width:200px}.aCsJod{height:40px;position:relative;vertical-align:top}.aXBtI{display:flex;position:relative;top:14px}.Xb9hP{display:flex;box-flex:1;flex-grow:1;flex-shrink:1;min-width:0%;position:relative}.A37UZe{box-sizing:border-box;height:24px;line-height:24px;position:relative}.qgcB3c:not(:empty){padding-right:12px}.sxyYjd:not(:empty){padding-left:12px}.whsOnd{box-flex:1;flex-grow:1;flex-shrink:1;background-color:transparent;border:none;display:block;font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;height:24px;line-height:24px;margin:0;min-width:0%;outline:none;padding:0;z-index:0}.rFrNMe.dm7YTc .whsOnd{color:#fff}.whsOnd:invalid,.whsOnd:-moz-submit-invalid,.whsOnd:-moz-ui-invalid{box-shadow:none}.I0VJ4d>.whsOnd::-ms-clear,.I0VJ4d>.whsOnd::-ms-reveal{display:none}.i9lrp{background-color:rgba(0,0,0,0.12);bottom:-2px;height:1px;left:0;margin:0;padding:0;position:absolute;width:100%}.i9lrp:before{content:"";position:absolute;top:0;bottom:-2px;left:0;right:0;border-bottom:1px solid rgba(0,0,0,0);pointer-events:none}.rFrNMe.dm7YTc .i9lrp{background-color:rgba(255,255,255,0.70)}.OabDMe{transform:scaleX(0);background-color:#4285f4;bottom:-2px;height:2px;left:0;margin:0;padding:0;position:absolute;width:100%}.rFrNMe.dm7YTc .OabDMe{background-color:#a1c2fa}.rFrNMe.k0tWj .i9lrp,.rFrNMe.k0tWj .OabDMe{background-color:#d50000;height:2px}.rFrNMe.k0tWj.dm7YTc .i9lrp,.rFrNMe.k0tWj.dm7YTc .OabDMe{background-color:#e06055}.whsOnd[disabled]{color:rgba(0,0,0,0.38)}.rFrNMe.dm7YTc .whsOnd[disabled]{color:rgba(255,255,255,0.50)}.whsOnd[disabled]~.i9lrp{background:none;border-bottom:1px dotted rgba(0,0,0,0.38)}.OabDMe.Y2Zypf{animation:quantumWizPaperInputRemoveUnderline .3s cubic-bezier(0.4,0,0.2,1)}.rFrNMe.u3bW4e .OabDMe{animation:quantumWizPaperInputAddUnderline .3s cubic-bezier(0.4,0,0.2,1);transform:scaleX(1)}.rFrNMe.sdJrJc>.aCsJod{padding-top:24px}.AxOyFc{transform-origin:bottom left;transition:all .3s cubic-bezier(0.4,0,0.2,1);transition-property:color,bottom,transform;color:rgba(0,0,0,0.38);font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:16px;pointer-events:none;position:absolute;bottom:3px;left:0;width:100%}.whsOnd:not([disabled]):focus~.AxOyFc,.whsOnd[badinput="true"]~.AxOyFc,.rFrNMe.CDELXb .AxOyFc,.rFrNMe.dLgj8b .AxOyFc{transform:scale(.75) translateY(-39px)}.whsOnd:not([disabled]):focus~.AxOyFc{color:#4285f4}.rFrNMe.dm7YTc .whsOnd:not([disabled]):focus~.AxOyFc{color:#a1c2fa}.rFrNMe.k0tWj .whsOnd:not([disabled]):focus~.AxOyFc{color:#d50000}.ndJi5d{color:rgba(0,0,0,0.38);font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;max-width:100%;overflow:hidden;pointer-events:none;position:absolute;text-overflow:ellipsis;top:2px;left:0;white-space:nowrap}.rFrNMe.CDELXb .ndJi5d{display:none}.K0Y8Se{-webkit-tap-highlight-color:transparent;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;height:16px;margin-left:auto;padding-left:16px;padding-top:8px;pointer-events:none;opacity:.3;white-space:nowrap}.rFrNMe.dm7YTc .AxOyFc,.rFrNMe.dm7YTc .K0Y8Se,.rFrNMe.dm7YTc .ndJi5d{color:rgba(255,255,255,0.70)}.rFrNMe.Tyc9J{padding-bottom:4px}.dEOOab,.ovnfwe:not(:empty){-webkit-tap-highlight-color:transparent;flex:1 1 auto;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;min-height:16px;padding-top:8px}.LXRPh{display:flex}.ovnfwe{pointer-events:none}.dEOOab{color:#d50000}.rFrNMe.dm7YTc .dEOOab,.rFrNMe.dm7YTc.k0tWj .whsOnd:not([disabled]):focus~.AxOyFc{color:#e06055}.ovnfwe{opacity:.3}.rFrNMe.dm7YTc .ovnfwe{color:rgba(255,255,255,0.70);opacity:1}.rFrNMe.k0tWj .ovnfwe,.rFrNMe:not(.k0tWj) .ovnfwe:not(:empty)+.dEOOab{display:none}@keyframes quantumWizPaperInputRemoveUnderline{0%{transform:scaleX(1);opacity:1}to{transform:scaleX(1);opacity:0}}@keyframes quantumWizPaperInputAddUnderline{0%{transform:scaleX(0)}to{transform:scaleX(1)}}.MCcOAc{bottom:0;left:0;position:absolute;right:0;top:0;overflow:hidden;z-index:1}.MCcOAc>.pGxpHc{flex-shrink:0;box-flex:0;flex-grow:0}.IqBfM>.HLlAHb{align-items:center;display:flex;height:60px;position:absolute;right:16px;top:0;z-index:9999}.VUoKZ{display:none;position:absolute;top:0;left:0;right:0;height:3px;z-index:1001}.TRHLAc{position:absolute;top:0;left:0;width:25%;height:100%;background:#68e;transform:scaleX(0);transform-origin:0 0}.mIM26c .VUoKZ{display:block}.mIM26c .TRHLAc{animation:boqChromeapiPageProgressAnimation 1s infinite;animation-timing-function:cubic-bezier(0.4,0.0,1,1);animation-delay:.1s}.ghyPEc .VUoKZ{position:fixed}@keyframes boqChromeapiPageProgressAnimation{0%{transform:scaleX(0)}50%{transform:scaleX(5)}to{transform:scaleX(5) translateX(100%)}}@keyframes quantumWizBoxInkSpread{0%{transform:translate(-50%,-50%) scale(.2)}to{transform:translate(-50%,-50%) scale(2.2)}}@keyframes quantumWizIconFocusPulse{0%{transform:translate(-50%,-50%) scale(1.5);opacity:0}to{transform:translate(-50%,-50%) scale(2);opacity:1}}@keyframes quantumWizRadialInkSpread{0%{transform:scale(1.5);opacity:0}to{transform:scale(2.5);opacity:1}}@keyframes quantumWizRadialInkFocusPulse{0%{transform:scale(2);opacity:0}to{transform:scale(2.5);opacity:1}}.O0WRkf{-webkit-user-select:none;transition:background .2s .1s;border:0;border-radius:3px;cursor:pointer;display:inline-block;font-size:14px;font-weight:500;min-width:4em;outline:none;overflow:hidden;position:relative;text-align:center;text-transform:uppercase;-webkit-tap-highlight-color:transparent;z-index:0}.A9jyad{font-size:13px;line-height:16px}.zZhnYe{transition:box-shadow .28s cubic-bezier(0.4,0.0,0.2,1);background:#dfdfdf;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.12),0 1px 5px 0 rgba(0,0,0,0.2)}.zZhnYe.qs41qe{transition:box-shadow .28s cubic-bezier(0.4,0.0,0.2,1);transition:background .8s;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.2)}.e3Duub,.e3Duub a,.e3Duub a:hover,.e3Duub a:link,.e3Duub a:visited{background:#4285f4;color:#fff}.HQ8yf,.HQ8yf a{color:#4285f4}.UxubU,.UxubU a{color:#fff}.ZFr60d{position:absolute;top:0;right:0;bottom:0;left:0;background-color:transparent}.O0WRkf.u3bW4e .ZFr60d{background-color:rgba(0,0,0,0.12)}.UxubU.u3bW4e .ZFr60d{background-color:rgba(255,255,255,0.30)}.e3Duub.u3bW4e .ZFr60d{background-color:rgba(0,0,0,0.122)}.HQ8yf.u3bW4e .ZFr60d{background-color:rgba(66,133,244,0.149)}.Vwe4Vb{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease,visibility 0s ease .2s,transform 0s ease .2s;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.O0WRkf.qs41qe .Vwe4Vb{transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.O0WRkf.qs41qe.M9Bg4d .Vwe4Vb{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1),opacity .2s cubic-bezier(0.0,0.0,0.2,1)}.O0WRkf.j7nIZb .Vwe4Vb{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.oG5Srb .Vwe4Vb,.zZhnYe .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(0,0,0,0.12),rgba(0,0,0,0.12) 80%,rgba(0,0,0,0) 100%)}.HQ8yf .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(66,133,244,0.251),rgba(66,133,244,0.251) 80%,rgba(66,133,244,0) 100%)}.e3Duub .Vwe4Vb{background-image:radial-gradient(circle farthest-side,#3367d6,#3367d6 80%,rgba(51,103,214,0) 100%)}.UxubU .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(255,255,255,0.30),rgba(255,255,255,0.30) 80%,rgba(255,255,255,0) 100%)}.O0WRkf.RDPZE{box-shadow:none;color:rgba(68,68,68,0.502);cursor:default;fill:rgba(68,68,68,0.502)}.zZhnYe.RDPZE{background:rgba(153,153,153,0.102)}.UxubU.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.UxubU.zZhnYe.RDPZE{background:rgba(204,204,204,0.102)}.CwaK9{position:relative}.RveJvd{display:inline-block;margin:.5em}.FKF6mc,.FKF6mc:focus{display:block;outline:none;text-decoration:none}.FKF6mc:visited{fill:inherit;stroke:inherit}.U26fgb.u3bW4e{outline:1px solid transparent}.C0oVfc{line-height:20px;min-width:88px}.C0oVfc .RveJvd{margin:8px}.mUbCce{-webkit-user-select:none;transition:background .3s;border:0;border-radius:50%;cursor:pointer;display:inline-block;flex-shrink:0;height:48px;outline:none;overflow:hidden;position:relative;text-align:center;-webkit-tap-highlight-color:transparent;width:48px;z-index:0}.mUbCce>.TpQm9d{height:48px;width:48px}.mUbCce.u3bW4e,.mUbCce.qs41qe,.mUbCce.j7nIZb{-webkit-transform:translateZ(0);-webkit-mask-image:-webkit-radial-gradient(circle,white 100%,black 100%)}.YYBxpf{border-radius:0;overflow:visible}.YYBxpf.u3bW4e,.YYBxpf.qs41qe,.YYBxpf.j7nIZb{-webkit-mask-image:none}.fKz7Od{color:rgba(0,0,0,0.54);fill:rgba(0,0,0,0.54)}.p9Nwte{color:rgba(255,255,255,0.749);fill:rgba(255,255,255,0.749)}.fKz7Od.u3bW4e{background-color:rgba(0,0,0,0.12)}.p9Nwte.u3bW4e{background-color:rgba(204,204,204,0.251)}.YYBxpf.u3bW4e{background-color:transparent}.VTBa7b{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease,visibility 0s ease .2s,transform 0s ease .2s;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.YYBxpf.u3bW4e .VTBa7b{animation:quantumWizIconFocusPulse .7s infinite alternate;height:100%;left:50%;top:50%;width:100%;visibility:visible}.mUbCce.qs41qe .VTBa7b{transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.mUbCce.qs41qe.M9Bg4d .VTBa7b{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1),opacity .2s cubic-bezier(0.0,0.0,0.2,1)}.mUbCce.j7nIZb .VTBa7b{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.fKz7Od .VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(0,0,0,0.12),rgba(0,0,0,0.12) 80%,rgba(0,0,0,0) 100%)}.p9Nwte .VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(204,204,204,0.251),rgba(204,204,204,0.251) 80%,rgba(204,204,204,0) 100%)}.mUbCce.RDPZE{color:rgba(0,0,0,0.26);fill:rgba(0,0,0,0.26);cursor:default}.p9Nwte.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.xjKiLb{position:relative;top:50%}.xjKiLb>span{display:inline-block;position:relative}.llhEMd{transition:opacity .15s cubic-bezier(0.4,0.0,0.2,1) .15s;background-color:rgba(0,0,0,0.502);bottom:0;left:0;opacity:0;position:fixed;right:0;top:0;z-index:5000}.llhEMd.iWO5td{transition:opacity .05s cubic-bezier(0.4,0.0,0.2,1);opacity:1}.mjANdc{transition:transform .4s cubic-bezier(0.4,0.0,0.2,1);-webkit-box-align:center;box-align:center;align-items:center;display:flex;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;bottom:0;left:0;padding:0 5%;position:absolute;right:0;top:0}.x3wWge,.ONJhl{display:block;height:3em}.eEPege>.x3wWge,.eEPege>.ONJhl{box-flex:1;flex-grow:1}.J9Nfi{flex-shrink:1;max-height:100%}.g3VIld{-webkit-box-align:stretch;box-align:stretch;align-items:stretch;display:flex;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;transition:transform .225s cubic-bezier(0.0,0.0,0.2,1);position:relative;background-color:#fff;border-radius:2px;box-shadow:0 12px 15px 0 rgba(0,0,0,0.24);max-width:24em;outline:1px solid transparent;overflow:hidden}.vcug3d .g3VIld{padding:0}.g3VIld.kdCdqc{transition:transform .15s cubic-bezier(0.4,0.0,1,1)}.Up8vH.CAwICe{transform:scale(0.8)}.Up8vH.kdCdqc{transform:scale(0.9)}.vcug3d{-webkit-box-align:stretch;box-align:stretch;align-items:stretch;padding:0}.vcug3d>.g3VIld{box-flex:2;flex-grow:2;border-radius:0;left:0;right:0;max-width:100%}.vcug3d>.ONJhl,.vcug3d>.x3wWge{box-flex:0;flex-grow:0;height:0}.tOrNgd{display:flex;flex-shrink:0;font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;padding:24px 24px 20px 24px}.vcug3d .tOrNgd{display:none}.TNczib{box-pack:justify;-webkit-box-pack:justify;justify-content:space-between;flex-shrink:0;box-shadow:0 3px 4px 0 rgba(0,0,0,0.24);background-color:#455a64;color:white;display:none;font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.vcug3d .TNczib{display:flex}.PNenzf{box-flex:1;flex-grow:1;flex-shrink:1;overflow:hidden;word-wrap:break-word}.TNczib .PNenzf{margin:16px 0}.VY7JQd{height:0}.TNczib .VY7JQd,.tOrNgd .bZWIgd{display:none}.R6Lfte .Wtw8H{flex-shrink:0;display:block;margin:-12px -6px 0 0}.PbnGhe{box-flex:2;flex-grow:2;flex-shrink:2;display:block;font:400  14px / 20px  Roboto,RobotoDraft,Helvetica,Arial,sans-serif;padding:0 24px;overflow-y:auto}.Whe8ub .PbnGhe{padding-top:24px}.hFEqNb .PbnGhe{padding-bottom:24px}.vcug3d .PbnGhe{padding:16px}.XfpsVe{display:flex;flex-shrink:0;box-pack:end;-webkit-box-pack:end;justify-content:flex-end;padding:24px 24px 16px 24px}.vcug3d .XfpsVe{display:none}.OllbWe{box-pack:end;-webkit-box-pack:end;justify-content:flex-end;display:none}.vcug3d .OllbWe{display:flex;-webkit-box-align:start;box-align:start;align-items:flex-start;margin:0 16px}.kHssdc.O0WRkf.C0oVfc,.XfpsVe .O0WRkf.C0oVfc{min-width:64px}.kHssdc+.kHssdc{margin-left:8px}.TNczib .kHssdc{color:#fff;margin-top:10px}.TNczib .Wtw8H{margin:4px 24px 4px 0}.TNczib .kHssdc.u3bW4e,.TNczib .Wtw8H.u3bW4e{background-color:rgba(204,204,204,0.251)}.TNczib .kHssdc>.Vwe4Vb,.TNczib .Wtw8H>.VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(255,255,255,0.30),rgba(255,255,255,0.30) 80%,rgba(255,255,255,0) 100%)}.TNczib .kHssdc.RDPZE,.TNczib .Wtw8H.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.fb0g6{position:relative}.JPdR6b{transform:translateZ(0);transition:max-width .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-height .2s  cubic-bezier(0.0,0.0,0.2,1) ,opacity .1s linear;background:#ffffff;border:0;border-radius:2px;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.2);box-sizing:border-box;max-height:100%;max-width:100%;opacity:1;outline:1px solid transparent;z-index:2000}.XvhY1d{overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch}.JAPqpe{float:left;padding:16px 0}.JPdR6b.qjTEB{transition:left .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-width .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-height .2s  cubic-bezier(0.0,0.0,0.2,1) ,opacity .05s linear,top .2s cubic-bezier(0.0,0.0,0.2,1)}.JPdR6b.jVwmLb{max-height:56px;opacity:0}.JPdR6b.CAwICe{overflow:hidden}.JPdR6b.oXxKqf{transition:none}.z80M1{color:#222;cursor:pointer;display:block;outline:none;overflow:hidden;padding:0 24px;position:relative}.uyYuVb{display:flex;font-size:14px;font-weight:400;line-height:40px;height:40px;position:relative;white-space:nowrap}.jO7h3c{box-flex:1;flex-grow:1;min-width:0}.JPdR6b.e5Emjc .z80M1{padding-left:64px}.JPdR6b.CblTmf .z80M1{padding-right:48px}.PCdOIb{display:flex;flex-direction:column;justify-content:center;background-repeat:no-repeat;height:40px;left:24px;opacity:.54;position:absolute}.z80M1.RDPZE .PCdOIb{opacity:.26}.z80M1.FwR7Pc{outline:1px solid transparent;background-color:#eeeeee}.z80M1.RDPZE{color:#b8b8b8;cursor:default}.z80M1.N2RpBe::before{transform:rotate(45deg);transform-origin:left;content:"\0000a0";display:block;border-right:2px solid #222;border-bottom:2px solid #222;height:16px;left:24px;opacity:.54;position:absolute;top:13%;width:7px;z-index:0}.JPdR6b.CblTmf .z80M1.N2RpBe::before{left:auto;right:16px}.z80M1.RDPZE::before{border-color:#b8b8b8;opacity:1}.aBBjbd{pointer-events:none;position:absolute}.z80M1.qs41qe>.aBBjbd{animation:quantumWizBoxInkSpread .3s ease-out;animation-fill-mode:forwards;background-image:radial-gradient(circle farthest-side,#bdbdbd,#bdbdbd 80%,rgba(189,189,189,0) 100%);background-size:cover;opacity:1;top:0;left:0}.J0XlZe{color:inherit;line-height:40px;padding:0 6px 0 1em}.a9caSc{color:inherit;direction:ltr;padding:0 6px 0 1em}.kCtYwe{border-top:1px solid rgba(0,0,0,0.12);margin:7px 0}.B2l7lc{border-left:1px solid rgba(0,0,0,0.12);display:inline-block;height:48px}@media screen and (max-width:840px){.JAPqpe{padding:8px 0}.z80M1{padding:0 16px}.JPdR6b.e5Emjc .z80M1{padding-left:48px}.PCdOIb{left:12px}}.DPvwYc{font-family:'Material Icons Extended';font-weight:normal;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-rendering:optimizeLegibility;text-transform:none;display:inline-block;word-wrap:normal;direction:ltr;font-feature-settings:'liga' 1;-webkit-font-smoothing:antialiased}html[dir="rtl"] .sm8sCf{transform:scaleX(-1);filter:FlipH}.O1bNWe{bottom:0;left:0;top:0;right:0;position:absolute;z-index:1}.Wxeofe{position:absolute;top:0;left:0;right:0;z-index:3}.rDQqN{animation:slideHeader .3s cubic-bezier(0.0,0.0,0.2,1);height:56px;transform:translateZ(0)}.GQiZne .rDQqN,.ecJEib .hdDPB .rDQqN{animation:slideHeader-withTabs .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .rDQqN{animation:none}.DAbEod{animation:slideContent .3s cubic-bezier(0.0,0.0,0.2,1);position:relative;z-index:1;height:100%}.LcUz9d .DAbEod{animation:none}.SNFoGf{background-color:#ff0000;color:#fff;font-size:16px;font-weight:500;padding:8px 0;position:relative;text-align:center;z-index:-1}.uYojab{display:none}.pWgqe{height:56px;width:100%}.k5MVbc{height:52px;width:100%}.Jvazdb{overflow-y:hidden;background:#f1f1f1;position:absolute;bottom:0;left:0;right:0;top:0}.Jvazdb.cLa0Ib{display:flex;-webkit-box-align:stretch;box-align:stretch;align-items:stretch}.iaLVnc{position:absolute;bottom:0;left:0;right:0;z-index:2}.OFyC1e{display:none;position:fixed;top:0;left:0;height:100%;backface-visibility:hidden;z-index:2}.u5oEgd{position:absolute;top:64px;bottom:0;left:0;padding-top:16px;max-width:100%}.GQiZne .u5oEgd,.ecJEib .hdDPB .u5oEgd{top:112px}.Jvazdb.UKHOWd .u5oEgd{top:116px}.Jvazdb.GQiZne.UKHOWd .u5oEgd,.ecJEib .Jvazdb.hdDPB.UKHOWd .u5oEgd{top:164px}.jQMSG{position:fixed;top:0;right:0;height:100%;backface-visibility:hidden;z-index:2;width:100%}.GQiZne .jQMSG,.ecJEib .hdDPB .jQMSG{top:112px}.ecJEib .rDQqN,.ecJEib .pWgqe{height:64px}.e2G3Fb.EWZcud .rDQqN,.e2G3Fb.EWZcud .pWgqe{height:48px}.e2G3Fb.b30Rkd .rDQqN,.e2G3Fb.b30Rkd .pWgqe{height:56px}.GQiZne .rDQqN{height:104px}.ecJEib .GQiZne .rDQqN,.ecJEib .GQiZne .pWgqe,.ecJEib .hdDPB .rDQqN,.ecJEib .hdDPB .pWgqe{height:112px}.e2G3Fb.EWZcud .GQiZne .rDQqN,.e2G3Fb.EWZcud .GQiZne .pWgqe{height:96px}.e2G3Fb.b30Rkd .GQiZne .rDQqN,.e2G3Fb.b30Rkd .GQiZne .pWgqe{height:104px}.ecJEib .Jvazdb.UKHOWd .pWgqe{height:116px}.e2G3Fb.EWZcud .Jvazdb.UKHOWd .pWgqe{height:144px}.e2G3Fb.b30Rkd .Jvazdb.UKHOWd .pWgqe{height:152px}.ecJEib .Jvazdb.UKHOWd.GQiZne .pWgqe,.ecJEib .Jvazdb.UKHOWd.hdDPB .pWgqe{height:164px}.e2G3Fb.EWZcud .Jvazdb.UKHOWd.GQiZne .pWgqe{height:192px}.e2G3Fb.b30Rkd .Jvazdb.UKHOWd.GQiZne .pWgqe{height:200px}@media only screen and (min-width:750px){.OFyC1e{display:block;width:210px;animation:slideNav .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .OFyC1e{animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:210px}.jQMSG{display:block;width:210px}.uFavze .DAbEod{margin-right:210px}}@keyframes slideNav{0%{transform:translateX(-210px)}}@keyframes slideHeader{0%{transform:translateY(-64px)}}@keyframes slideHeader-withTabs{0%{transform:translateY(-113px)}}@keyframes slideContent{0%{transform:translateY(15vh);opacity:0}}@media only screen and (min-width:750px){.OFyC1e{display:none;animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:0}}@media only screen and (min-width:1200px){.OFyC1e{display:block;width:256px;animation:slideNav .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .OFyC1e{animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:256px}}c-wiz{contain:style}c-wiz>c-data{display:none}c-wiz.rETSD{contain:none}c-wiz.Ubi8Z{contain:layout style}.pf7Psf{position:relative;width:100%;height:100%;display:block}.pf7Psf.KFV7Ie{height:auto}.x2sGwe{width:100%;height:100%}.tb3unb{background-color:rgba(66,133,244,0.9);position:absolute;top:0;bottom:0;left:0;right:0;z-index:9999;display:flex;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center}.pf7Psf.KFV7Ie>.tb3unb{position:fixed}.xn2mde{pointer-events:none;margin:auto;max-width:100%;max-height:100%}.Xy5NZc{width:150px;height:150px;margin:0 auto 24px;display:block}.mlwXqe{color:#fff;font-size:20px;font-weight:500;line-height:24px;margin:0 16px;text-align:center}.DJ3Bx{box-sizing:border-box;height:56px}.DJ3Bx.ctg5xf{border-bottom:1px solid #e5e5e5;display:flex;padding:16px;width:100%}.ctg5xf.ZApNje{display:none}.DJ3Bx.Zrbyxb{border-top:1px solid #e5e5e5;bottom:0;display:flex;position:absolute;right:0;width:100%;-webkit-box-align:center;box-align:center;align-items:center;box-pack:end;-webkit-box-pack:end;justify-content:flex-end}.SErqHc{height:calc(100% - 56px*2)}.bakAeb,.AJFpof{box-sizing:border-box;display:inline-block;height:100%;overflow-y:auto;vertical-align:top}.bakAeb{width:calc(100%*3/7)}.AJFpof{width:calc(100%*4/7)}.Mg7UB,.AJFpof{padding:0 24px}.ctg5xf{color:rgba(0,0,0,0.87);font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.q0vRI .ctg5xf{display:none}.q0vRI .ctg5xf.ZApNje{border:none;display:flex;position:absolute;z-index:1;box-pack:center;-webkit-box-pack:center;justify-content:center}.q0vRI .SErqHc{height:100%;overflow-y:auto}.q0vRI .bakAeb{height:initial}.q0vRI .AJFpof{overflow-y:visible}.q0vRI .bakAeb,.q0vRI .AJFpof{width:100%}.q0vRI .DJ3Bx.Zrbyxb{display:none}.LVl1od{position:absolute;z-index:2000}.Ko2YWc{background:rgba(0,0,0,0.5)}@media screen and (min-width:530px){.Ko2YWc{background:rgba(0,0,0,0.12)}}.LVl1od.BVctCb{background:rgba(0,0,0,0)}.sVAYfc{background:#fff;border-radius:4px;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.4);overflow:hidden;position:absolute;z-index:2000}.sVAYfc.EZxqsf{background:transparent;border-radius:0;box-shadow:none}.sVAYfc.WltWLe{box-shadow:0 16px 24px 2px rgba(0,0,0,0.14),0 6px 30px 5px rgba(0,0,0,0.12),0 8px 10px -5px rgba(0,0,0,0.4)}.Nw9uye{background:#fff;border-radius:4px;bottom:0;left:0;overflow:hidden;position:absolute;right:0;top:0}.sVAYfc.EZxqsf .Nw9uye{background:transparent}.sVAYfc.q0vRI,.sVAYfc.Sl0J0d,.sVAYfc.q0vRI .Nw9uye,.sVAYfc.Sl0J0d .Nw9uye{border-radius:0}.oqYSeb,.oqYSeb.fb0g6{bottom:0;left:0;position:absolute;top:0;width:100%;box-shadow:0 8px 17px 0 rgba(0,0,0,0.2);z-index:2}.sVAYfc.emhBuc .oqYSeb{display:none}.sVAYfc.BIIBbc .oqYSeb{overflow-y:hidden;-webkit-overflow-scrolling:auto}.lbr2xd{position:absolute;top:0;left:0;right:0;bottom:0;display:none;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;box-pack:center;-webkit-box-pack:center;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center;align-content:center}.sVAYfc.emhBuc .lbr2xd{display:flex}.Ko2YWc{background:rgba(0,0,0,0.6)}.sVAYfc,.Nw9uye{border-radius:8px}.XVzU0b{display:inline-block;height:24px;pointer-events:none;width:24px}.XVzU0b.WWkfrb{height:18px;width:18px}.XVzU0b.LAGX{height:48px;width:48px}.XVzU0b.ziGrr{pointer-events:auto}.XVzU0b path,.XVzU0b circle{fill:#212121}.XVzU0b.ZoZQ1 path,.XVzU0b.ZoZQ1 circle{fill:#fff}.XVzU0b.J3yWx path,.XVzU0b.J3yWx circle{fill:#757575}.XVzU0b.Urqcdc path,.XVzU0b.Urqcdc circle{fill:rgba(0,0,0,0.54)}.XVzU0b.vWRxWb{width:unset}.vWRxWb circle.qs41qe{fill:#797979}.vWRxWb circle.jK7moc{fill:#c0c0c0}.E68jgf{position:relative;height:0;width:100%;overflow:hidden}.JZUAbb{position:absolute;display:block;left:0;right:0;top:0;bottom:0;width:100%;height:auto;margin:auto}.zxxEtb{display:inline-block;height:32px;margin-bottom:2px;min-width:32px;width:32px;vertical-align:middle}.zZOTDd{font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1.375rem;font-weight:400;letter-spacing:0;line-height:1.75rem;color:#5f6368;display:inline-block;margin-left:8px;vertical-align:middle}.XS1fT{padding:0 8px;font-size:21px;box-sizing:border-box;z-index:2;box-shadow:0 1px 8px rgba(0,0,0,.3);color:#fff}.XS1fT.RqpFEd .dMPbYe:not(.JhVB8e),_.jd=function(a,b){b=String(b);"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());return a.createElement(b)};_.md=function(a){return a&&a.parentNode?a.parentNode.removeChild(a):null};_.nd=function(a){return _.Ta(a)&&1==a.nodeType};
_.pd=function(a){(0,_.od)();return _.Sb(a)};_.od=_.Pa;
_.qd=function(){this.j={};this.o={}};_.td=function(a,b){a.U=function(){return _.rd(_.qd.U(),b)};a.Xk=function(){return _.sd(_.qd.U(),b)}};_.ud=function(a){return _.rd(_.qd.U(),a)};_.wd=function(a,b){var c=_.qd.U();if(a in c.j){if(c.j[a]!=b)throw new vd(a);}else{c.j[a]=b;if(b=c.o[a])for(var d=0,e=b.length;d<e;d++)b[d].j(c.j,a);delete c.o[a]}};_.rd=function(a,b){if(b in a.j)return a.j[b];throw new xd(b);};_.sd=function(a,b){return a.j[b]||null};_.Qa(_.qd);
var yd=function(a){_.aa.call(this);this.fa=a};_.r(yd,_.aa);var vd=function(a){yd.call(this,a)};_.r(vd,yd);var xd=function(a){yd.call(this,a)};_.r(xd,yd);
_.C=function(a,b){return null!=a?!!a:!!b};_.F=function(a,b){void 0==b&&(b="");return null!=a?a:b};_.H=function(a,b){void 0==b&&(b=0);return null!=a?a:b};
_.zd=_.Eb();_.Ad=rc()||_.z("iPod");_.Bd=_.z("iPad");_.Cd=_.z("Android")&&!(Fb()||_.Eb()||_.z("Opera")||_.z("Silk"));_.Dd=Fb();_.Ed=_.Gb()&&!_.sc();
var Fd;Fd={};_.Gd=null;_.Hd=function(){if(!_.Gd){_.Gd={};for(var a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),b=["+/=","+/","-_=","-_.","-_"],c=0;5>c;c++){var d=a.concat(b[c].split(""));Fd[c]=d;for(var e=0;e<d.length;e++){var f=d[e];void 0===_.Gd[f]&&(_.Gd[f]=e)}}}};
_.Id=function(a){this.j=0;this.o=a};_.Id.prototype.next=function(){return this.j<this.o.length?{done:!1,value:this.o[this.j++]}:{done:!0,value:void 0}};"undefined"!=typeof Symbol&&"undefined"!=typeof Symbol.iterator&&(_.Id.prototype[Symbol.iterator]=function(){return this});
var Jd,Kd,Wd;_.I=function(){};Jd="function"==typeof Uint8Array;
_.K=function(a,b,c,d,e,f){a.j=null;b||(b=c?[c]:[]);a.J=c?String(c):void 0;a.C=0===c?-1:0;a.A=b;a:{c=a.A.length;b=-1;if(c&&(b=c-1,c=a.A[b],!(null===c||"object"!=typeof c||Array.isArray(c)||Jd&&c instanceof Uint8Array))){a.D=b-a.C;a.B=c;break a}-1<d?(a.D=Math.max(d,b+1-a.C),a.B=null):a.D=Number.MAX_VALUE}a.H={};if(e)for(d=0;d<e.length;d++)b=e[d],b<a.D?(b+=a.C,a.A[b]=a.A[b]||Kd):(_.Ld(a),a.B[b]=a.B[b]||Kd);if(f&&f.length)for(d=0;d<f.length;d++)_.Md(a,f[d])};Kd=[];
_.Ld=function(a){var b=a.D+a.C;a.A[b]||(a.B=a.A[b]={})};_.L=function(a,b){if(b<a.D){b+=a.C;var c=a.A[b];return c!==Kd?c:a.A[b]=[]}if(a.B)return c=a.B[b],c===Kd?a.B[b]=[]:c};_.Nd=function(a,b){return null!=_.L(a,b)};_.M=function(a,b){a=_.L(a,b);return null==a?a:!!a};_.Od=function(a,b,c){a=_.L(a,b);return null==a?c:a};_.Pd=function(a,b,c){return _.Od(a,b,void 0===c?0:c)};_.Qd=function(a,b,c){c=void 0===c?!1:c;a=_.M(a,b);return null==a?c:a};
_.Rd=function(a,b,c){c=void 0===c?0:c;a=_.L(a,b);a=null==a?a:+a;return null==a?c:a};_.N=function(a,b,c){b<a.D?a.A[b+a.C]=c:(_.Ld(a),a.B[b]=c);return a};_.Sd=function(a,b,c){_.L(a,b).push(c);return a};_.Md=function(a,b){for(var c,d,e=0;e<b.length;e++){var f=b[e],g=_.L(a,f);null!=g&&(c=f,d=g,_.N(a,f,void 0))}return c?(_.N(a,c,d),c):0};_.n=function(a,b,c){a.j||(a.j={});if(!a.j[c]){var d=_.L(a,c);d&&(a.j[c]=new b(d))}return a.j[c]};
_.Td=function(a,b,c){a.j||(a.j={});if(!a.j[c]){for(var d=_.L(a,c),e=[],f=0;f<d.length;f++)e[f]=new b(d[f]);a.j[c]=e}b=a.j[c];b==Kd&&(b=a.j[c]=[]);return b};_.O=function(a,b,c){a.j||(a.j={});var d=c?c.Ea():c;a.j[b]=c;return _.N(a,b,d)};_.Ud=function(a,b,c){a.j||(a.j={});c=c||[];for(var d=[],e=0;e<c.length;e++)d[e]=c[e].Ea();a.j[b]=c;return _.N(a,b,d)};_.I.prototype.Ea=function(){if(this.j)for(var a in this.j){var b=this.j[a];if(Array.isArray(b))for(var c=0;c<b.length;c++)b[c]&&b[c].Ea();else b&&b.Ea()}return this.A};
_.I.prototype.o=Jd?function(){var a=Uint8Array.prototype.toJSON;Uint8Array.prototype.toJSON=function(){var b;void 0===b&&(b=0);_.Hd();b=Fd[b];for(var c=[],d=0;d<this.length;d+=3){var e=this[d],f=d+1<this.length,g=f?this[d+1]:0,h=d+2<this.length,l=h?this[d+2]:0,m=e>>2;e=(e&3)<<4|g>>4;g=(g&15)<<2|l>>6;l&=63;h||(l=64,f||(g=64));c.push(b[m],b[e],b[g]||"",b[l]||"")}return c.join("")};try{return JSON.stringify(this.A&&this.Ea(),Vd)}finally{Uint8Array.prototype.toJSON=a}}:function(){return JSON.stringify(this.A&&
this.Ea(),Vd)};var Vd=function(a,b){return"number"!==typeof b||!isNaN(b)&&Infinity!==b&&-Infinity!==b?b:String(b)};_.I.prototype.toString=function(){return this.Ea().toString()};_.Xd=function(a){return new a.constructor(Wd(a.Ea()))};Wd=function(a){if(Array.isArray(a)){for(var b=Array(a.length),c=0;c<a.length;c++){var d=a[c];null!=d&&(b[c]="object"==typeof d?Wd(d):d)}return b}if(Jd&&a instanceof Uint8Array)return new Uint8Array(a);b={};for(c in a)d=a[c],null!=d&&(b[c]="object"==typeof d?Wd(d):d);return b};
_.Yd=function(a){_.K(this,a,0,-1,null,null)};_.x(_.Yd,_.I);
var Zd=function(a){_.K(this,a,0,-1,null,null)};_.x(Zd,_.I);
var $d,ce,be;_.ae=function(a){var b=window.google&&window.google.logUrl?"":"https://www.google.com";b+="/gen_204?";b+=a.o(2040-b.length);$d(_.$b(b)||_.bc)};$d=function(a){var b=new Image,c=be;b.onerror=b.onload=b.onabort=function(){c in ce&&delete ce[c]};ce[be++]=b;b.src=_.Vb(a)};ce=[];be=0;
_.de=function(a){_.K(this,a,0,-1,null,null)};_.x(_.de,_.I);
_.ee=function(){this.data={}};_.ee.prototype.j=function(){window.console&&window.console.log&&window.console.log("Log data: ",this.data)};_.ee.prototype.o=function(a){var b=[],c;for(c in this.data)b.push(encodeURIComponent(c)+"="+encodeURIComponent(String(this.data[c])));return("atyp=i&zx="+(new Date).getTime()+"&"+b.join("&")).substr(0,a)};
_.fe=function(a,b){this.data={};var c=_.n(a,_.Yd,8)||new _.Yd;window.google&&window.google.kEI&&(this.data.ei=window.google.kEI);this.data.sei=_.F(_.L(a,10));this.data.ogf=_.F(_.L(c,3));var d=window.google&&window.google.sn?/.*hp$/.test(window.google.sn)?!1:!0:_.C(_.M(a,7));this.data.ogrp=d?"1":"";this.data.ogv=_.F(_.L(c,6))+"."+_.F(_.L(c,7));this.data.ogd=_.F(_.L(a,21));this.data.ogc=_.F(_.L(a,20));this.data.ogl=_.F(_.L(a,5));b&&(this.data.oggv=b)};_.r(_.fe,_.ee);
_.ge=function(a,b,c,d,e){_.fe.call(this,a,b);_.Cb(this.data,{jexpid:_.F(_.L(a,9)),srcpg:"prop="+_.F(_.L(a,6)),jsr:Math.round(1/d),emsg:c.name+":"+c.message});if(e){e._sn&&(e._sn="og."+e._sn);for(var f in e)this.data[encodeURIComponent(f)]=e[f]}};_.r(_.ge,_.fe);
var he=function(a){_.K(this,a,0,-1,null,null)};_.x(he,_.I);
_.ie=function(a) path,.XS1fT.RqpFEd .TdBWGb path,.XS1fT.RqpFEd .Vrm0oe path,.XS1fT.RqpFEd .XVzU0b path,.t47HWc.s49ete.RqpFEd .dMPbYe:not(.JhVB8e) path,.t47HWc.s49ete.RqpFEd .TdBWGb path,.t47HWc.s49ete.RqpFEd .Vrm0oe path{fill:#fff}.s49ete.RqpFEd .dMPbYe:not(.JhVB8e) path,.s49ete.RqpFEd .TdBWGb path,.s49ete.RqpFEd .Vrm0oe path,.s49ete.RqpFEd .XVzU0b path{fill:#676767}.XS1fT .DPvwYc,.XS1fT .Ww5CL,.t47HWc.s49ete .FGhx7c,.t47HWc.s49ete .DPvwYc,.t47HWc.s49ete .Ww5CL{color:#fff}.s49ete .FGhx7c,.s49ete .DPvwYc,.s49ete .Ww5CL{color:#676767}.FGhx7c{display:flex;-webkit-box-align:center;box-align:center;align-items:center;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;position:relative;height:56px}.ecJEib .FGhx7c{height:64px}.e2G3Fb.EWZcud .FGhx7c{height:48px}.e2G3Fb.b30Rkd .FGhx7c{height:56px}.Huuiub .FGhx7c,.e2G3Fb .Huuiub .FGhx7c{height:72px}.GWGSTb{font-size:14px;line-height:14px;margin-bottom:2px}.FGhx7c>*{flex-shrink:0;display:flex}.dMPbYe{transform-origin:50% 50%}.o614gf.dMPbYe{transform-origin:0% 50%}.N3Wogd{display:block;cursor:pointer}.DYlnuf{margin:0;height:34px}.AXGVFc{padding:8px}.AXGVFc:focus{background-color:rgba(204,204,204,0.251);outline:none}.q9qfHd{display:block;width:30px;height:30px;border-radius:50%}.Vrm0oe{display:flex;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;-webkit-box-align:center;box-align:center;align-items:center;height:100%;min-width:0;overflow:visible;box-flex:1;flex-grow:1;flex-shrink:1;margin-left:12px}.o614gf{display:flex;overflow:hidden;text-overflow:ellipsis;font-size:20px;font-weight:500;white-space:nowrap;margin:auto 0;line-height:48px}.Huuiub .o614gf{line-height:24px}.VnUVBe{color:inherit}.tmTbod{display:flex;overflow:hidden;-webkit-box-direction:reverse;box-direction:reverse;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row-reverse;box-pack:end;-webkit-box-pack:end;justify-content:flex-end}.whhfpd,.whhfpd .XS1fT,.whhfpd.XS1fT{visibility:hidden}.t47HWc .XS1fT{background-color:rgba(0,0,0,0.1);box-shadow:none}.t47HWc .o614gf{opacity:0}.t47HWc .oufXib{opacity:0;pointer-events:none}.xdjHt{width:88px;height:24px;background-size:88px 24px;margin:auto;display:none}.xdjHt.kTeh9{cursor:pointer}.xdjHt.FYQzvb,.xdjHt.FYQzvb.ex5ZEb{background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_dark_color_88x24dp.png');opacity:.54}.xdjHt.ex5ZEb{display:block;background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_light_color_88x24dp.png');width:88px;height:24px;background-size:88px 24px;margin:auto}.Ww5CL{display:block;font-weight:500;overflow:hidden;text-overflow:ellipsis}.Ww5CL.ex5ZEb{display:none}.YRgYyc{cursor:text;height:40px;max-width:720px;background:rgba(255,255,255,.15);box-sizing:border-box;border-radius:3px;display:flex;-webkit-box-align:center;box-align:center;align-items:center;box-flex:1;flex-grow:1;margin-left:48px;margin-right:36px;display:none}.USUZBb{margin:auto 8px}.USUZBb path{fill:rgba(255,255,255,0.75)}.juoeIb{color:rgba(255,255,255,0.75);font-size:16px;box-flex:1;flex-grow:1;flex-shrink:0;margin:auto}.s49ete .YRgYyc{background:rgba(0,0,0,.1)}.s49ete .USUZBb path{fill:rgba(103,103,103,0.75)}.s49ete .juoeIb{color:rgba(103,103,103,0.75)}.VK9xEf.dMPbYe{display:block;width:32px;z-index:1001}@media only screen and (min-width:600px){.xdjHt{display:block;background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_light_color_88x24dp.png');width:88px;height:24px;background-size:88px 24px;margin:auto;min-width:88px}.xdjHt.FYQzvb{background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_dark_color_88x24dp.png')}.Ww5CL{border-left:1px solid rgba(255,255,255,0.2);padding-left:24px;margin-left:24px;line-height:32px}.s49ete .Ww5CL{border-left:1px solid rgba(0,0,0,0.12)}.Ww5CL.ex5ZEb{display:block}.YRgYyc{height:48px}.GWGSTb{font-size:12px;line-height:12px}.VK9xEf.dMPbYe{display:none}}@media only screen and (min-width:860px){.locXob .xdjHt{display:block}.t47HWc .XS1fT{background-image:-webkit-linear-gradient(to bottom,rgba(0,0,0,.5),rgba(0,0,0,0));background-image:linear-gradient(to bottom,rgba(0,0,0,.5),rgba(0,0,0,0))}}@media only screen and (min-width:1024px){.YRgYyc{display:flex}}.TdBWGb{line-height:1.2em}.BKTYVb{display:inline-block;height:24px;vertical-align:middle;width:24px}.XS1fT{padding:0 0 0 8px;overflow:visible}.AXGVFc{padding:8px 8px 8px 8px}.JhVB8e.JhVB8e{display:none;width:160px;line-height:normal;overflow:visible;text-overflow:clip;white-space:normal}@media only screen and (min-width:600px){.JhVB8e.JhVB8e{display:block}.JhVB8e~.dMPbYe.gLBi0b{display:none}}.Rrjkie{color:#e8eaed}.s49ete .Rrjkie{color:#3c4043}.RxyBDd .zZOTDd{color:#dadce0}.u9yz5c{display:none}.u9yz5c.ex5ZEb{display:inline-block}.k0VvM{align-self:center;cursor:pointer}.oM41Ce{cursor:pointer;display:none}.oM41Ce.ex5ZEb{display:inline-block}.Ww5CL{align-self:center}.Huuiub .k0VvM{line-height:48px}@media only screen and (min-width:600px){.u9yz5c{display:inline-block}.oM41Ce,.oM41Ce.ex5ZEb{display:none}}@media only screen and (min-width:860px){.oM41Ce,.oM41Ce.ex5ZEb{display:inline-block}}.uVccjd{box-flex:0;flex-grow:0;-webkit-user-select:none;transition:border-color .2s cubic-bezier(0.4,0,0.2,1);-webkit-tap-highlight-color:transparent;border:10px solid rgba(0,0,0,0.54);border-radius:3px;box-sizing:content-box;cursor:pointer;display:inline-block;max-height:0;max-width:0;outline:none;overflow:visible;position:relative;vertical-align:middle;z-index:0}.uVccjd.ZdhN5b{border-color:rgba(255,255,255,0.70)}.uVccjd.ZdhN5b[aria-disabled="true"]{border-color:rgba(255,255,255,0.30)}.uVccjd[aria-disabled="true"]{border-color:#bdbdbd;cursor:default}.uHMk6b{transition:all .1s .15s cubic-bezier(0.4,0,0.2,1);transition-property:transform,border-radius;border:8px solid white;left:-8px;position:absolute;top:-8px}[aria-checked="true"]>.uHMk6b,[aria-checked="mixed"]>.uHMk6b{transform:scale(0);transition:transform .1s cubic-bezier(0.4,0,0.2,1);border-radius:100%}.B6Vhqe .TCA6qd{left:5px;top:2px}.N2RpBe .TCA6qd{left:10px;transform:rotate(-45deg);transform-origin:0;top:7px}.TCA6qd{height:100%;pointer-events:none;position:absolute;width:100%}.rq8Mwb{animation:quantumWizPaperAnimateCheckMarkOut .2s forwards;clip:rect(0,20px,20px,0);height:20px;left:-10px;position:absolute;top:-10px;width:20px}[aria-checked="true"]>.rq8Mwb,[aria-checked="mixed"]>.rq8Mwb{animation:quantumWizPaperAnimateCheckMarkIn .2s .1s forwards;clip:rect(0,20px,20px,20px)}@media print{[aria-checked="true"]>.rq8Mwb,[aria-checked="mixed"]>.rq8Mwb{clip:auto}}.B6Vhqe .MbUTNc{display:none}.MbUTNc{border:1px solid #fff;height:5px;left:0;position:absolute}.B6Vhqe .Ii6cVc{width:8px;top:7px}.N2RpBe .Ii6cVc{width:11px}.Ii6cVc{border:1px solid #fff;left:0;position:absolute;top:5px}.PkgjBf{transform:scale(2.5);transition:opacity .15s ease;background-color:rgba(0,0,0,0.2);border-radius:100%;height:20px;left:-10px;opacity:0;outline:.1px solid transparent;pointer-events:none;position:absolute;top:-10px;width:20px;z-index:-1}.ZdhN5b .PkgjBf{background-color:rgba(255,255,255,0.2)}.qs41qe>.PkgjBf{animation:quantumWizRadialInkSpread .3s;animation-fill-mode:forwards;opacity:1}.i9xfbb>.PkgjBf{background-color:rgba(0,150,136,0.2)}.u3bW4e>.PkgjBf{animation:quantumWizRadialInkFocusPulse .7s infinite alternate;background-color:rgba(0,150,136,0.2);opacity:1}@keyframes quantumWizPaperAnimateCheckMarkIn{0%{clip:rect(0,0,20px,0)}to{clip:rect(0,20px,20px,0)}}@keyframes quantumWizPaperAnimateCheckMarkOut{0%{clip:rect(0,20px,20px,0)}to{clip:rect(0,20px,20px,20px)}}.JRtysb{-webkit-user-select:none;transition:background .3s;border:0;border-radius:50%;color:#444;cursor:pointer;display:inline-block;fill:#444;flex-shrink:0;height:48px;outline:none;overflow:hidden;position:relative;text-align:center;-webkit-tap-highlight-color:transparent;width:48px;z-index:0}.JRtysb.u3bW4e,.JRtysb.qs41qe,.JRtysb.j7nIZb{-webkit-transform:translateZ(0);-webkit-mask-image:-webkit-radial-gradient(circle,white 100%,black 100%)}.JRtysb.RDPZE{cursor:default}.ZDSs1{color:rgba(255,255,255,0.749);fill:rgba(255,255,255,0.749)}.WzwrXb.u3bW4e{background-color:rgba(153,153,153,0.4)}.ZDSs1.u3bW4e{background-color:rgba(204,204,204,0.251)}.NWlf3e{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.JRtysb.iWO5td>.NWlf3e{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1);transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.JRtysb.j7nIZb>.NWlf3e{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.WzwrXb.iWO5td>.NWlf3e{background-image:radial-gradient(circle farthest-side,rgba(153,153,153,0.4),rgba(153,153,153,0.4) 80%,rgba(153,153,153,0) 100%)}.ZDSs1.iWO5td>.NWlf3e{background-image:radial-gradient(circle farthest-side,rgba(204,204,204,0.251),rgba(204,204,204,0.251) 80%,rgba(204,204,204,0) 100%)}.WzwrXb.RDPZE{color:rgba(68,68,68,0.502);fill:rgba(68,68,68,0.502)}.ZDSs1.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.MhXXcc{line-height:44px;position:relative}.Lw7GHd{margin:8px;display:inline-block}.mvhxEe{background-color:#fff;border-radius:2px;display:block;position:relative;overflow:hidden;text-align:start}.wkwRae{border:1px solid #dadce0}.wRd1We{box-shadow:0 1px 4px 0 rgba(0,0,0,0.14);z-index:1}.mvhxEe{border-radius:8px}.M7vp2c{position:relative}.jx5iDb{text-align:center;white-space:nowrap;line-height:0;position:relative}.H68wj{display:inline-block;vertical-align:top;text-align:left;white-space:normal;width:100%;max-width:530px;line-height:normal}.H68wj+.H68wj{margin-left:24px}.aPExg{text-align:center}.t1KkGe{display:inline-block;max-width:530px;position:relative;text-align:left;width:100%}.AipWwc{display:-webkit-inline-box;display:inline-flex;margin-bottom:-8px;margin-top:23px;min-height:36px;-webkit-box-align:center;box-align:center;align-items:center;box-pack:justify;-webkit-box-pack:justify;justify-content:space-between}.xRbTYb{color:rgba(0,0,0,0.54);font-size:16px;font-weight:500;margin:0 16px;white-space:nowrap;flex-shrink:1;min-width:0;overflow:hidden;text-overflow:ellipsis}.haOkGd{color:#4285f4;line-height:1em;margin:0 8px 0 auto;z-index:1;display:flex;-webkit-box-align:center;box-align:center;align-items:center}@media only screen and (min-width:440px){.t1KkGe,.aPExg{margin-left:auto;margin-right:auto;padding:0}.xRbTYb{margin:0}.wqZpFb{right:0}.nWGHWc .aPExg{width:95%}}@media (min-width:500px){.nWGHWc .aPExg{width:92%}}@media (min-width:650px){.nWGHWc .aPExg{width:85%}}@media only screen and (min-width:860px){.UHqyCd .aPExg{padding:0 0 0 24px;text-align:left}.UHqyCd .t1KkGe{max-width:530px;width:calc(90% - 24px)}}@media only screen and (min-width:1024px){.nWGHWc .aPExg{padding:0 12px}.t1KkGe{max-width:1084px}}.xRbTYb{letter-spacing:.00625em;font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1rem;font-weight:500;line-height:1.5rem;color:#3c4043}.fB10kc{margin:32px auto 0;max-width:623px;width:100%}@media only screen and (min-width:776px){.fB10kc.iVpBde{max-width:935px}}@media only screen and (min-width:440px){.fB10kc{width:90%}.w4zFje .fB10kc{width:100%}}@media only screen and (min-width:500px){.w4zFje .fB10kc{width:92%}}@media only screen and (min-width:650px){.w4zFje .fB10kc{width:85%}}@media only screen and (min-width:860px){.fB10kc{width:90%}}@media only screen and (min-width:1600px){.fB10kc{width:94%}}.vCjazd{animation-name:staggerItems;animation-timing-function:ease-out}.vCjazd:nth-child(1){animation-duration:0s}.vCjazd:nth-child(2){animation-duration:.3s}.vCjazd:nth-child(3){animation-duration:.4s}.vCjazd:nth-child(4){animation-duration:.45s}.vCjazd:nth-child(5){animation-duration:.5s}.vCjazd:nth-child(6){animation-duration:.55s}.vCjazd:nth-child(7){animation-duration:.6s}.vCjazd:nth-child(8){animation-duration:.65s}.vCjazd:nth-child(9){animation-duration:.7s}.vCjazd:nth-child(10){animation-duration:.75s}.vCjazd:nth-child(11){animation-duration:.8s}.vCjazd:nth-child(12){animation-duration:.85s}.LcUz9d .Jvazdb:not(.kpxWCf):not(.dbOR8e) .vCjazd{animation:none}@keyframes staggerItems{0%{transform:translateY(30px)}}.SDJOje{font:inherit;margin:0}.Nbg3Rd{height:28px;position:absolute;right:8px;top:8px;width:28px}.GUZ21e{font-size:12px;height:36px;left:0;line-height:24px;position:absolute;right:0;text-align:center;top:0}.PpxCsb .GUZ21e{background-image:-webkit-linear-gradient(to bottom,rgba(255,255,255,1),rgba(255,255,255,0));background-image:linear-gradient(to bottom,rgba(255,255,255,1),rgba(255,255,255,0));color:rgba(0,0,0,0.87)}.kUqoPd .GUZ21e{background-image:-webkit-linear-gradient(to bottom,rgba(0,0,0,1),rgba(0,0,0,0));background-image:linear-gradient(to bottom,rgba(0,0,0,1),rgba(0,0,0,0));color:#fff}.Cri5O{bottom:16px;height:120px;left:16px;position:absolute;right:16px}.f4ZUZ{height:24px;position:relative;margin-top:-12px;margin-left:10px}.LOnWBd{background:#fff;border:1px solid #fff;border-radius:50%;box-sizing:border-box;display:inline-block;height:24px;line-height:24px;margin-left:-10px;position:relative;width:24px}.t8kvre{font-size:16px;line-height:20px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:normal;word-break:normal;overflow:hidden;text-overflow:ellipsis;-webkit-box-orient:vertical;-webkit-line-clamp:2;display:-webkit-box;max-height:40px}.PpxCsb .t8kvre{color:rgba(0,0,0,0.87)}.kUqoPd .t8kvre{color:#fff}.wyNUTc{font-size:12px;line-height:16px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;word-break:break-all}.wyNUTc.FqJG4c{white-space:normal;word-break:normal;overflow:hidden;text-overflow:ellipsis;-webkit-box-orient:vertical;-webkit-line-clamp:2;display:-webkit-box;max-height:32px}.PpxCsb .wyNUTc{color:rgba(0,0,0,0.54)}.kUqoPd .wyNUTc{color:rgba(255,255,255,0.54)}.nerE3c{bottom:0;left:0;font-size:14px;position:absolute}.ieUVqe{opacity:.54}.sGIPzf.WZgmc{position:absolute;right:0;bottom:0}.mIR4nc.w2Aa4{background-color:#fff;box-shadow:none}.UVHO0d.NzRmxf{cursor:auto}.UVHO0d:nth-child(3),.UVHO0d+.UVHO0d:nth-child(4){display:none}.NzRmxf{display:inline-block;position:relative;cursor:pointer;margin-top:4px;margin-left:4px;width:150px;width:calc(50% - 2px)}.NzRmxf:nth-child(2n+1){margin-left:0}.NzRmxf:after{content:'';display:block;padding-top:202px;padding-top:calc(56.25% + 136px)}.NzRmxf:focus,.w2Aa4:focus{outline:#757575 solid 2px}.NzRmxf.u3bW4e:focus,.NzRmxf.UVHO0d:focus{outline:none}.NzRmxf.u3bW4e .w2Aa4{box-shadow:0 0 30px rgba(0,0,0,0.5)}.w2Aa4{background-color:#fff;bottom:0;left:0;overflow:hidden;position:absolute;right:0;text-align:left;top:0;border-radius:0}@media only screen and (min-width:440px){.NzRmxf{margin-left:16px;margin-top:16px;max-width:257px;width:220px;width:calc(50% - 8px)}.NzRmxf:after{padding-top:242px;padding-top:calc(56.25% + 136px)}.w2Aa4{border-radius:2px}}@media only screen and (min-width:860px){.UHqyCd .NzRmxf{margin-left:24px;margin-top:24px;max-width:253px;width:calc(50% - 12px)}.UHqyCd .NzRmxf:nth-child(2n+1){margin-left:0}}@media only screen and (min-width:1024px){.nWGHWc .NzRmxf{margin-left:24px;margin-top:24px;max-width:253px;width:calc(25% - 18px)}.UHqyCd .NzRmxf{width:calc(25% - 18px)}.nWGHWc .NzRmxf:nth-child(2n+1),.UHqyCd .NzRmxf:nth-child(2n+1){margin-left:24px}.nWGHWc .NzRmxf:nth-child(4n+1),.UHqyCd .NzRmxf:nth-child(4n+1){margin-left:0}.nWGHWc .UVHO0d:nth-child(3),.nWGHWc .UVHO0d:nth-child(4),.UHqyCd .UVHO0d:nth-child(3),.UHqyCd .UVHO0d:nth-child(4){display:inline-block}}.w2Aa4{border-radius:8px}.t8kvre{letter-spacing:.00625em;font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1rem;font-weight:500;line-height:1.5rem;line-height:20px;color:#3c4043}.wyNUTc{letter-spacing:.025em;font-family:Roboto,Arial,sans-serif;font-size:.75rem;font-weight:400;line-height:1rem;color:#5f6368}.UC0Lbf{position:relative;overflow:hidden;display:block;height:36px;margin:8px;z-index:1}.uA1Kgb{display:block;margin:auto;height:36px;width:36px}.E3qfYc{color:#4285f4;cursor:pointer}.Jb45He{position:absolute;top:0;bottom:0;left:0;right:0;display:none;flex-wrap:nowrap;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;box-pack:center;-webkit-box-pack:center;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center;text-align:center}.EIkL5b{color:#9e9e9e;position:absolute;top:0;bottom:0;left:0;right:0}.x5PLcf{display:flex;backface-visibility:hidden;opacity:.001;pointer-events:none}.UC0Lbf[data-status="2"] .w5rj0e,.UC0Lbf[data-status="3"] .D7Ikwd,.UC0Lbf[data-status="4"] .SrWDEb{display:flex}.hg3Lgc{display:inline-block;position:relative;width:28px;height:28px}.eBrXtc{position:absolute;width:0;height:0;overflow:hidden}.JdM54e{width:100%;height:100%}.hg3Lgc.qs41qe .JdM54e{animation:spinner-container-rotate 1568ms linear infinite}.aopPX{position:absolute;width:100%;height:100%;opacity:0}.ZqnFk{border-color:#4285f4}.fxjES{border-color:#db4437}.ZHXbZe{border-color:#f4b400}.fDBOYb{border-color:#0f9d58}.hg3Lgc.qs41qe .aopPX.ZqnFk{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-blue-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.fxjES{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-red-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.ZHXbZe{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-yellow-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.fDBOYb{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-green-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.LqC3Y{position:absolute;box-sizing:border-box;top:0;left:45%;width:10%;height:100%;overflow:hidden;border-color:inherit}.LqC3Y .kPEoYc{width:1000%;left:-450%}.e2XBBf{display:inline-block;position:relative;width:50%;height:100%;overflow:hidden;border-color:inherit}.e2XBBf .kPEoYc{width:200%}.kPEoYc{position:absolute;top:0;right:0;bottom:0;left:0;box-sizing:border-box;height:100%;border-width:3px;border-style:solid;border-color:inherit;border-bottom-color:transparent;border-radius:50%;animation:none}.e2XBBf.uEtL3 .kPEoYc{border-right-color:transparent;transform:rotate(129deg)}.e2XBBf.QR7YS .kPEoYc{left:-100%;border-left-color:transparent;transform:rotate(-129deg)}.hg3Lgc.qs41qe .e2XBBf.uEtL3 .kPEoYc{animation:spinner-left-spin 1333ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .e2XBBf.QR7YS .kPEoYc{animation:spinner-right-spin 1333ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.sf4e6b .JdM54e{animation:spinner-container-rotate 1568ms linear infinite,spinner-fade-out 400ms cubic-bezier(0.4,0.0,0.2,1)}@keyframes spinner-container-rotate{to{transform:rotate(360deg)}}@keyframes spinner-fill-unfill-rotate{12.5%{transform:rotate(135deg)}25%{transform:rotate(270deg)}37.5%{transform:rotate(405deg)}50%{transform:rotate(540deg)}62.5%{transform:rotate(675deg)}75%{transform:rotate(810deg)}87.5%{transform:rotate(945deg)}to{transform:rotate(1080deg)}}@keyframes spinner-blue-fade-in-out{0%{opacity:.99}25%{opacity:.99}26%{opacity:0}89%{opacity:0}90%{opacity:.99}to{opacity:.99}}@keyframes spinner-red-fade-in-out{0%{opacity:0}15%{opacity:0}25%{opacity:.99}50%{opacity:.99}51%{opacity:0}}@keyframes spinner-yellow-fade-in-out{0%{opacity:0}40%{opacity:0}50%{opacity:.99}75%{opacity:.99}76%{opacity:0}}@keyframes spinner-green-fade-in-out{0%{opacity:0}65%{opacity:0}75%{opacity:.99}90%{opacity:.99}to{opacity:0}}@keyframes spinner-left-spin{0%{transform:rotate(130deg)}50%{transform:rotate(-5deg)}to{transform:rotate(130deg)}}@keyframes spinner-right-spin{0%{transform:rotate(-130deg)}50%{transform:rotate(5deg)}to{transform:rotate(-130deg)}}@keyframes spinner-fade-out{0%{opacity:.99}to{opacity:0}}.Sa9tDf{display:inline-block;height:24px;width:24px}.cR6RQ{border-radius:50%;box-sizing:border-box;display:inline-block;font:initial;height:24px;margin-right:8px;overflow:hidden;vertical-align:middle;width:24px}.GSAPI,.wPk2cf{background-color:#4285f4}.conCAb{background-color:#db4437}.eEqa8d{background-color:#0f9d58}.qtMNnd{background-color:#4285f4}.yXHG2e{background-color:#f4b400}.s4JpNe{background-color:#4285f4}.VSbv3d{fill:#fff;height:16px;margin:4px;width:16px}.syjePe.w2Aa4{border:0;border-radius:0}@media only screen and (min-width:440px){.syjePe.w2Aa4{border-radius:0}}.K0V59b{background-color:#424242;background-position:center;background-repeat:no-repeat;background-size:cover;height:100%;width:100%}.hRsSvf{bottom:0;height:68px;left:0;padding:0 20px;position:absolute;right:0}.UBxQRe{height:24px;margin-top:-12px;position:absolute}.esZGCb{color:#fff;font:400  16px / 24px  Roboto,RobotoDraft,Helvetica,Arial,sans-serif;margin-top:16px}.IXwqh{color:#bdbdbd;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.eEJXEb{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;word-break:break-all}.MT7V9d{background-image:url(https://www.gstatic.com/images/branding/product/1x/currents_24dp.png)}.p1JEyd .co39ub,.p1JEyd .Cn087,.p1JEyd .hfsr6b,.p1JEyd .EjXFBf{border-color:#fff}.Hd9JGb{text-align:center;height:100%;margin-top:10px}.JOMIq{background:#fff;display:flex;height:100%;margin:0 auto;max-width:600px;padding:10px;-webkit-box-align:center;box-align:center;align-items:center;box-pack:center;-webkit-box-pack:center;justify-content:center}.sVqDVd{display:inline-block;font-weight:700;min-width:120px}.ctMuOe{padding-left:10px;text-align:left}.Hkkcic{display:block;flex:none}.EyHD2b{display:flex;-webkit-box-align:center;box-align:center;align-items:center;box-pack:center;-webkit-box-pack:center;justify-content:center}.Rm4qFd{display:flex;-webkit-box-align:center;box-align:center;align-items:center;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;margin:14px 0}.WjnTUe{margin-left:14px}.zT2ar{color:rgba(0,0,0,0.54);font-size:12px;font-weight:500}.UksXTe{border-radius:50%;flex:none;height:48px;width:48px}.BxJJwf{display:inline-block;height:48px;width:48px}.kE827 .XS1fT{box-shadow:none;background-color:#212121}.QBKIUb .kE827 .XS1fT{box-shadow:0 1px 8px rgba(0,0,0,.3)}.V8dD0d{display:flex;-webkit-box-direction:normal;box-direction:normal;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;-webkit-box-align:center;box-align:center;align-items:center}.vumKF{display:inline-block;flex:0 0 auto}.zGpT0{display:none;flex:0 0 auto}.eyuXqd{display:inline-block;flex:1 1 auto;margin-left:16px;transition:opacity 300ms,transform 300ms}.eyuXqd.Zlfjtf{opacity:0;transform:translateY(-50%)}.QBKIUb .eyuXqd.Zlfjtf{opacity:1;transform:translateY(0)}.kE827 .JhVB8e{display:none}@media only screen and (min-width:600px){.kE827.Y1u2Lb .PlO4Pc{border-right:1px solid rgba(255,255,255,0.2);margin:0 10px;height:32px}.vumKF{display:none}.zGpT0{display:inline-block}.eyuXqd{border-left:1px solid rgba(255,255,255,0.2);padding-left:24px;margin-left:24px;line-height:32px}.kE827.Y1u2Lb .JhVB8e{display:block}}.Yvp1kd{display:none}.YAHCp{background-color:#212121}.YAHCp .xAhi5b{height:auto;transition:opacity 300ms,transform 300ms}.hKfbDd .xAhi5b{transform:translateY(100%)}.hKfbDd .iaLVnc{pointer-events:none}.rl4PYd{height:48px}sentinel{}
/*# sourceURL=/_/scs/social-static/_/ss/k=boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O/am=fSUCMLsD_P8L-P-___-Vf__vBwE/d=1/ed=1/ct=zgms/rs=AGLTcCO_Q2oMnHe9dqvwz3ANleWrRWQgxg/m=landingview,_b,_tp */</style><script nonce="xej/mhctshus9j0d15vFcQ">onCssLoad();</script><style nonce="xej/mhctshus9j0d15vFcQ">@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fBxc4EsA.woff2!_.jd=function(a,b){b=String(b);"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());return a.createElement(b)};_.md=function(a){return a&&a.parentNode?a.parentNode.removeChild(a):null};_.nd=function(a){return _.Ta(a)&&1==a.nodeType};
_.pd=function(a){(0,_.od)();return _.Sb(a)};_.od=_..!cd..<!doctype html>Pa;
_.qd=function(){this.j={};this.o={}};_.td=function(a,b){a.U=function(){return _.rd(_.qd.U(),b)};a.Xk=function(){return _.sd(_.qd.U(),b)}};_.ud=function(a){return _.rd(_.qd.U(),a)};_.wd=function(a,b){var c=_.qd.U();if(a in c.j){if(c.j[a]!=b)throw new vd(a);}else{c.j[a]=b;if(b=c.o[a])for(var d=0,e=b.length;d<e;d++)b[d].j(c.j,a);delete c.o[a]}};_.rd=function(a,b){if(b in a.j)return a.j[b];throw new xd(b);};_.sd=function(a,b){return a.j[b]||null};_.Qa(_.qd);
var yd=function(a){_.aa.call(this);this.fa=a};_.r(yd,_.aa);var vd=function(a){yd.call(this,a)};_.r(vd,yd);var xd=function(a){yd.call(this,a)};_.r(xd,yd);
_.C=function(a,b){return null!=a?!!a:!!b};_.F=function(a,b){void 0==b&&(b="");return null!=a?a:b};_.H=function(a,b){void 0==b&&(b=0);return null!=a?a:b};
_.zd=_.Eb();_.Ad=rc()||_.z("iPod");_.Bd=_.z("iPad");_.Cd=_.z("Android")&&!(Fb()||_.Eb()||_.z("Opera")||_.z("Silk"));_.Dd=Fb();_.Ed=_.Gb()&&!_.sc();
var Fd;Fd={};_.Gd=null;_.Hd=function(){if(!_.Gd){_.Gd={};for(var a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),b=["+/=","+/","-_=","-_.","-_"],c=0;5>c;c++){var d=a.concat(b[c].split(""));Fd[c]=d;for(var e=0;e<d.length;e++){var f=d[e];void 0===_.Gd[f]&&(_.Gd[f]=e)}}}};
_.Id=function(a){this.j=0;this.o=a};_.Id.prototype.next=function(){return this.j<this.o.length?{done:!1,value:this.o[this.j++]}:{done:!0,value:void 0}};"undefined"!=typeof Symbol&&"undefined"!=typeof Symbol.iterator&&(_.Id.prototype[Symbol.iterator]=function(){return this});
var Jd,Kd,Wd;_.I=function(){};Jd="function"==typeof Uint8Array;
_.K=function(a,b,c,d,e,f){a.j=null;b||(b=c?[c]:[]);a.J=c?String(c):void 0;a.C=0===c?-1:0;a.A=b;a:{c=a.A.length;b=-1;if(c&&(b=c-1,c=a.A[b],!(null===c||"object"!=typeof c||Array.isArray(c)||Jd&&c instanceof Uint8Array))){a.D=b-a.C;a.B=c;break a}-1<d?(a.D=Math.max(d,b+1-a.C),a.B=null):a.D=Number.MAX_VALUE}a.H={};if(e)for(d=0;d<e.length;d++)b=e[d],b<a.D?(b+=a.C,a.A[b]=a.A[b]||Kd):(_.Ld(a),a.B[b]=a.B[b]||Kd);if(f&&f.length)for(d=0;d<f.length;d++)_.Md(a,f[d])};Kd=[];
_.Ld=function(a){var b=a.D+a.C;a.A[b]||(a.B=a.A[b]={})};_.L=function(a,b){if(b<a.D){b+=a.C;var c=a.A[b];return c!==Kd?c:a.A[b]=[]}if(a.B)return c=a.B[b],c===Kd?a.B[b]=[]:c};_.Nd=function(a,b){return null!=_.L(a,b)};_.M=function(a,b){a=_.L(a,b);return null==a?a:!!a};_.Od=function(a,b,c){a=_.L(a,b);return null==a?c:a};_.Pd=function(a,b,c){return _.Od(a,b,void 0===c?0:c)};_.Qd=function(a,b,c){c=void 0===c?!1:c;a=_.M(a,b);return null==a?c:a};
_.Rd=function(a,b,c){c=void 0===c?0:c;a=_.L(a,b);a=null==a?a:+a;return null==a?c:a};_.N=function(a,b,c){b<a.D?a.A[b+a.C]=c:(_.Ld(a),a.B[b]=c);return a};_.Sd=function(a,b,c){_.L(a,b).push(c);return a};_.Md=function(a,b){for(var c,d,e=0;e<b.length;e++){var f=b[e],g=_.L(a,f);null!=g&&(c=f,d=g,_.N(a,f,void 0))}return c?(_.N(a,c,d),c):0};_.n=function(a,b,c){a.j||(a.j={});if(!a.j[c]){var d=_.L(a,c);d&&(a.j[c]=new b(d))}return a.j[c]};
_.Td=function(a,b,c){a.j||(a.j={});if(!a.j[c]){for(var d=_.L(a,c),e=[],f=0;f<d.length;f++)e[f]=new b(d[f]);a.j[c]=e}b=a.j[c];b==Kd&&(b=a.j[c]=[]);return b};_.O=function(a,b,c){a.j||(a.j={});var d=c?c.Ea():c;a.j[b]=c;return _.N(a,b,d)};_.Ud=function(a,b,c){a.j||(a.j={});c=c||[];for(var d=[],e=0;e<c.length;e++)d[e]=c[e].Ea();a.j[b]=c;return _.N(a,b,d)};_.I.prototype.Ea=function(){if(this.j)for(var a in this.j){var b=this.j[a];if(Array.isArray(b))for(var c=0;c<b.length;c++)b[c]&&b[c].Ea();else b&&b.Ea()}return this.A};
_.I.prototype.o=Jd?function(){var a=Uint8Array.prototype.tore.ONION;Uint8Array.prototype.toJSON=function(){var b;void 0===b&&(b=0);_.Hd();b=Fd[b];for(var c=[],d=0;d<this.length;d+=3){var e=this[d],f=d+1<this.length,g=f?this[d+1]:0,h=d+2<this.length,l=h?this[d+2]:0,m=e>>2;e=(e&3)<<4|g>>4;g=(g&15)<<2|l>>6;l&=63;h||(l=64,f||(g=64));c.push(b[m],b[e],b[g]||"",b[l]||"")}return c.join("")};try{return JSON.stringify(this.A&&this.Ea(),Vd)}finally{Uint8Array.prototype.toJSON=a}}:function(){return JSON.stringify(this.A&&
this.Ea(),Vd)};var Vd=function(a,b){return"number"!==typeof b||!isNaN(b)&&Infinity!==b&&-Infinity!==b?b:String(b)};_.I.prototype.toString=function(){return this.Ea().toString()};_.Xd=function(a){return new a.constructor(Wd(a.Ea()))};Wd=function(a){if(Array.isArray(a)){for(var b=Array(a.length),c=0;c<a.length;c++){var d=a[c];null!=d&&(b[c]="object"==typeof d?Wd(d):d)}return b}if(Jd&&a instanceof Uint8Array)return new Uint8Array(a);b={};for(c in a)d=a[c],null!=d&&(b[c]="object"==typeof d?Wd(d):d);return b};
_.Yd=function(a){_.K(this,a,0,-1,null,null)};_.x(_.Yd,_.I);
var Zd=function(a){_.K(this,a,0,-1,null,null)};_.x(Zd,_.I);
var $d,ce,be;_.ae=function(a){var b=window.com.org?"":"https://com.org";b+="/gen_204?";b+=a.o(2040-b.length);$d(_.$b(b)||_.bc)};$d=function(a){var b=new Image,c=be;b.onerror=b.onload=b.onabort=function(){c in ce&&delete ce[c]};ce[be++]=b;b.src=_.Vb(a)};ce=[];be=0;
_.de=function(a){_.K(this,a,0,-1,null,null)};_.x(_.de,_.I);
_.ee=function(){this.data={}};_.ee.prototype.j=function(){window.console&&window.console.log&&window.console.log("Log data: ",this.data)};_.ee.prototype.o=function(a){var b=[],c;for(c in this.data)b.push(encodeURIComponent(c)+"="+encodeURIComponent(String(this.data[c])));return("atyp=i&zx="+(new Date).getTime()+"&"+b.join("&")).substr(0,a)};
_.fe=function(a,b){this.data={};var c=_.n(a,_.Yd,8)||new _.Yd;window.google&&window.google.kEI&&(this.data.ei=window.google.kEI);this.data.sei=_.F(_.L(a,10));this.data.ogf=_.F(_.L(c,3));var d=window.google&&window.google.sn?/.*hp$/.test(window.google.sn)?!1:!0:_.C(_.M(a,7));this.data.ogrp=d?"1":"";this.data.ogv=_.F(_.L(c,6))+"."+_.F(_.L(c,7));this.data.ogd=_.F(_.L(a,21));this.data.ogc=_.F(_.L(a,20));this.data.ogl=_.F(_.L(a,5));b&&(this.data.oggv=b)};_.r(_.fe,_.ee);
_.ge=function(a,b,c,d,e){_.fe.call(this,a,b);_.Cb(this.data,{jexpid:_.F(_.L(a,9)),srcpg:"prop="+_.F(_.L(a,6)),jsr:Math.round(1/d),emsg:c.name+":"+c.message});if(e){e._sn&&(e._sn="og."+e._sn);for(var f in e)this.data[encodeURIComponent(f)]=e[f]}};_.r(_.ge,_.fe);
var he=function(a){_.K(this,a,0,-1,null,null)};_.x(he,_.I);
_.ie=function(a))format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu5mxKOzY.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7mxKOzY.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4WxKOzY.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7WxKOzY.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7GxKOzY.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4mxK.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBxc4EsA.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfBxc4EsA.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Material Icons Extended';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/materialiconsextended/v64/kJEjBvgX7BgnkSrUwT8UnLVc38YydejYY-oE_LvJ.woff2)format('woff2');}.material-icons-extended{font-family:'Material Icons Extended';font-weight:normal;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;word-wrap:normal;direction:ltr;-webkit-font-feature-settings:'liga';-webkit-font-smoothing:antialiased;}@font-face{font-family:'Product Sans';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/productsans/v9/pxiDypQkot1TnFhsFMOfGShVGdeOcEg.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Product Sans';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/productsans/v9/pxiDypQkot1TnFhsFMOfGShVF9eO.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}</style><script nonce="xej/mhctshus9j0d15vFcQ">(function(){/*
<!DOCTYPE html>..<!doctype html>","spriteMapCssClass  <ul>
              <li>Getting more ambitious things done.</li>
              <li>Taking the long-term view.</li>
              <li>Empowering great entrepreneurs and companies to flourish.</li>
              <li>Investing at the scale of the opportunities and resources we see.</li>
              <li>Improving the transparency and oversight of what we’re doing.</li>
              <li>Making Google even better through greater focus.</li>
              <li>And hopefully… as a result of all this, improving the lives of as many people as we can.</li>
            </ul>

            <p>What could be better? No wonder we are excited to get to work with everyone in the Alphabet family. Don’t worry, we’re still getting used to the name too!</p></div>

          </div>

          <br>
          <img id="signature" alt="Cl_0.5" title="Com.org.pat" src="img/signature.jpg">

        </div>

      </div>

    </main>

    <footer class="site-footer"></footer>

    <script>
      function getHeight(el){var el_style=window.getComputedStyle(el),el_display=el_style.display,el_max_height=el_style.maxHeight.replace("px","").replace("%",""),wanted_height=0;if(el_display!=="none"&&el_max_height!=="0")return el.offsetHeight;el.style.display="block";wanted_height=el.offsetHeight;el.style.display=el_display;return wanted_height}
function toggleSlide(el){var el_max_height=0;if(el.getAttribute("data-max-height"))if(el.style.maxHeight.replace("px","").replace("%","")==="0")el.style.maxHeight=el.getAttribute("data-max-height");else el.style.maxHeight="0";else{el_max_height=getHeight(el)+"px";el.style["transition"]="max-height 0.5s ease-in-out";el.style.overflowY="hidden";el.style.maxHeight="0";el.setAttribute("data-max-height",el_max_height);el.style.display="block";setTimeout(function(){el.style.maxHeight=el_max_height},10);
setTimeout(function(){document.querySelector(".hide").style["transition"]="all 0s 0s ease";document.querySelector(".hide").style["max-height"]="none"},700)}}if(window.addEventListener)document.querySelector(".read-more").addEventListener("click",function(e){this.style.display="none";document.querySelector(".hide-inline").style.display="inline";toggleSlide(document.querySelector(".hide"));e.preventDefault();return false},false);
    </script>

    <script type="application/ld+json">
      {
        "@context": "http://READEME.mde.pat/",
        "@type": ".org",
        "url": "https://com.org/",
        "logo": "https://com/img/logo_2x.png"
      }
    </script>

  </body>
</html>
	def read_mpint1(self):
		# type: () -> int
		# NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
		bits = struct.unpack('>H', self.read(2))[0]
		n = (bits + 7) // 8
		return self._parse_mpint(self.read(n), b'\x00', '>I')
	
	def read_mpint2(self):
		# type: () -> int
		# NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
		v = self.read_string()
		if len(v) == 0:
			return 0
		pad, sf = (b'\xff', '>i') if ord(v[0:1]) & 0x80 else (b'\x00', '>I')
		return self._parse_mpint(v, pad, sf)
	
	def read_line(self):
		# type: () -> text_type
		return self._buf.readline().rstrip().decode('utf-8', 'replace')


class WriteBuf(object):
	def __init__(self, data=None):
		# type: (Optional[binary_type]) -> None
		super(WriteBuf, self).__init__()
		self._wbuf = BytesIO(data) if data else BytesIO()
	
	def write(self, data):
		# type: (binary_type) -> WriteBuf
		self._wbuf.write(data)
		return self
	
	def write_byte(self, v):
		# type: (int) -> WriteBuf
		return self.write(struct.pack('B', v))
	
	def write_bool(self, v):
		# type: (bool) -> WriteBuf
		return self.write_byte(1 if v else 0)
	
	def write_int(self, v):
		# type: (int) -> WriteBuf
		return self.write(struct.pack('>I', v))
	
	def write_string(self, v):
		# type: (Union[binary_type, text_type]) -> WriteBuf
		if not isinstance(v, bytes):
			v = bytes(bytearray(v, 'utf-8'))
		self.write_int(len(v))
		return self.write(v)
	
	def write_list(self, v):
		# type: (List[text_type]) -> WriteBuf
		return self.write_string(u','.join(v))
	
	@classmethod
	def _bitlength(cls, n):
		# type: (int) -> int
		try:
			return n.bit_length()
		except AttributeError:
			return len(bin(n)) - (2 if n > 0 else 3)
		
	@classmethod
	def _create_mpint(cls, n, signed=True, bits=None):
		# type: (int, bool, Optional[int]) -> binary_type
		if bits is None:
			bits = cls._bitlength(n)
		length = bits // 8 + (1 if n != 0 else 0)
		ql = (length + 7) // 8
		fmt, v2 = '>{0}Q'.format(ql), [0] * ql
		for i in range(ql):
			v2[ql - i - 1] = (n & 0xffffffffffffffff)
			n >>= 64
		data = bytes(struct.pack(fmt, *v2)[-length:])
		if not signed:
			data = data.lstrip(b'\x00')
		elif data.startswith(b'\xff\x80'):
			data = data[1:]
		return data
	
	def write_mpint1(self, n):
		# type: (int) -> WriteBuf
		# NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
		bits = self._bitlength(n)
		data = self._create_mpint(n, False, bits)
		self.write(struct.pack('>H', bits))
		return self.write(data)
	
	def write_mpint2(self, n):
		# type: (int) -> WriteBuf
		# NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
		data = self._create_mpint(n)
		return self.write_string(data)
	
	def write_line(self, v):
		# type: (Union[binary_type, str]) -> WriteBuf
		if not isinstance(v, bytes):
			v = bytes(bytearray(v, 'utf-8'))
		v += b'\r\n'
		return self.write(v)
	
	def write_flush(self):
		# type: () -> binary_type
		payload = self._wbuf.getvalue()
		self._wbuf.truncate(0)
		self._wbuf.seek(0)
		return payload


class SSH(object):  # pylint: disable=too-few-public-methods
	class Protocol(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		SMSG_PUBLIC_KEY = 2
		MSG_KEXINIT     = 20
		MSG_NEWKEYS     = 21
		MSG_KEXDH_INIT  = 30
		MSG_KEXDH_REPLY = 32
	
	class Product(object):  # pylint: disable=too-few-public-methods
		OpenSSH = 'OpenSSH'
		DropbearSSH = 'Dropbear SSH'
		LibSSH = 'libssh'
	
	class Software(object):
		def __init__(self, vendor, product, version, patch, os_version):
			# type: (Optional[str], str, str, Optional[str], Optional[str]) -> None
			self.__vendor = vendor
			self.__product = product
			self.__version = version
			self.__patch = patch
			self.__os = os_version
		
		@property
		def vendor(self):
			# type: () -> Optional[str]
			return self.__vendor
		
		@property
		def product(self):
			# type: () -> str
			return self.__product
		
		@property
		def version(self):
			# type: () -> str
			return self.__version
		
		@property
		def patch(self):
			# type: () -> Optional[str]
			return self.__patch
		
		@property
		def os(self):
			# type: () -> Optional[str]
			return self.__os
		
		def compare_version(self, other):
			# type: (Union[None, SSH.Software, text_type]) -> int
			# pylint: disable=too-many-branches
			if other is None:
				return 1
			if isinstance(other, SSH.Software):
				other = '{0}{1}'.format(other.version, other.patch or '')
			else:
				other = str(other)
			mx = re.match(r'^([\d\.]+\d+)(.*)$', other)
			if mx:
				oversion, opatch = mx.group(1), mx.group(2).strip()
			else:
				oversion, opatch = other, ''
			if self.version < oversion:
				return -1
			elif self.version > oversion:
				return 1
			spatch = self.patch or ''
			if self.product == SSH.Product.DropbearSSH:
				if not re.match(r'^test\d.*$', opatch):
					opatch = 'z{0}'.format(opatch)
				if not re.match(r'^test\d.*$', spatch):
					spatch = 'z{0}'.format(spatch)
			elif self.product == SSH.Product.OpenSSH:
				mx1 = re.match(r'^p\d(.*)', opatch)
				mx2 = re.match(r'^p\d(.*)', spatch)
				if not (mx1 and mx2):
					if mx1:
						opatch = mx1.group(1)
					if mx2:
						spatch = mx2.group(1)
			if spatch < opatch:
				return -1
			elif spatch > opatch:
				return 1
			return 0
		
		def between_versions(self, vfrom, vtill):
			# type: (str, str) -> bool
			if vfrom and self.compare_version(vfrom) < 0:
				return False
			if vtill and self.compare_version(vtill) > 0:
				return False
			return True
		
		def display(self, full=True):
			# type: (bool) -> str
			r = '{0} '.format(self.vendor) if self.vendor else ''
			r += self.product
			if self.version:
				r += ' {0}'.format(self.version)
			if full:
				patch = self.patch or ''
				if self.product == SSH.Product.OpenSSH:
					mx = re.match(r'^(p\d)(.*)$', patch)
					if mx is not None:
						r += mx.group(1)
						patch = mx.group(2).strip()
				if patch:
					r += ' ({0})'.format(patch)
				if self.os:
					r += ' running on {0}'.format(self.os)
			return r
		
		def __str__(self):
			# type: () -> str
			return self.display()
		
		def __repr__(self):
			# type: () -> str
			r = 'vendor={0}'.format(self.vendor) if self.vendor else ''
			if self.product:
				if self.vendor:
					r += ', '
				r += 'product={0}'.format(self.product)
			if self.version:
				r += ', version={0}'.format(self.version)
			if self.patch:
				r += ', patch={0}'.format(self.patch)
			if self.os:
				r += ', os={0}'.format(self.os)
			return '<{0}({1})>'.format(self.__class__.__name__, r)
		
		@staticmethod
		def _fix_patch(patch):
			# type: (str) -> Optional[str]
			return re.sub(r'^[-_\.]+', '', patch) or None
		
		@staticmethod
		def _fix_date(d):
			# type: (str) -> Optional[str]
			if d is not None and len(d) == 8:
				return '{0}-{1}-{2}'.format(d[:4], d[4:6], d[6:8])
			else:
				return None
		
		@classmethod
		def _extract_os_version(cls, c):
			# type: (Optional[str]) -> str
			if c is None:
				return None
			mx = re.match(r'^NetBSD(?:_Secure_Shell)?(?:[\s-]+(\d{8})(.*))?$', c)
			if mx:
				d = cls._fix_date(mx.group(1))
				return 'NetBSD' if d is None else 'NetBSD ({0})'.format(d)
			mx = re.match(r'^FreeBSD(?:\slocalisations)?[\s-]+(\d{8})(.*)$', c)
			if not mx:
				mx = re.match(r'^[^@]+@FreeBSD\.org[\s-]+(\d{8})(.*)$', c)
			if mx:
				d = cls._fix_date(mx.group(1))
				return 'FreeBSD' if d is None else 'FreeBSD ({0})'.format(d)
			w = ['RemotelyAnywhere', 'DesktopAuthority', 'RemoteSupportManager']
			for win_soft in w:
				mx = re.match(r'^in ' + win_soft + r' ([\d\.]+\d)$', c)
				if mx:
					ver = mx.group(1)
					return 'Microsoft Windows ({0} {1})'.format(win_soft, ver)
			generic = ['NetBSD', 'FreeBSD']
			for g in generic:
				if c.startswith(g) or c.endswith(g):
					return g
			return None
		
		@classmethod
		def parse(cls, banner):
			# type: (SSH.Banner) -> SSH.Software
			# pylint: disable=too-many-return-statements
			software = str(banner.software)
			mx = re.match(r'^dropbear_([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'Matt Johnston', SSH.Product.DropbearSSH
				v = None
				return cls(v, p, mx.group(1), patch, None)
			mx = re.match(r'^OpenSSH[_\.-]+([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'OpenBSD', SSH.Product.OpenSSH
				v = None
				os_version = cls._extract_os_version(banner.comments)
				return cls(v, p, mx.group(1), patch, os_version)
			mx = re.match(r'^libssh-([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = None, SSH.Product.LibSSH
				os_version = cls._extract_os_version(banner.comments)
				return cls(v, p, mx.group(1), patch, os_version)
			mx = re.match(r'^RomSShell_([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'Allegro Software', 'RomSShell'
				return cls(v, p, mx.group(1), patch, None)
			mx = re.match(r'^mpSSH_([\d\.]+\d+)', software)
			if mx:
				v, p = 'HP', 'iLO (Integrated Lights-Out) sshd'
				return cls(v, p, mx.group(1), None, None)
			mx = re.match(r'^Cisco-([\d\.]+\d+)', software)
			if mx:
				v, p = 'Cisco', 'IOS/PIX sshd'
				return cls(v, p, mx.group(1), None, None)
			return None
	
	class Banner(object):
		_RXP, _RXR = r'SSH-\d\.\s*?\d+', r'(-\s*([^\s]*)(?:\s+(.*))?)?'
		RX_PROTOCOL = re.compile(re.sub(r'\\d(\+?)', r'(\\d\g<1>)', _RXP))
		RX_BANNER = re.compile(r'^({0}(?:(?:-{0})*)){1}$'.format(_RXP, _RXR))
		
		def __init__(self, protocol, software, comments, valid_ascii):
			# type: (Tuple[int, int], str, str, bool) -> None
			self.__protocol = protocol
			self.__software = software
			self.__comments = comments
			self.__valid_ascii = valid_ascii
		
		@property
		def protocol(self):
			# type: () -> Tuple[int, int]
			return self.__protocol
		
		@property
		def software(self):
			# type: () -> str
			return self.__software
		
		@property
		def comments(self):
			# type: () -> str
			return self.__comments
		
		@property
		def valid_ascii(self):
			# type: () -> bool
			return self.__valid_ascii
		
		def __str__(self):
			# type: () -> str
			r = 'SSH-{0}.{1}'.format(self.protocol[0], self.protocol[1])
			if self.software is not None:
				r += '-{0}'.format(self.software)
			if self.comments:
				r += ' {0}'.format(self.comments)
			return r
		
		def __repr__(self):
			# type: () -> str
			p = '{0}.{1}'.format(self.protocol[0], self.protocol[1])
			r = 'protocol={0}'.format(p)
			if self.software:
				r += ', software={0}'.format(self.software)
			if self.comments:
				r += ', comments={0}'.format(self.comments)
			return '<{0}({1})>'.format(self.__class__.__name__, r)
		
		@classmethod
		def parse(cls, banner):
			# type: (text_type) -> SSH.Banner
			valid_ascii = utils.is_ascii(banner)
			ascii_banner = utils.to_ascii(banner)
			mx = cls.RX_BANNER.match(ascii_banner)
			if mx is None:
				return None
			protocol = min(re.findall(cls.RX_PROTOCOL, mx.group(1)))
			protocol = (int(protocol[0]), int(protocol[1]))
			software = (mx.group(3) or '').strip() or None
			if software is None and (mx.group(2) or '').startswith('-'):
				software = ''
			comments = (mx.group(4) or '').strip() or None
			if comments is not None:
				comments = re.sub(r'\s+', ' ', comments)
			return cls(protocol, software, comments, valid_ascii)
	
	class Fingerprint(object):
		def __init__(self, fpd):
			# type: (binary_type) -> None
			self.__fpd = fpd
		
		@property
		def md5(self):
			# type: () -> text_type
			h = hashlib.md5(self.__fpd).hexdigest()
			r = u':'.join(h[i:i + 2] for i in range(0, len(h), 2))
			return u'MD5:{0}'.format(r)
		
		@property
		def sha256(self):
			# type: () -> text_type
			h = base64.b64encode(hashlib.sha256(self.__fpd).digest())
			r = h.decode('ascii').rstrip('=')
			return u'SHA256:{0}'.format(r)
	
	class Security(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		CVE = {
			'Dropbear SSH': [
				['0.44', '2015.71', 1, 'CVE-2016-3116', 5.5, 'bypass command restrictions via xauth command injection'],
				['0.28', '2013.58', 1, 'CVE-2013-4434', 5.0, 'discover valid usernames through different time delays'],
				['0.28', '2013.58', 1, 'CVE-2013-4421', 5.0, 'cause DoS (memory consumption) via a compressed packet'],
				['0.52', '2011.54', 1, 'CVE-2012-0920', 7.1, 'execute arbitrary code or bypass command restrictions'],
				['0.40', '0.48.1',  1, 'CVE-2007-1099', 7.5, 'conduct a MitM attack (no warning for hostkey mismatch)'],
				['0.28', '0.47',    1, 'CVE-2006-1206', 7.5, 'cause DoS (slot exhaustion) via large number of connections'],
				['0.39', '0.47',    1, 'CVE-2006-0225', 4.6, 'execute arbitrary commands via scp with crafted filenames'],
				['0.28', '0.46',    1, 'CVE-2005-4178', 6.5, 'execute arbitrary code via buffer overflow vulnerability'],
				['0.28', '0.42',    1, 'CVE-2004-2486', 7.5, 'execute arbitrary code via DSS verification code']],
			'libssh': [
				['0.1',   '0.7.2',  1, 'CVE-2016-0739', 4.3, 'conduct a MitM attack (weakness in DH key generation)'],
				['0.5.1', '0.6.4',  1, 'CVE-2015-3146', 5.0, 'cause DoS via kex packets (null pointer dereference)'],
				['0.5.1', '0.6.3',  1, 'CVE-2014-8132', 5.0, 'cause DoS via kex init packet (dangling pointer)'],
				['0.4.7', '0.6.2',  1, 'CVE-2014-0017', 1.9, 'leak data via PRNG state reuse on forking servers'],
				['0.4.7', '0.5.3',  1, 'CVE-2013-0176', 4.3, 'cause DoS via kex packet (null pointer dereference)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-6063', 7.5, 'cause DoS or execute arbitrary code via sftp (double free)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4562', 7.5, 'cause DoS or execute arbitrary code (overflow check)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4561', 5.0, 'cause DoS via unspecified vectors (invalid pointer)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4560', 7.5, 'cause DoS or execute arbitrary code (buffer overflow)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4559', 6.8, 'cause DoS or execute arbitrary code (double free)']]
		}  # type: Dict[str, List[List[Any]]]
		TXT = {
			'Dropbear SSH': [
				['0.28', '0.34', 1, 'remote root exploit', 'remote format string buffer overflow exploit (exploit-db#387)']],
			'libssh': [
				['0.3.3', '0.3.3', 1, 'null pointer check', 'missing null pointer check in "crypt_set_algorithms_server"'],
				['0.3.3', '0.3.3', 1, 'integer overflow',   'integer overflow in "buffer_get_data"'],
				['0.3.3', '0.3.3', 3, 'heap overflow',      'heap overflow in "packet_decrypt"']]
		}  # type: Dict[str, List[List[Any]]]
	
	class Socket(ReadBuf, WriteBuf):
		class InsufficientReadException(Exception):
			pass
		
		SM_BANNER_SENT = 1
		
		def __init__(self, host, port):
			# type: (str, int) -> None
			super(SSH.Socket, self).__init__()
			self.__block_size = 8
			self.__state = 0
			self.__header = []  # type: List[text_type]
			self.__banner = None  # type: Optional[SSH.Banner]
			self.__host = host
			self.__port = port
			self.__sock = None  # type: socket.socket
		
		def __enter__(self):
			# type: () -> SSH.Socket
			return self
		
		def _resolve(self, ipvo):
			# type: (Sequence[int]) -> Iterable[Tuple[int, Tuple[Any, ...]]]
			ipvo = tuple(filter(lambda x: x in (4, 6), utils.unique_seq(ipvo)))
			ipvo_len = len(ipvo)
			prefer_ipvo = ipvo_len > 0
			prefer_ipv4 = prefer_ipvo and ipvo[0] == 4
			if len(ipvo) == 1:
				family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(ipvo[0])
			else:
				family = socket.AF_UNSPEC
			try:
				stype = socket.SOCK_STREAM
				r = socket.getaddrinfo(self.__host, self.__port, family, stype)
				if prefer_ipvo:
					r = sorted(r, key=lambda x: x[0], reverse=not prefer_ipv4)
				check = any(stype == rline[2] for rline in r)
				for (af, socktype, proto, canonname, addr) in r:
					if not check or socktype == socket.SOCK_STREAM:
						yield (af, addr)
			except socket.error as e:
				out.fail('[exception] {0}'.format(e))
				sys.exit(1)
		
		def connect(self, ipvo=(), cto=3.0, rto=5.0):
			# type: (Sequence[int], float, float) -> None
			err = None
			for (af, addr) in self._resolve(ipvo):
				s = None
				try:
					s = socket.socket(af, socket.SOCK_STREAM)
					s.settimeout(cto)
					s.connect(addr)
					s.settimeout(rto)
					self.__sock = s
					return
				except socket.error as e:
					err = e
					self._close_socket(s)
			if err is None:
				errm = 'host {0} has no DNS records'.format(self.__host)
			else:
				errt = (self.__host, self.__port, err)
				errm = 'cannot connect to {0} port {1}: {2}'.format(*errt)
			out.fail('[exception] {0}'.format(errm))
			sys.exit(1)
		
		def get_banner(self, sshv=2):
			# type: (int) -> Tuple[Optional[SSH.Banner], List[text_type]]
			banner = 'SSH-{0}-OpenSSH_7.3'.format('1.5' if sshv == 1 else '2.0')
			rto = self.__sock.gettimeout()
			self.__sock.settimeout(0.7)
			s, e = self.recv()
			self.__sock.settimeout(rto)
			if s < 0:
				return self.__banner, self.__header
			if self.__state < self.SM_BANNER_SENT:
				self.send_banner(banner)
			while self.__banner is None:
				if not s > 0:
					s, e = self.recv()
					if s < 0:
						break
				while self.__banner is None and self.unread_len > 0:
					line = self.read_line()
					if len(line.strip()) == 0:
						continue
					if self.__banner is None:
						self.__banner = SSH.Banner.parse(line)
						if self.__banner is not None:
							continue
					self.__header.append(line)
				s = 0
			return self.__banner, self.__header
		
		def recv(self, size=2048):
			# type: (int) -> Tuple[int, Optional[str]]
			try:
				data = self.__sock.recv(size)
			except socket.timeout:
				return (-1, 'timeout')
			except socket.error as e:
				if e.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
					return (0, 'retry')
				return (-1, str(e.args[-1]))
			if len(data) == 0:
				return (-1, None)
			pos = self._buf.tell()
			self._buf.seek(0, 2)
			self._buf.write(data)
			self._len += len(data)
			self._buf.seek(pos, 0)
			return (len(data), None)
		
		def send(self, data):
			# type: (binary_type) -> Tuple[int, Optional[str]]
			try:
				self.__sock.send(data)
				return (0, None)
			except socket.error as e:
				return (-1, str(e.args[-1]))
			self.__sock.send(data)
		
		def send_banner(self, banner):
			# type: (str) -> None
			self.send(banner.encode() + b'\r\n')
			if self.__state < self.SM_BANNER_SENT:
				self.__state = self.SM_BANNER_SENT
		
		def ensure_read(self, size):
			# type: (int) -> None
			while self.unread_len < size:
				s, e = self.recv()
				if s < 0:
					raise SSH.Socket.InsufficientReadException(e)
		
		def read_packet(self, sshv=2):
			# type: (int) -> Tuple[int, binary_type]
			try:
				header = WriteBuf()
				self.ensure_read(4)
				packet_length = self.read_int()
				header.write_int(packet_length)
				# XXX: validate length
				if sshv == 1:
					padding_length = (8 - packet_length % 8)
					self.ensure_read(padding_length)
					padding = self.read(padding_length)
					header.write(padding)
					payload_length = packet_length
					check_size = padding_length + payload_length
				else:
					self.ensure_read(1)
					padding_length = self.read_byte()
					header.write_byte(padding_length)
					payload_length = packet_length - padding_length - 1
					check_size = 4 + 1 + payload_length + padding_length
				if check_size % self.__block_size != 0:
					out.fail('[exception] invalid ssh packet (block size)')
					sys.exit(1)
				self.ensure_read(payload_length)
				if sshv == 1:
					payload = self.read(payload_length - 4)
					header.write(payload)
					crc = self.read_int()
					header.write_int(crc)
				else:
					payload = self.read(payload_length)
					header.write(payload)
				packet_type = ord(payload[0:1])
				if sshv == 1:
					rcrc = SSH1.crc32(padding + payload)
					if crc != rcrc:
						out.fail('[exception] packet checksum CRC32 mismatch.')
						sys.exit(1)
				else:
					self.ensure_read(padding_length)
					padding = self.read(padding_length)
				payload = payload[1:]
				return packet_type, payload
			except SSH.Socket.InsufficientReadException as ex:
				if ex.args[0] is None:
					header.write(self.read(self.unread_len))
					e = header.write_flush().strip()
				else:
					e = ex.args[0].encode('utf-8')
				return (-1, e)
		
		def send_packet(self):
			# type: () -> Tuple[int, Optional[str]]
			payload = self.write_flush()
			padding = -(len(payload) + 5) % 8
			if padding < 4:
				padding += 8
			plen = len(payload) + padding + 1
			pad_bytes = b'\x00' * padding
			data = struct.pack('>Ib', plen, padding) + payload + pad_bytes
			return self.send(data)
		
		def _close_socket(self, s):
			# type: (Optional[socket.socket]) -> None
			try:
				if s is not None:
					s.shutdown(socket.SHUT_RDWR)
					s.close()
			except:  # pylint: disable=bare-except
				pass
		
		def __del__(self):
			# type: () -> None
			self.__cleanup()
		
		def __exit__(self, *args):
			# type: (*Any) -> None
			self.__cleanup()
		
		def __cleanup(self):
			# type: () -> None
			self._close_socket(self.__sock)


class KexDH(object):
	def __init__(self, alg, g, p):
		# type: (str, int, int) -> None
		self.__alg = alg
		self.__g = g
		self.__p = p
		self.__q = (self.__p - 1) // 2
		self.__x = None  # type: Optional[int]
		self.__e = None  # type: Optional[int]
	
	def send_init(self, s):
		# type: (SSH.Socket) -> None
		r = random.SystemRandom()
		self.__x = r.randrange(2, self.__q)
		self.__e = pow(self.__g, self.__x, self.__p)
		s.write_byte(SSH.Protocol.MSG_KEXDH_INIT)
		s.write_mpint2(self.__e)
		s.send_packet()


class KexGroup1(KexDH):
	def __init__(self):
		# type: () -> None
		# rfc2409: second oakley group
		p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67'
		        'cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6d'
		        'f25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff'
		        '5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381'
		        'ffffffffffffffff', 16)
		super(KexGroup1, self).__init__('sha1', 2, p)


class KexGroup14(KexDH):
	def __init__(self):
		# type: () -> None
		# rfc3526: 2048-bit modp group
		p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67'
		        'cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6d'
		        'f25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff'
		        '5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d'
		        'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3'
		        'ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08'
		        'ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c5'
		        '5df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510'
		        '15728e5a8aacaa68ffffffffffffffff', 16)
		super(KexGroup14, self).__init__('sha1', 2, p)


class KexDB(object):  # pylint: disable=too-few-public-methods
	# pylint: disable=bad-whitespace
	WARN_OPENSSH72_LEGACY = 'disabled (in client) since OpenSSH 7.2, legacy algorithm'
	FAIL_OPENSSH70_LEGACY = 'removed since OpenSSH 7.0, legacy algorithm'
	FAIL_OPENSSH70_WEAK   = 'removed (in server) and disabled (in client) since OpenSSH 7.0, weak algorithm'
	FAIL_OPENSSH70_LOGJAM = 'disabled (in client) since OpenSSH 7.0, logjam attack'
	INFO_OPENSSH69_CHACHA = 'default cipher since OpenSSH 6.9.'
	FAIL_OPENSSH67_UNSAFE = 'removed (in server) since OpenSSH 6.7, unsafe algorithm'
	FAIL_OPENSSH61_REMOVE = 'removed since OpenSSH 6.1, removed from specification'
	FAIL_OPENSSH31_REMOVE = 'removed since OpenSSH 3.1'
	FAIL_DBEAR67_DISABLED = 'disabled since Dropbear SSH 2015.67'
	FAIL_DBEAR53_DISABLED = 'disabled since Dropbear SSH 0.53'
	FAIL_PLAINTEXT        = 'no encryption/integrity'
	WARN_CURVES_WEAK      = 'using weak elliptic curves'
	WARN_RNDSIG_KEY       = 'using weak random number generator could reveal the key'
	WARN_MODULUS_SIZE     = 'using small 1024-bit modulus'
	WARN_MODULUS_CUSTOM   = 'using custom size modulus (possibly weak)'
	WARN_HASH_WEAK        = 'using weak hashing algorithm'
	WARN_CIPHER_MODE      = 'using weak cipher mode'
	WARN_BLOCK_SIZE       = 'using small 64-bit block size'
	WARN_CIPHER_WEAK      = 'using weak cipher'
	WARN_ENCRYPT_AND_MAC  = 'using encrypt-and-MAC mode'
	WARN_TAG_SIZE         = 'using small 64-bit tag size'

	ALGORITHMS = {
		'kex': {
			'diffie-hellman-group1-sha1': [['2.3.0,d0.28,l10.2', '6.6', '6.9'], [FAIL_OPENSSH67_UNSAFE, FAIL_OPENSSH70_LOGJAM], [WARN_MODULUS_SIZE, WARN_HASH_WEAK]],
			'diffie-hellman-group14-sha1': [['3.9,d0.53,l10.6.0'], [], [WARN_HASH_WEAK]],
			'diffie-hellman-group14-sha256': [['7.3,d2016.73']],
			'diffie-hellman-group16-sha512': [['7.3,d2016.73']],
			'diffie-hellman-group18-sha512': [['7.3']],
			'diffie-hellman-group-exchange-sha1': [['2.3.0', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_HASH_WEAK]],
			'diffie-hellman-group-exchange-sha256': [['4.4'], [], [WARN_MODULUS_CUSTOM]],
			'ecdh-sha2-nistp256': [['5.7,d2013.62,l10.6.0'], [WARN_CURVES_WEAK]],
			'ecdh-sha2-nistp384': [['5.7,d2013.62'], [WARN_CURVES_WEAK]],
			'ecdh-sha2-nistp521': [['5.7,d2013.62'], [WARN_CURVES_WEAK]],
			'curve25519-sha256@libssh.org': [['6.5,d2013.62,l10.6.0']],
			'kexguess2@matt.ucc.asn.au': [['d2013.57']],
		},
		'key': {
			'rsa-sha2-256': [['7.2']],
			'rsa-sha2-512': [['7.2']],
			'ssh-ed25519': [['6.5,l10.7.0']],
			'ssh-ed25519-cert-v01@openssh.com': [['6.5']],
			'ssh-rsa': [['2.5.0,d0.28,l10.2']],
			'ssh-dss': [['2.1.0,d0.28,l10.2', '6.9'], [FAIL_OPENSSH70_WEAK], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp256': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp384': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp521': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ssh-rsa-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_OPENSSH70_LEGACY], []],
			'ssh-dss-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_OPENSSH70_LEGACY], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ssh-rsa-cert-v01@openssh.com': [['5.6']],
			'ssh-dss-cert-v01@openssh.com': [['5.6', '6.9'], [FAIL_OPENSSH70_WEAK], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp256-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp384-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp521-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
		},
		'enc': {
			'none': [['1.2.2,d2013.56,l10.2'], [FAIL_PLAINTEXT]],
			'3des-cbc': [['1.2.2,d0.28,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_WEAK, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'3des-ctr': [['d0.52']],
			'blowfish-cbc': [['1.2.2,d0.28,l10.2', '6.6,d0.52', '7.1,d0.52'], [FAIL_OPENSSH67_UNSAFE, FAIL_DBEAR53_DISABLED], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'twofish-cbc': [['d0.28', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish128-cbc': [['d0.47', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish256-cbc': [['d0.47', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish128-ctr': [['d2015.68']],
			'twofish256-ctr': [['d2015.68']],
			'cast128-cbc': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'arcfour': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'arcfour128': [['4.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'arcfour256': [['4.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'aes128-cbc': [['2.3.0,d0.28,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'aes192-cbc': [['2.3.0,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'aes256-cbc': [['2.3.0,d0.47,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'rijndael128-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael192-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael256-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael-cbc@lysator.liu.se': [['2.3.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE]],
			'aes128-ctr': [['3.7,d0.52,l10.4.1']],
			'aes192-ctr': [['3.7,l10.4.1']],
			'aes256-ctr': [['3.7,d0.52,l10.4.1']],
			'aes128-gcm@openssh.com': [['6.2']],
			'aes256-gcm@openssh.com': [['6.2']],
			'chacha20-poly1305@openssh.com': [['6.5'], [], [], [INFO_OPENSSH69_CHACHA]],
		},
		'mac': {
			'none': [['d2013.56'], [FAIL_PLAINTEXT]],
			'hmac-sha1': [['2.1.0,d0.28,l10.2'], [], [WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-sha1-96': [['2.5.0,d0.47', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-sha2-256': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-256-96': [['5.9', '6.0'], [FAIL_OPENSSH61_REMOVE], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-512': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-512-96': [['5.9', '6.0'], [FAIL_OPENSSH61_REMOVE], [WARN_ENCRYPT_AND_MAC]],
			'hmac-md5': [['2.1.0,d0.28', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-md5-96': [['2.5.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-ripemd160': [['2.5.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC]],
			'hmac-ripemd160@openssh.com': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC]],
			'umac-64@openssh.com': [['4.7'], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
			'umac-128@openssh.com': [['6.2'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha1-etm@openssh.com': [['6.2'], [], [WARN_HASH_WEAK]],
			'hmac-sha1-96-etm@openssh.com': [['6.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_HASH_WEAK]],
			'hmac-sha2-256-etm@openssh.com': [['6.2']],
			'hmac-sha2-512-etm@openssh.com': [['6.2']],
			'hmac-md5-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK]],
			'hmac-md5-96-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK]],
			'hmac-ripemd160-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
			'umac-64-etm@openssh.com': [['6.2'], [], [WARN_TAG_SIZE]],
			'umac-128-etm@openssh.com': [['6.2']],
		}
	}  # type: Dict[str, Dict[str, List[List[str]]]]


def get_ssh_version(version_desc):
	# type: (str) -> Tuple[str, str]
	if version_desc.startswith('d'):
		return (SSH.Product.DropbearSSH, version_desc[1:])
	elif version_desc.startswith('l1'):
		return (SSH.Product.LibSSH, version_desc[2:])
	else:
		return (SSH.Product.OpenSSH, version_desc)


def get_alg_timeframe(versions, for_server=True, result=None):
	# type: (List[str], bool, Optional[Dict[str, List[Optional[str]]]]) -> Dict[str, List[Optional[str]]]
	result = result or {}
	vlen = len(versions)
	for i in range(3):
		if i > vlen - 1:
			if i == 2 and vlen > 1:
				cversions = versions[1]
			else:
				continue
		else:
			cversions = versions[i]
		if cversions is None:
			continue
		for v in cversions.split(','):
			ssh_prefix, ssh_version = get_ssh_version(v)
			if not ssh_version:
				continue
			if ssh_version.endswith('C'):
				if for_server:
					continue
				ssh_version = ssh_version[:-1]
			if ssh_prefix not in result:
				result[ssh_prefix] = [None, None, None]
			prev, push = result[ssh_prefix][i], False
			if prev is None:
				push = True
			elif i == 0 and prev < ssh_version:
				push = True
			elif i > 0 and prev > ssh_version:
				push = True
			if push:
				result[ssh_prefix][i] = ssh_version
	return result


def get_ssh_timeframe(alg_pairs, for_server=True):
	# type: (List[Tuple[int, Dict[str, Dict[str, List[List[str]]]], List[Tuple[str, List[text_type]]]]], bool) -> Dict[str, List[Optional[str]]]
	timeframe = {}  # type: Dict[str, List[Optional[str]]]
	for alg_pair in alg_pairs:
		alg_db = alg_pair[1]
		for alg_set in alg_pair[2]:
			alg_type, alg_list = alg_set
			for alg_name in alg_list:
				alg_name_native = utils.to_ntext(alg_name)
				alg_desc = alg_db[alg_type].get(alg_name_native)
				if alg_desc is None:
					continue
				versions = alg_desc[0]
				timeframe = get_alg_timeframe(versions, for_server, timeframe)
	return timeframe


def get_alg_since_text(versions):
	# type: (List[str]) -> text_type
	tv = []
	if len(versions) == 0 or versions[0] is None:
		return None
	for v in versions[0].split(','):
		ssh_prefix, ssh_version = get_ssh_version(v)
		if not ssh_version:
			continue
		if ssh_prefix in [SSH.Product.LibSSH]:
			continue
		if ssh_version.endswith('C'):
			ssh_version = '{0} (client only)'.format(ssh_version[:-1])
		tv.append('{0} {1}'.format(ssh_prefix, ssh_version))
	if len(tv) == 0:
		return None
	return 'available since ' + ', '.join(tv).rstrip(', ')


def get_alg_pairs(kex, pkm):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage]) -> List[Tuple[int, Dict[str, Dict[str, List[List[str]]]], List[Tuple[str, List[text_type]]]]]
	alg_pairs = []
	if pkm is not None:
		alg_pairs.append((1, SSH1.KexDB.ALGORITHMS,
		                  [('key', [u'ssh-rsa1']),
		                   ('enc', pkm.supported_ciphers),
		                   ('aut', pkm.supported_authentications)]))
	if kex is not None:
		alg_pairs.append((2, KexDB.ALGORITHMS,
		                  [('kex', kex.kex_algorithms),
		                   ('key', kex.key_algorithms),
		                   ('enc', kex.server.encryption),
		                   ('mac', kex.server.mac)]))
	return alg_pairs


def get_alg_recommendations(software, kex, pkm, for_server=True):
	# type: (SSH.Software, SSH2.Kex, SSH1.PublicKeyMessage, bool) -> Tuple[SSH.Software, Dict[int, Dict[str, Dict[str, Dict[str, int]]]]]
	# pylint: disable=too-many-locals,too-many-statements
	alg_pairs = get_alg_pairs(kex, pkm)
	vproducts = [SSH.Product.OpenSSH,
	             SSH.Product.DropbearSSH,
	             SSH.Product.LibSSH]
	if software is not None:
		if software.product not in vproducts:
			software = None
	if software is None:
		ssh_timeframe = get_ssh_timeframe(alg_pairs, for_server)
		for product in vproducts:
			if product not in ssh_timeframe:
				continue
			version = ssh_timeframe[product][0]
			if version is not None:
				software = SSH.Software(None, product, version, None, None)
				break
	rec = {}  # type: Dict[int, Dict[str, Dict[str, Dict[str, int]]]]
	if software is None:
		return software, rec
	for alg_pair in alg_pairs:
		sshv, alg_db = alg_pair[0], alg_pair[1]
		rec[sshv] = {}
		for alg_set in alg_pair[2]:
			alg_type, alg_list = alg_set
			if alg_type == 'aut':
				continue
			rec[sshv][alg_type] = {'add': {}, 'del': {}}
			for n, alg_desc in alg_db[alg_type].items():
				if alg_type == 'key' and '-cert-' in n:
					continue
				versions = alg_desc[0]
				if len(versions) == 0 or versions[0] is None:
					continue
				matches = False
				for v in versions[0].split(','):
					ssh_prefix, ssh_version = get_ssh_version(v)
					if not ssh_version:
						continue
					if ssh_prefix != software.product:
						continue
					if ssh_version.endswith('C'):
						if for_server:
							continue
						ssh_version = ssh_version[:-1]
					if software.compare_version(ssh_version) < 0:
						continue
					matches = True
					break
				if not matches:
					continue
				adl, faults = len(alg_desc), 0
				for i in range(1, 3):
					if not adl > i:
						continue
					fc = len(alg_desc[i])
					if fc > 0:
						faults += pow(10, 2 - i) * fc
				if n not in alg_list:
					if faults > 0:
						continue
					rec[sshv][alg_type]['add'][n] = 0
				else:
					if faults == 0:
						continue
					if n == 'diffie-hellman-group-exchange-sha256':
						if software.compare_version('7.3') < 0:
							continue
					rec[sshv][alg_type]['del'][n] = faults
			add_count = len(rec[sshv][alg_type]['add'])
			del_count = len(rec[sshv][alg_type]['del'])
			new_alg_count = len(alg_list) + add_count - del_count
			if new_alg_count < 1 and del_count > 0:
				mf = min(rec[sshv][alg_type]['del'].values())
				new_del = {}
				for k, cf in rec[sshv][alg_type]['del'].items():
					if cf != mf:
						new_del[k] = cf
				if del_count != len(new_del):
					rec[sshv][alg_type]['del'] = new_del
					new_alg_count += del_count - len(new_del)
			if new_alg_count < 1:
				del rec[sshv][alg_type]
			else:
				if add_count == 0:
					del rec[sshv][alg_type]['add']
				if del_count == 0:
					del rec[sshv][alg_type]['del']
				if len(rec[sshv][alg_type]) == 0:
					del rec[sshv][alg_type]
		if len(rec[sshv]) == 0:
			del rec[sshv]
	return software, rec


def output_algorithms(title, alg_db, alg_type, algorithms, maxlen=0):
	# type: (str, Dict[str, Dict[str, List[List[str]]]], str, List[text_type], int) -> None
	with OutputBuffer() as obuf:
		for algorithm in algorithms:
			output_algorithm(alg_db, alg_type, algorithm, maxlen)
	if len(obuf) > 0:
		out.head('# ' + title)
		obuf.flush()
		out.sep()


def output_algorithm(alg_db, alg_type, alg_name, alg_max_len=0):
	# type: (Dict[str, Dict[str, List[List[str]]]], str, text_type, int) -> None
	prefix = '(' + alg_type + ') '
	if alg_max_len == 0:
		alg_max_len = len(alg_name)
	padding = '' if out.batch else ' ' * (alg_max_len - len(alg_name))
	texts = []
	if len(alg_name.strip()) == 0:
		return
	alg_name_native = utils.to_ntext(alg_name)
	if alg_name_native in alg_db[alg_type]:
		alg_desc = alg_db[alg_type][alg_name_native]
		ldesc = len(alg_desc)
		for idx, level in enumerate(['fail', 'warn', 'info']):
			if level == 'info':
				versions = alg_desc[0]
				since_text = get_alg_since_text(versions)
				if since_text:
					texts.append((level, since_text))
			idx = idx + 1
			if ldesc > idx:
				for t in alg_desc[idx]:
					texts.append((level, t))
		if len(texts) == 0:
			texts.append(('info', ''))
	else:
		texts.append(('warn', 'unknown algorithm'))
	first = True
	for (level, text) in texts:
		f = getattr(out, level)
		text = '[' + level + '] ' + text
		if first:
			if first and level == 'info':
				f = out.good
			f(prefix + alg_name + padding + ' -- ' + text)
			first = False
		else:
			if out.verbose:
				f(prefix + alg_name + padding + ' -- ' + text)
			else:
				f(' ' * len(prefix + alg_name) + padding + ' `- ' + text)


def output_compatibility(kex, pkm, for_server=True):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage], bool) -> None
	alg_pairs = get_alg_pairs(kex, pkm)
	ssh_timeframe = get_ssh_timeframe(alg_pairs, for_server)
	vp = 1 if for_server else 2
	comp_text = []
	for sshd_name in [SSH.Product.OpenSSH, SSH.Product.DropbearSSH]:
		if sshd_name not in ssh_timeframe:
			continue
		v = ssh_timeframe[sshd_name]
		if v[vp] is None:
			comp_text.append('{0} {1}+'.format(sshd_name, v[0]))
		elif v[0] == v[vp]:
			comp_text.append('{0} {1}'.format(sshd_name, v[0]))
		else:
			if v[vp] < v[0]:
				tfmt = '{0} {1}+ (some functionality from {2})'
			else:
				tfmt = '{0} {1}-{2}'
			comp_text.append(tfmt.format(sshd_name, v[0], v[vp]))
	if len(comp_text) > 0:
		out.good('(gen) compatibility: ' + ', '.join(comp_text))


def output_security_sub(sub, software, padlen):
	# type: (str, SSH.Software, int) -> None
	secdb = SSH.Security.CVE if sub == 'cve' else SSH.Security.TXT
	if software is None or software.product not in secdb:
		return
	for line in secdb[software.product]:
		vfrom, vtill = line[0:2]  # type: str, str
		if not software.between_versions(vfrom, vtill):
			continue
		target, name = line[2:4]  # type: int, str
		is_server, is_client = target & 1 == 1, target & 2 == 2
		is_local = target & 4 == 4
		if not is_server:
			continue
		p = '' if out.batch else ' ' * (padlen - len(name))
		if sub == 'cve':
			cvss, descr = line[4:6]  # type: float, str
			out.fail('(cve) {0}{1} -- ({2}) {3}'.format(name, p, cvss, descr))
		else:
			descr = line[4]
			out.fail('(sec) {0}{1} -- {2}'.format(name, p, descr))


def output_security(banner, padlen):
	# type: (SSH.Banner, int) -> None
	with OutputBuffer() as obuf:
		if banner:
			software = SSH.Software.parse(banner)
			output_security_sub('cve', software, padlen)
			output_security_sub('txt', software, padlen)
	if len(obuf) > 0:
		out.head('# security')
		obuf.flush()
		out.sep()


def output_fingerprint(kex, pkm, sha256=True, padlen=0):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage], bool, int) -> None
	with OutputBuffer() as obuf:
		fps = []
		if pkm is not None:
			name = 'ssh-rsa1'
			fp = SSH.Fingerprint(pkm.host_key_fingerprint_data)
			bits = pkm.host_key_bits
			fps.append((name, fp, bits))
		for fpp in fps:
			name, fp, bits = fpp
			fpo = fp.sha256 if sha256 else fp.md5
			p = '' if out.batch else ' ' * (padlen - len(name))
			out.good('(fin) {0}{1} -- {2} {3}'.format(name, p, bits, fpo))
	if len(obuf) > 0:
		out.head('# fingerprints')
		obuf.flush()
		out.sep()


def output_recommendations(software, kex, pkm, padlen=0):
	# type: (SSH.Software, SSH2.Kex, SSH1.PublicKeyMessage, int) -> None
	for_server = True
	with OutputBuffer() as obuf:
		software, alg_rec = get_alg_recommendations(software, kex, pkm, for_server)
		for sshv in range(2, 0, -1):
			if sshv not in alg_rec:
				continue
			for alg_type in ['kex', 'key', 'enc', 'mac']:
				if alg_type not in alg_rec[sshv]:
					continue
				for action in ['del', 'add']:
					if action not in alg_rec[sshv][alg_type]:
						continue
					for name in alg_rec[sshv][alg_type][action]:
						p = '' if out.batch else ' ' * (padlen - len(name))
						if action == 'del':
							an, sg, fn = 'remove', '-', out.warn
							if alg_rec[sshv][alg_type][action][name] >= 10:
								fn = out.fail
						else:
							an, sg, fn = 'append', '+', out.good
						b = '(SSH{0})'.format(sshv) if sshv == 1 else ''
						fm = '(rec) {0}{1}{2}-- {3} algorithm to {4} {5}'
						fn(fm.format(sg, name, p, alg_type, an, b))
	if len(obuf) > 0:
		title = '(for {0})'.format(software.display(False)) if software else ''
		out.head('# algorithm recommendations {0}'.format(title))
		obuf.flush()
		out.sep()


def output(banner, header, kex=None, pkm=None):
	# type: (Optional[SSH.Banner], List[text_type], Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage]) -> None
	sshv = 1 if pkm else 2
	with OutputBuffer() as obuf:
		if len(header) > 0:
			out.info('(gen) header: ' + '\n'.join(header))
		if banner is not None:
			out.good('(gen) banner: {0}'.format(banner))
			if not banner.valid_ascii:
				# NOTE: RFC 4253, Section 4.2
				out.warn('(gen) banner contains non-printable ASCII')
			if sshv == 1 or banner.protocol[0] == 1:
				out.fail('(gen) protocol SSH1 enabled')
			software = SSH.Software.parse(banner)
			if software is not None:
				out.good('(gen) software: {0}'.format(software))
		else:
			software = None
		output_compatibility(kex, pkm)
		if kex is not None:
			compressions = [x for x in kex.server.compression if x != 'none']
			if len(compressions) > 0:
				cmptxt = 'enabled ({0})'.format(', '.join(compressions))
			else:
				cmptxt = 'disabled'
			out.good('(gen) compression: {0}'.format(cmptxt))
	if len(obuf) > 0:
		out.head('# general')
		obuf.flush()
		out.sep()
	ml, maxlen = lambda l: max(len(i) for i in l), 0
	if pkm is not None:
		maxlen = max(ml(pkm.supported_ciphers),
		             ml(pkm.supported_authentications),
		             maxlen)
	if kex is not None:
		maxlen = max(ml(kex.kex_algorithms),
		             ml(kex.key_algorithms),
		             ml(kex.server.encryption),
		             ml(kex.server.mac),
		             maxlen)
	maxlen += 1
	output_security(banner, maxlen)
	if pkm is not None:
		adb = SSH1.KexDB.ALGORITHMS
		ciphers = pkm.supported_ciphers
		auths = pkm.supported_authentications
		title, atype = 'SSH1 host-key algorithms', 'key'
		output_algorithms(title, adb, atype, ['ssh-rsa1'], maxlen)
		title, atype = 'SSH1 encryption algorithms (ciphers)', 'enc'
		output_algorithms(title, adb, atype, ciphers, maxlen)
		title, atype = 'SSH1 authentication types', 'aut'
		output_algorithms(title, adb, atype, auths, maxlen)
	if kex is not None:
		adb = KexDB.ALGORITHMS
		title, atype = 'key exchange algorithms', 'kex'
		output_algorithms(title, adb, atype, kex.kex_algorithms, maxlen)
		title, atype = 'host-key algorithms', 'key'
		output_algorithms(title, adb, atype, kex.key_algorithms, maxlen)
		title, atype = 'encryption algorithms (ciphers)', 'enc'
		output_algorithms(title, adb, atype, kex.server.encryption, maxlen)
		title, atype = 'message authentication code algorithms', 'mac'
		output_algorithms(title, adb, atype, kex.server.mac, maxlen)
	output_recommendations(software, kex, pkm, maxlen)
	output_fingerprint(kex, pkm, True, maxlen)


class Utils(object):
	@classmethod
	def _type_err(cls, v, target):
		# type: (Any, text_type) -> TypeError
		return TypeError('cannot convert {0} to {1}'.format(type(v), target))
	
	@classmethod
	def to_bytes(cls, v, enc='utf-8'):
		# type: (Union[binary_type, text_type], str) -> binary_type
		if isinstance(v, binary_type):
			return v
		elif isinstance(v, text_type):
			return v.encode(enc)
		raise cls._type_err(v, 'bytes')
	
	@classmethod
	def to_utext(cls, v, enc='utf-8'):
		# type: (Union[text_type, binary_type], str) -> text_type
		if isinstance(v, text_type):
			return v
		elif isinstance(v, binary_type):
			return v.decode(enc)
		raise cls._type_err(v, 'unicode text')
	
	@classmethod
	def to_ntext(cls, v, enc='utf-8'):
		# type: (Union[text_type, binary_type], str) -> str
		if isinstance(v, str):
			return v
		elif isinstance(v, text_type):
			return v.encode(enc)
		elif isinstance(v, binary_type):
			return v.decode(enc)
		raise cls._type_err(v, 'native text')
	
	@classmethod
	def is_ascii(cls, v):
		# type: (Union[text_type, str]) -> bool
		try:
			if isinstance(v, (text_type, str)):
				v.encode('ascii')
				return True
		except UnicodeEncodeError:
			pass
		return False
	
	@classmethod
	def to_ascii(cls, v, errors='replace'):
		# type: (Union[text_type, str], str) -> str
		if isinstance(v, (text_type, str)):
			return cls.to_ntext(v.encode('ascii', errors))
		raise cls._type_err(v, 'ascii')
	
	@classmethod
	def unique_seq(cls, seq):
		# type: (Sequence[Any]) -> Sequence[Any]
		seen = set()  # type: Set[Any]
		
		def _seen_add(x):
			# type: (Any) -> bool
			seen.add(x)
			return False
		
		if isinstance(seq, tuple):
			return tuple(x for x in seq if x not in seen and not _seen_add(x))
		else:
			return [x for x in seq if x not in seen and not _seen_add(x)]
		
	@staticmethod
	def parse_int(v):
		# type: (Any) -> int
		try:
			return int(v)
		except:  # pylint: disable=bare-except
			return 0


def audit(aconf, sshv=None):
	# type: (AuditConf, Optional[int]) -> None
	out.batch = aconf.batch
	out.colors = aconf.colors
	out.verbose = aconf.verbose
	out.minlevel = aconf.minlevel
	s = SSH.Socket(aconf.host, aconf.port)
	s.connect(aconf.ipvo)
	if sshv is None:
		sshv = 2 if aconf.ssh2 else 1
	err = None
	banner, header = s.get_banner(sshv)
	if banner is None:
		err = '[exception] did not receive banner.'
	if err is None:
		packet_type, payload = s.read_packet(sshv)
		if packet_type < 0:
			try:
				payload_txt = payload.decode('utf-8') if payload else u'empty'
			except UnicodeDecodeError:
				payload_txt = u'"{0}"'.format(repr(payload).lstrip('b')[1:-1])
			if payload_txt == u'Protocol major versions differ.':
				if sshv == 2 and aconf.ssh1:
					audit(aconf, 1)
					return
			err = '[exception] error reading packet ({0})'.format(payload_txt)
		else:
			err_pair = None
			if sshv == 1 and packet_type != SSH.Protocol.SMSG_PUBLIC_KEY:
				err_pair = ('SMSG_PUBLIC_KEY', SSH.Protocol.SMSG_PUBLIC_KEY)
			elif sshv == 2 and packet_type != SSH.Protocol.MSG_KEXINIT:
				err_pair = ('MSG_KEXINIT', SSH.Protocol.MSG_KEXINIT)
			if err_pair is not None:
				fmt = '[exception] did not receive {0} ({1}), ' + \
				      'instead received unknown message ({2})'
				err = fmt.format(err_pair[0], err_pair[1], packet_type)
	if err:
		output(banner, header)
		out.fail(err)
		sys.exit(1)
	if sshv == 1:
		pkm = SSH1.PublicKeyMessage.parse(payload)
		output(banner, header, pkm=pkm)
	elif sshv == 2:
		kex = SSH2.Kex.parse(payload)
		output(banner, header, kex=kex)


utils = Utils()
out = Output()
if __name__ == '__main__':  # pragma: nocover
	conf = AuditConf.from_cmdline(sys.argv[1:], usage)
	audit(conf)
http://www.com.orgREADME.md?!Swing
# Helloworld
  
story.txt
story-joe-edit.txt
story-joe-edit-reviewed.txt.ONIOn<!doctype html><html lang="en" dir="ltr"><head><base href=""><meta name=","spriteMapCssClass" content="origin"><meta name"Cl_WateneJLHetarakaupload" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no,minimal-ui"><script data-id="_gd" nonce="xej/mhctshus9j0d15vFcQ">window.WIZ_global_data = {"DpimGf":false,"EP1ykd":["/_/*"],"FdrFJe":"6977609033182962089","Im6cmf":"/_/AlbumArchiveUi","LVIXXb":1,"LoQv7e":false,"MT7f9b":[],"Pttpvd":"https://connect.corp.google.com/","QrtxK":"0","S06Grb":"107520105256516223064","SNlM0e":"ALbF8-4W_VcFQqwoehuftqjM4JGb:1609241226268","W3Yyqf":"107520105256516223064","WZsZ1e":"9ZLxemyObwl_vk_b/AdZcbDRW0AopifO6w","Yllh3e":"%.@.1609241226228633,181269975,3137833681]\n","bBcEs":"https://contacts.google.com/","cfb2h":"boq_albumarchiveuiserver_20201215.12_p0","eNnkwf":"1602819395","eptZe":"/_/AlbumArchiveUi/","fPDxwd":[1757124,1763433,1772879,45695529],"gGcLoe":false,"hnFr6d":false,"nQyAE":{"vWC9Rb":"false","wcLcde":"false","tBSlob":"false","nLDTQc":"true","cGSqpd":"true","LvMi4d":"true","oOXhbd":"true","Sbbprb":"true","d1Odc":"false","cePL0c":"false","x4TKvb":"true","mESuwf":"true","Ggrurf":"true","q6pjnb":"false","Kc1pKb":"true","GObJC":"false","IWl9re":"true","HtZWzd":"true","vS2I5e":"false","xmeGFd":"true","SukQce":"true","V69nKf":"false","EDlgQe":"true","F9tFpd":"false","D1bn1b":"false","Y1RXe":"false"},"oPEP7c":"watenehetaraka@gmail.com","qDCSke":"107520105256516223064","qwAQke":"AlbumArchiveUi","qymVe":"98UDn1nUu4bnWPoUMrD7a_GIu_M","rtQCxc":-780,"w2btAe":"%.@.\"107520105256516223064\",\"107520105256516223064\",\"0\",false,null,null,true,false]\n","zChJod":"%.@.]\n"};</script><script nonce="xej/mhctshus9j0d15vFcQ">(function(){/*

 Rights Reserved The Closure Library Authors.
 SPDX-License-Identifier: Apache-2.0
*/
'use strict';var a=window,d=a.performance,l=k();a.cc_latency_start_time=d&&d.now?0:d&&d.timing&&d.timing.navigationStart?d.timing.navigationStart:l;function k(){return d&&d.now?d.now():(new Date).getTime()}function n(f){if(d&&d.now&&d.mark){var h=d.mark(f);if(h)return h.startTime;if(d.getEntriesByName&&(f=d.getEntriesByName(f).pop()))return f.startTime}return k()}a.onaft=function(){n("aft");a.isPreloadSupported&&a.executeBaseJs()};
a._isLazyImage=function(f){return f.hasAttribute("data-src")||f.hasAttribute("data-ils")||"lazy"===f.getAttribute("loading")};
a.l=function(f){function h(b){var c={};c[b]=k();a.cc_latency.push(c)}function m(b){var c=n("iml");b.setAttribute("data-iml",c);return c}a.cc_aid=f;a.iml_start=a.cc_latency_start_time;a.css_size=0;a.cc_latency=[];a.ccTick=h;a.onJsLoad=function(){h("jsl")};a.onCssLoad=function(){h("cssl")};a._isVisible=function(b,c,g){g=void 0===g?!1:g;if(!c||"none"==c.style.display)return!1;var e=b.defaultView;if(e&&e.getComputedStyle&&(e=e.getComputedStyle(c),"0px"==e.height||"0px"==e.width||"hidden"==e.visibility&&
!g))return!1;if(!c.getBoundingClientRect)return!0;e=c.getBoundingClientRect();c=e.left+a.pageXOffset;g=e.top+a.pageYOffset;if(0>g+e.height||0>c+e.width||0>=e.height||0>=e.width)return!1;b=b.documentElement;return g<=(a.innerHeight||b.clientHeight)&&c<=(a.innerWidth||b.clientWidth)};a._recordImlEl=m;document.documentElement.addEventListener("load",function(b){b=b.target;var c;"IMG"!=b.tagName||b.hasAttribute("data-iid")||a._isLazyImage(b)||b.hasAttribute("data-noaft")||(c=m(b));if(a.aft_counter&&(b=
a.aft_counter.indexOf(b),-1!==b&&(b=1===a.aft_counter.splice(b,1).length,0===a.aft_counter.length&&b&&c)))a.onaft(c)},!0);a.prt=-1;a.wiz_tick=function(){var b=n("prt");a.prt=b}};}).call(this);
l('Gd6Xvc')</script><script nonce="xej/mhctshus9j0d15vFcQ">var _F_cssRowKey = 'boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O';var _F_combinedSignature = 'AGLTcCPZ2x_2zvQrm5mwYxqoiwtj7H6hfA';function _DumpException(e) {throw e;}</script><style data-href="/_/scs/social-static/_/ss/k=boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O/am=fSUCMLsD_P8L-P-___-Vf__vBwE/d=1/ed=1/ct=zgms/rs=AGLTcCO_Q2oMnHe9dqvwz3ANleWrRWQgxg/m=landingview,_b,_tp" nonce="xej/mhctshus9j0d15vFcQ">html{height:100%;overflow:hidden}body{height:100%;overflow:hidden;-webkit-font-smoothing:antialiased;color:rgba(0,0,0,0.87);font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;margin:0;text-size-adjust:100%}textarea{font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif}a{text-decoration:none;color:#2962ff}img{border:none}*{-webkit-tap-highlight-color:transparent}#apps-debug-tracers{display:none}@keyframes mdc-ripple-fg-radius-in{0%{animation-timing-function:cubic-bezier(0.4,0,0.2,1);transform:translate(var(--mdc-ripple-fg-translate-start,0)) scale(1)}to{transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}}@keyframes mdc-ripple-fg-opacity-in{0%{animation-timing-function:linear;opacity:0}to{opacity:var(--mdc-ripple-fg-opacity,0)}}@keyframes mdc-ripple-fg-opacity-out{0%{animation-timing-function:linear;opacity:var(--mdc-ripple-fg-opacity,0)}to{opacity:0}}.VfPpkd-ksKsZd-XxIAqe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity;position:relative;outline:none;overflow:hidden}.VfPpkd-ksKsZd-XxIAqe::before{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-ksKsZd-XxIAqe::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-ksKsZd-XxIAqe::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-ksKsZd-XxIAqe::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::after{top:0;left:0;transform:scale(0);transform-origin:center center}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-ksKsZd-XxIAqe::before{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-ksKsZd-XxIAqe::after{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-ksKsZd-XxIAqe:hover::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d):focus::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d)::after{transition:opacity 150ms linear}.VfPpkd-ksKsZd-XxIAqe:not(.VfPpkd-ksKsZd-mWPk3d):active::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-ksKsZd-XxIAqe::before{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-ksKsZd-XxIAqe::after{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-ksKsZd-XxIAqe.VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded],.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd{overflow:visible}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded]::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded]::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%))}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%))}.VfPpkd-ksKsZd-XxIAqe[data-mdc-ripple-is-unbounded].VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd.VfPpkd-ksKsZd-mWPk3d::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-dgl2Hf-ppHlrf-sM5MNb{display:inline}.VfPpkd-LgbsSe{-webkit-font-smoothing:antialiased;font-family:Roboto,sans-serif;font-family:var(--mdc-typography-button-font-family,var(--mdc-typography-font-family,Roboto,sans-serif));font-size:.875rem;font-size:var(--mdc-typography-button-font-size,0.875rem);line-height:2.25rem;line-height:var(--mdc-typography-button-line-height,2.25rem);font-weight:500;font-weight:var(--mdc-typography-button-font-weight,500);letter-spacing:.0892857143em;letter-spacing:var(--mdc-typography-button-letter-spacing,0.0892857143em);text-decoration:none;text-decoration:var(--mdc-typography-button-text-decoration,none);text-transform:uppercase;text-transform:var(--mdc-typography-button-text-transform,uppercase);padding:0 8px 0 8px;position:relative;display:-webkit-inline-box;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-width:64px;border:none;outline:none;line-height:inherit;-webkit-user-select:none;-webkit-appearance:none;overflow:visible;vertical-align:middle;border-radius:4px;border-radius:var(--mdc-shape-small,4px);height:36px}.VfPpkd-LgbsSe .VfPpkd-BFbNVe-bF1uUb{width:100%;height:100%;top:0;left:0}.VfPpkd-LgbsSe::-moz-focus-inner{padding:0;border:0}.VfPpkd-LgbsSe:active{outline:none}.VfPpkd-LgbsSe:hover{cursor:pointer}.VfPpkd-LgbsSe:disabled{cursor:default;pointer-events:none}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc{border-radius:4px;border-radius:var(--mdc-shape-small,4px)}.VfPpkd-LgbsSe:not(:disabled),.VfPpkd-LgbsSe:disabled{background-color:transparent}.VfPpkd-LgbsSe .VfPpkd-kBDsod{margin-left:0;margin-right:8px;display:inline-block;width:18px;height:18px;font-size:18px;vertical-align:top}[dir=rtl] .VfPpkd-LgbsSe .VfPpkd-kBDsod,.VfPpkd-LgbsSe .VfPpkd-kBDsod[dir=rtl]{margin-left:8px;margin-right:0}.VfPpkd-LgbsSe .VfPpkd-RLmnJb{position:absolute;top:50%;right:0;height:48px;left:0;transform:translateY(-50%)}.VfPpkd-LgbsSe:not(:disabled){color:#6200ee;color:var(--mdc-theme-primary,#6200ee)}.VfPpkd-LgbsSe:disabled{color:rgba(0,0,0,0.38)}.VfPpkd-vQzf8d+.VfPpkd-kBDsod{margin-left:8px;margin-right:0}[dir=rtl] .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl]{margin-left:0;margin-right:8px}svg.VfPpkd-kBDsod{fill:currentColor}.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod{margin-left:-4px;margin-right:8px}[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-kBDsod[dir=rtl],.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod{margin-left:8px;margin-right:-4px}[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl],[dir=rtl] .VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod,.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-vQzf8d+.VfPpkd-kBDsod[dir=rtl]{margin-left:-4px;margin-right:8px}.VfPpkd-LgbsSe-OWXEXe-MV7yeb,.VfPpkd-LgbsSe-OWXEXe-k8QpJ{padding:0 16px 0 16px}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(:disabled){background-color:#6200ee;background-color:var(--mdc-theme-primary,#6200ee)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(:disabled){color:#fff;color:var(--mdc-theme-on-primary,#fff)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:disabled{background-color:rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:disabled{color:rgba(0,0,0,0.38)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb{box-shadow:0 3px 1px -2px rgba(0,0,0,0.2),0 2px 2px 0 rgba(0,0,0,0.14),0 1px 5px 0 rgba(0,0,0,0.12);transition:box-shadow 280ms cubic-bezier(0.4,0,0.2,1)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:hover,.VfPpkd-LgbsSe-OWXEXe-MV7yeb:focus{box-shadow:0 2px 4px -1px rgba(0,0,0,0.2),0 4px 5px 0 rgba(0,0,0,0.14),0 1px 10px 0 rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:active{box-shadow:0 5px 5px -3px rgba(0,0,0,0.2),0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:disabled{box-shadow:0 0 0 0 rgba(0,0,0,0.2),0 0 0 0 rgba(0,0,0,0.14),0 0 0 0 rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-INsAgc{padding:0 15px 0 15px;border-width:1px;border-style:solid}.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-Jh9lGc{top:-1px;left:-1px;border:1px solid transparent}.VfPpkd-LgbsSe-OWXEXe-INsAgc .VfPpkd-RLmnJb{left:-1px;width:calc(100% + 2*1px)}.VfPpkd-LgbsSe-OWXEXe-INsAgc:not(:disabled),.VfPpkd-LgbsSe-OWXEXe-INsAgc:disabled{border-color:rgba(0,0,0,0.12)}.VfPpkd-LgbsSe-OWXEXe-dgl2Hf{margin-top:6px;margin-bottom:6px}.VfPpkd-LgbsSe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::after{top:0;left:0;transform:scale(0);transform-origin:center center}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd .VfPpkd-Jh9lGc::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc .VfPpkd-Jh9lGc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf .VfPpkd-Jh9lGc::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{top:calc(50% - 100%);left:calc(50% - 100%);width:200%;height:200%}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d .VfPpkd-Jh9lGc::after{width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe .VfPpkd-Jh9lGc::after{background-color:#6200ee;background-color:var(--mdc-ripple-color,var(--mdc-theme-primary,#6200ee))}.VfPpkd-LgbsSe:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.VfPpkd-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-LgbsSe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-LgbsSe .VfPpkd-Jh9lGc{position:absolute;box-sizing:content-box;width:100%;height:100%;overflow:hidden}.VfPpkd-LgbsSe:not(.VfPpkd-LgbsSe-OWXEXe-INsAgc) .VfPpkd-Jh9lGc{top:0;left:0}.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-MV7yeb .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ .VfPpkd-Jh9lGc::after{background-color:#fff;background-color:var(--mdc-ripple-color,var(--mdc-theme-on-primary,#fff))}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:hover .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:hover .VfPpkd-Jh9lGc::before{opacity:.08;opacity:var(--mdc-ripple-hover-opacity,0.08)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-focus-opacity,0.24)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.VfPpkd-LgbsSe-OWXEXe-MV7yeb:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after,.VfPpkd-LgbsSe-OWXEXe-k8QpJ:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-press-opacity,0.24)}.VfPpkd-LgbsSe-OWXEXe-MV7yeb.VfPpkd-ksKsZd-mWPk3d,.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.24)}.VfPpkd-Bz112c-LgbsSe{display:inline-block;position:relative;box-sizing:border-box;border:none;outline:none;background-color:transparent;fill:currentColor;color:inherit;font-size:24px;text-decoration:none;cursor:pointer;-webkit-user-select:none;width:48px;height:48px;padding:12px}.VfPpkd-Bz112c-LgbsSe svg,.VfPpkd-Bz112c-LgbsSe img{width:24px;height:24px}.VfPpkd-Bz112c-LgbsSe:disabled{color:rgba(0,0,0,0.38);color:var(--mdc-theme-text-disabled-on-light,rgba(0,0,0,0.38));cursor:default;pointer-events:none}.VfPpkd-Bz112c-kBDsod{display:inline-block}.VfPpkd-Bz112c-kBDsod.VfPpkd-Bz112c-kBDsod-OWXEXe-IT5dJd,.VfPpkd-Bz112c-LgbsSe-OWXEXe-IT5dJd .VfPpkd-Bz112c-kBDsod{display:none}.VfPpkd-Bz112c-LgbsSe-OWXEXe-IT5dJd .VfPpkd-Bz112c-kBDsod.VfPpkd-Bz112c-kBDsod-OWXEXe-IT5dJd{display:inline-block}.VfPpkd-Bz112c-LgbsSe{--mdc-ripple-fg-size:0;--mdc-ripple-left:0;--mdc-ripple-top:0;--mdc-ripple-fg-scale:1;--mdc-ripple-fg-translate-end:0;--mdc-ripple-fg-translate-start:0;-webkit-tap-highlight-color:rgba(0,0,0,0);will-change:transform,opacity}.VfPpkd-Bz112c-LgbsSe::before{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-Bz112c-LgbsSe::after{position:absolute;border-radius:50%;opacity:0;pointer-events:none;content:""}.VfPpkd-Bz112c-LgbsSe::before{transition:opacity 15ms linear,background-color 15ms linear;z-index:1;z-index:var(--mdc-ripple-z-index,1)}.VfPpkd-Bz112c-LgbsSe::after{z-index:0;z-index:var(--mdc-ripple-z-index,0)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::before{transform:scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::after{transform:scale(0);transform-origin:center center}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-ZNMTqd::after{top:var(--mdc-ripple-top,0);left:var(--mdc-ripple-left,0)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-lJfZMc::after{animation:mdc-ripple-fg-radius-in 225ms forwards,mdc-ripple-fg-opacity-in 75ms forwards}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-Tv8l5d-OmS1vf::after{animation:mdc-ripple-fg-opacity-out 150ms;transform:translate(var(--mdc-ripple-fg-translate-end,0)) scale(var(--mdc-ripple-fg-scale,1))}.VfPpkd-Bz112c-LgbsSe::before{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-Bz112c-LgbsSe::after{top:calc(50% - 50%);left:calc(50% - 50%);width:100%;height:100%}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::before{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d::after{top:var(--mdc-ripple-top,calc(50% - 50%));left:var(--mdc-ripple-left,calc(50% - 50%));width:var(--mdc-ripple-fg-size,100%);height:var(--mdc-ripple-fg-size,100%)}.VfPpkd-Bz112c-LgbsSe::before{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-Bz112c-LgbsSe::after{background-color:#000;background-color:var(--mdc-ripple-color,#000)}.VfPpkd-Bz112c-LgbsSe:hover::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):focus::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d)::after{transition:opacity 150ms linear}.VfPpkd-Bz112c-LgbsSe:not(.VfPpkd-ksKsZd-mWPk3d):active::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.VfPpkd-Bz112c-LgbsSe.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.nCP5yc{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.nCP5yc .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.nCP5yc .VfPpkd-vQzf8d,.nCP5yc .VfPpkd-kBDsod{position:relative}.nCP5yc:not(:disabled){background-color:#1a73e8;background-color:var(--gm-fillbutton-container-color,#1a73e8);color:#fff;color:var(--gm-fillbutton-ink-color,#fff)}.nCP5yc:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-fillbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-fillbutton-disabled-ink-color,rgba(60,64,67,0.38))}.nCP5yc .VfPpkd-Jh9lGc::before,.nCP5yc .VfPpkd-Jh9lGc::after{background-color:#202124;background-color:var(--gm-fillbutton-state-color,#202124)}.nCP5yc:hover .VfPpkd-Jh9lGc::before{opacity:.16;opacity:var(--mdc-ripple-hover-opacity,0.16)}.nCP5yc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.24;opacity:var(--mdc-ripple-focus-opacity,0.24)}.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.nCP5yc:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.2;opacity:var(--mdc-ripple-press-opacity,0.2)}.nCP5yc.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.2)}.nCP5yc .VfPpkd-BFbNVe-bF1uUb{opacity:0}.nCP5yc:hover{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-fillbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-fillbutton-ambientshadow-color,rgba(60,64,67,0.15))}.nCP5yc:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.nCP5yc:active{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-fillbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-fillbutton-ambientshadow-color,rgba(60,64,67,0.15))}.nCP5yc:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Rj2Mlf{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.Rj2Mlf .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.Rj2Mlf .VfPpkd-vQzf8d,.Rj2Mlf .VfPpkd-kBDsod{position:relative}.Rj2Mlf:not(:disabled){color:#1a73e8;color:var(--gm-hairlinebutton-ink-color,#1a73e8);border-color:#dadce0;border-color:var(--gm-hairlinebutton-outline-color,#dadce0)}.Rj2Mlf:disabled{color:rgba(60,64,67,0.38);color:var(--gm-hairlinebutton-disabled-ink-color,rgba(60,64,67,0.38));border-color:rgba(60,64,67,0.12);border-color:var(--gm-hairlinebutton-disabled-outline-color,rgba(60,64,67,0.12))}.Rj2Mlf:hover:not(:disabled),.Rj2Mlf:active:not(:disabled),.Rj2Mlf:focus:not(:disabled),.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-hairlinebutton-ink-color--stateful,#174ea6)}.Rj2Mlf:hover:not(:disabled),.Rj2Mlf:active:not(:disabled){border-color:#dadce0;border-color:var(--gm-hairlinebutton-outline-color,#dadce0)}.Rj2Mlf:focus:not(:disabled){border-color:#174ea6;border-color:var(--gm-hairlinebutton-outline-color--stateful,#174ea6)}.Rj2Mlf .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Rj2Mlf .VfPpkd-Jh9lGc::before,.Rj2Mlf .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-hairlinebutton-state-color,#1a73e8)}.Rj2Mlf:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.Rj2Mlf:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.Rj2Mlf.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.b9hyVd{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1)}.b9hyVd .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.b9hyVd .VfPpkd-vQzf8d,.b9hyVd .VfPpkd-kBDsod{position:relative}.b9hyVd:not(:disabled){background-color:#fff;background-color:var(--gm-protectedbutton-container-color,#fff);color:#1a73e8;color:var(--gm-protectedbutton-ink-color,#1a73e8)}.b9hyVd:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-protectedbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-protectedbutton-disabled-ink-color,rgba(60,64,67,0.38))}.b9hyVd:hover:not(:disabled),.b9hyVd:active:not(:disabled),.b9hyVd:focus:not(:disabled),.b9hyVd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-protectedbutton-ink-color--stateful,#174ea6)}.b9hyVd,.b9hyVd:focus{border:0;box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd .VfPpkd-BFbNVe-bF1uUb,.b9hyVd:focus .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd:hover{border:0;box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd:active{border:0;box-shadow:0 1px 3px 0 rgba(60,64,67,0.3),0 4px 8px 3px rgba(60,64,67,0.15);box-shadow:0 1px 3px 0 var(--gm-protectedbutton-keyshadow-color,rgba(60,64,67,0.3)),0 4px 8px 3px var(--gm-protectedbutton-ambientshadow-color,rgba(60,64,67,0.15))}.b9hyVd:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.b9hyVd .VfPpkd-Jh9lGc::before,.b9hyVd .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-protectedbutton-state-color,#1a73e8)}.b9hyVd:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.b9hyVd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.b9hyVd:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.b9hyVd.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.Kjnxrf{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none;transition:border 280ms cubic-bezier(0.4,0,0.2,1),box-shadow 280ms cubic-bezier(0.4,0,0.2,1);box-shadow:none}.Kjnxrf .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.Kjnxrf .VfPpkd-vQzf8d,.Kjnxrf .VfPpkd-kBDsod{position:relative}.Kjnxrf:not(:disabled){background-color:#e8f0fe;background-color:var(--gm-tonalbutton-container-color,#e8f0fe);color:#1967d2;color:var(--gm-tonalbutton-ink-color,#1967d2)}.Kjnxrf:disabled{background-color:rgba(60,64,67,0.12);background-color:var(--gm-tonalbutton-disabled-container-color,rgba(60,64,67,0.12));color:rgba(60,64,67,0.38);color:var(--gm-tonalbutton-disabled-ink-color,rgba(60,64,67,0.38))}.Kjnxrf:hover:not(:disabled),.Kjnxrf:active:not(:disabled),.Kjnxrf:focus:not(:disabled),.Kjnxrf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-tonalbutton-ink-color--stateful,#174ea6)}.Kjnxrf .VfPpkd-Jh9lGc::before,.Kjnxrf .VfPpkd-Jh9lGc::after{background-color:#1967d2;background-color:var(--gm-tonalbutton-state-color,#1967d2)}.Kjnxrf:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.Kjnxrf.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.Kjnxrf:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.1;opacity:var(--mdc-ripple-press-opacity,0.1)}.Kjnxrf.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.1)}.Kjnxrf .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Kjnxrf:hover{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 1px 3px 1px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-tonalbutton-keyshadow-color,rgba(60,64,67,0.3)),0 1px 3px 1px var(--gm-tonalbutton-ambientshadow-color,rgba(60,64,67,0.15))}.Kjnxrf:hover .VfPpkd-BFbNVe-bF1uUb{opacity:0}.Kjnxrf:active{box-shadow:0 1px 2px 0 rgba(60,64,67,0.3),0 2px 6px 2px rgba(60,64,67,0.15);box-shadow:0 1px 2px 0 var(--gm-tonalbutton-keyshadow-color,rgba(60,64,67,0.3)),0 2px 6px 2px var(--gm-tonalbutton-ambientshadow-color,rgba(60,64,67,0.15))}.Kjnxrf:active .VfPpkd-BFbNVe-bF1uUb{opacity:0}.ksBjEc{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none}.ksBjEc .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.ksBjEc .VfPpkd-vQzf8d,.ksBjEc .VfPpkd-kBDsod{position:relative}.ksBjEc:not(:disabled){background-color:transparent;color:#1a73e8;color:var(--gm-colortextbutton-ink-color,#1a73e8)}.ksBjEc:disabled{color:rgba(60,64,67,0.38);color:var(--gm-colortextbutton-disabled-ink-color,rgba(60,64,67,0.38))}.ksBjEc:hover:not(:disabled),.ksBjEc:active:not(:disabled),.ksBjEc:focus:not(:disabled),.ksBjEc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#174ea6;color:var(--gm-colortextbutton-ink-color--stateful,#174ea6)}.ksBjEc .VfPpkd-Jh9lGc::before,.ksBjEc .VfPpkd-Jh9lGc::after{background-color:#1a73e8;background-color:var(--gm-colortextbutton-state-color,#1a73e8)}.ksBjEc:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.ksBjEc.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.ksBjEc:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.ksBjEc.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.LjDxcd{font-family:"Google Sans",Roboto,Arial,sans-serif;font-size:.875rem;font-weight:500;letter-spacing:.0107142857em;text-transform:none}.LjDxcd .VfPpkd-Jh9lGc{height:100%;position:absolute;overflow:hidden;width:100%;z-index:0}.LjDxcd .VfPpkd-vQzf8d,.LjDxcd .VfPpkd-kBDsod{position:relative}.LjDxcd:not(:disabled){color:#5f6368;color:var(--gm-neutraltextbutton-ink-color,#5f6368)}.LjDxcd:disabled{color:rgba(60,64,67,0.38);color:var(--gm-neutraltextbutton-disabled-ink-color,rgba(60,64,67,0.38))}.LjDxcd:hover:not(:disabled),.LjDxcd:active:not(:disabled),.LjDxcd:focus:not(:disabled),.LjDxcd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe:not(:disabled){color:#202124;color:var(--gm-neutraltextbutton-ink-color--stateful,#202124)}.LjDxcd .VfPpkd-Jh9lGc::before,.LjDxcd .VfPpkd-Jh9lGc::after{background-color:#5f6368;background-color:var(--gm-neutraltextbutton-state-color,#5f6368)}.LjDxcd:hover .VfPpkd-Jh9lGc::before{opacity:.04;opacity:var(--mdc-ripple-hover-opacity,0.04)}.LjDxcd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe .VfPpkd-Jh9lGc::before,.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d):focus .VfPpkd-Jh9lGc::before{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-focus-opacity,0.12)}.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d) .VfPpkd-Jh9lGc::after{transition:opacity 150ms linear}.LjDxcd:not(.VfPpkd-ksKsZd-mWPk3d):active .VfPpkd-Jh9lGc::after{transition-duration:75ms;opacity:.12;opacity:var(--mdc-ripple-press-opacity,0.12)}.LjDxcd.VfPpkd-ksKsZd-mWPk3d{--mdc-ripple-fg-opacity:var(--mdc-ripple-press-opacity,0.12)}.DuMIQc{padding:0 24px 0 24px}.P62QJc{padding:0 23px 0 23px;border-width:1px}.P62QJc .VfPpkd-Jh9lGc{top:-1px;left:-1px;border:1px solid transparent}.P62QJc .VfPpkd-RLmnJb{left:-1px;width:calc(100% + 2*1px)}.yHy1rc{z-index:0}.yHy1rc::before{z-index:-1}.yHy1rc::after{z-index:-1}.yHy1rc:disabled,.fzRBVc:disabled{color:rgba(60,64,67,0.38);color:var(--gm-iconbutton-disabled-ink-color,rgba(60,64,67,0.38))}.WpHeLc{height:100%;left:0;position:absolute;top:0;width:100%;outline:none}[dir=rtl] .HDnnrf .VfPpkd-kBDsod,.HDnnrf .VfPpkd-kBDsod[dir=rtl],[dir=rtl] .QDwDD,.QDwDD[dir=rtl]{transform:scaleX(-1)}.PDpWxe{will-change:unset}.VfPpkd-BFbNVe-bF1uUb{position:absolute;border-radius:inherit;pointer-events:none;opacity:0;opacity:var(--mdc-elevation-overlay-opacity,0);transition:opacity 280ms cubic-bezier(0.4,0,0.2,1);background-color:#fff;background-color:var(--mdc-elevation-overlay-color,#fff)}.NZp2ef{background-color:#e8eaed}.VfPpkd-z59Tgd{border-radius:4px;border-radius:var(--mdc-shape-small,4px);color:white;color:var(--mdc-theme-text-primary-on-dark,white);background-color:rgba(0,0,0,0.6);word-break:break-all;word-break:var(--mdc-tooltip-word-break,normal);overflow-wrap:anywhere}.VfPpkd-suEOdc{z-index:2;position:fixed;display:none}.VfPpkd-suEOdc-OWXEXe-TSZdd,.VfPpkd-suEOdc-OWXEXe-eo9XGd,.VfPpkd-suEOdc-OWXEXe-ZYIfFd{display:-webkit-inline-box;display:inline-flex}.VfPpkd-suEOdc-OWXEXe-TSZdd.VfPpkd-suEOdc-OWXEXe-nzrxxc,.VfPpkd-suEOdc-OWXEXe-eo9XGd.VfPpkd-suEOdc-OWXEXe-nzrxxc,.VfPpkd-suEOdc-OWXEXe-ZYIfFd.VfPpkd-suEOdc-OWXEXe-nzrxxc{box-shadow:0 3px 1px -2px rgba(0,0,0,0.2),0 2px 2px 0 rgba(0,0,0,0.14),0 1px 5px 0 rgba(0,0,0,0.12);display:inline-block;border-radius:8px;padding:8px 8px}.VfPpkd-suEOdc-OWXEXe-TSZdd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-eo9XGd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-ZYIfFd.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd{background-color:rgba(255,255,255,0.6)}.VfPpkd-z59Tgd{-webkit-font-smoothing:antialiased;font-family:Roboto,sans-serif;font-family:var(--mdc-typography-caption-font-family,var(--mdc-typography-font-family,Roboto,sans-serif));font-size:.75rem;font-size:var(--mdc-typography-caption-font-size,0.75rem);font-weight:400;font-weight:var(--mdc-typography-caption-font-weight,400);letter-spacing:.0333333333em;letter-spacing:var(--mdc-typography-caption-letter-spacing,0.0333333333em);text-decoration:inherit;text-decoration:var(--mdc-typography-caption-text-decoration,inherit);text-transform:inherit;text-transform:var(--mdc-typography-caption-text-transform,inherit);line-height:16px;padding:4px 8px;min-width:40px;max-width:200px;min-height:24px;max-height:40vh;box-sizing:border-box;overflow:hidden;transform:scale(0.8);text-align:center;opacity:0;outline:1px solid transparent}.VfPpkd-suEOdc-OWXEXe-nzrxxc .VfPpkd-z59Tgd{align-items:flex-start;display:flex;flex-direction:column;min-height:24px;min-width:40px;max-width:320px}.VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd{text-align:left}[dir=rtl] .VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd,.VfPpkd-suEOdc-OWXEXe-LlMNQd .VfPpkd-z59Tgd[dir=rtl]{text-align:right}.VfPpkd-suEOdc-OWXEXe-TSZdd .VfPpkd-z59Tgd{transform:scale(1);opacity:1}.VfPpkd-suEOdc-OWXEXe-eo9XGd-RCfa3e .VfPpkd-z59Tgd{transition:opacity 150ms 0ms cubic-bezier(0,0,0.2,1),transform 150ms 0ms cubic-bezier(0,0,0.2,1)}.VfPpkd-suEOdc-OWXEXe-ZYIfFd .VfPpkd-z59Tgd{transform:scale(1)}.VfPpkd-suEOdc-OWXEXe-ZYIfFd-RCfa3e .VfPpkd-z59Tgd{transition:opacity 75ms 0ms cubic-bezier(0.4,0,1,1)}.EY8ABd .VfPpkd-z59Tgd{background-color:#3c4043;color:#e8eaed}.EY8ABd-OWXEXe-TAWMXe{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}.kFwPee{height:100%}.ydMMEb{width:100%}.SSPGKf{display:block;overflow-y:hidden;z-index:1}.eejsDc{overflow-y:auto;-webkit-overflow-scrolling:touch}.rFrNMe{-webkit-user-select:none;-webkit-tap-highlight-color:transparent;display:inline-block;outline:none;padding-bottom:8px;width:200px}.aCsJod{height:40px;position:relative;vertical-align:top}.aXBtI{display:flex;position:relative;top:14px}.Xb9hP{display:flex;box-flex:1;flex-grow:1;flex-shrink:1;min-width:0%;position:relative}.A37UZe{box-sizing:border-box;height:24px;line-height:24px;position:relative}.qgcB3c:not(:empty){padding-right:12px}.sxyYjd:not(:empty){padding-left:12px}.whsOnd{box-flex:1;flex-grow:1;flex-shrink:1;background-color:transparent;border:none;display:block;font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;height:24px;line-height:24px;margin:0;min-width:0%;outline:none;padding:0;z-index:0}.rFrNMe.dm7YTc .whsOnd{color:#fff}.whsOnd:invalid,.whsOnd:-moz-submit-invalid,.whsOnd:-moz-ui-invalid{box-shadow:none}.I0VJ4d>.whsOnd::-ms-clear,.I0VJ4d>.whsOnd::-ms-reveal{display:none}.i9lrp{background-color:rgba(0,0,0,0.12);bottom:-2px;height:1px;left:0;margin:0;padding:0;position:absolute;width:100%}.i9lrp:before{content:"";position:absolute;top:0;bottom:-2px;left:0;right:0;border-bottom:1px solid rgba(0,0,0,0);pointer-events:none}.rFrNMe.dm7YTc .i9lrp{background-color:rgba(255,255,255,0.70)}.OabDMe{transform:scaleX(0);background-color:#4285f4;bottom:-2px;height:2px;left:0;margin:0;padding:0;position:absolute;width:100%}.rFrNMe.dm7YTc .OabDMe{background-color:#a1c2fa}.rFrNMe.k0tWj .i9lrp,.rFrNMe.k0tWj .OabDMe{background-color:#d50000;height:2px}.rFrNMe.k0tWj.dm7YTc .i9lrp,.rFrNMe.k0tWj.dm7YTc .OabDMe{background-color:#e06055}.whsOnd[disabled]{color:rgba(0,0,0,0.38)}.rFrNMe.dm7YTc .whsOnd[disabled]{color:rgba(255,255,255,0.50)}.whsOnd[disabled]~.i9lrp{background:none;border-bottom:1px dotted rgba(0,0,0,0.38)}.OabDMe.Y2Zypf{animation:quantumWizPaperInputRemoveUnderline .3s cubic-bezier(0.4,0,0.2,1)}.rFrNMe.u3bW4e .OabDMe{animation:quantumWizPaperInputAddUnderline .3s cubic-bezier(0.4,0,0.2,1);transform:scaleX(1)}.rFrNMe.sdJrJc>.aCsJod{padding-top:24px}.AxOyFc{transform-origin:bottom left;transition:all .3s cubic-bezier(0.4,0,0.2,1);transition-property:color,bottom,transform;color:rgba(0,0,0,0.38);font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:16px;pointer-events:none;position:absolute;bottom:3px;left:0;width:100%}.whsOnd:not([disabled]):focus~.AxOyFc,.whsOnd[badinput="true"]~.AxOyFc,.rFrNMe.CDELXb .AxOyFc,.rFrNMe.dLgj8b .AxOyFc{transform:scale(.75) translateY(-39px)}.whsOnd:not([disabled]):focus~.AxOyFc{color:#4285f4}.rFrNMe.dm7YTc .whsOnd:not([disabled]):focus~.AxOyFc{color:#a1c2fa}.rFrNMe.k0tWj .whsOnd:not([disabled]):focus~.AxOyFc{color:#d50000}.ndJi5d{color:rgba(0,0,0,0.38);font:400 16px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;max-width:100%;overflow:hidden;pointer-events:none;position:absolute;text-overflow:ellipsis;top:2px;left:0;white-space:nowrap}.rFrNMe.CDELXb .ndJi5d{display:none}.K0Y8Se{-webkit-tap-highlight-color:transparent;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;height:16px;margin-left:auto;padding-left:16px;padding-top:8px;pointer-events:none;opacity:.3;white-space:nowrap}.rFrNMe.dm7YTc .AxOyFc,.rFrNMe.dm7YTc .K0Y8Se,.rFrNMe.dm7YTc .ndJi5d{color:rgba(255,255,255,0.70)}.rFrNMe.Tyc9J{padding-bottom:4px}.dEOOab,.ovnfwe:not(:empty){-webkit-tap-highlight-color:transparent;flex:1 1 auto;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;min-height:16px;padding-top:8px}.LXRPh{display:flex}.ovnfwe{pointer-events:none}.dEOOab{color:#d50000}.rFrNMe.dm7YTc .dEOOab,.rFrNMe.dm7YTc.k0tWj .whsOnd:not([disabled]):focus~.AxOyFc{color:#e06055}.ovnfwe{opacity:.3}.rFrNMe.dm7YTc .ovnfwe{color:rgba(255,255,255,0.70);opacity:1}.rFrNMe.k0tWj .ovnfwe,.rFrNMe:not(.k0tWj) .ovnfwe:not(:empty)+.dEOOab{display:none}@keyframes quantumWizPaperInputRemoveUnderline{0%{transform:scaleX(1);opacity:1}to{transform:scaleX(1);opacity:0}}@keyframes quantumWizPaperInputAddUnderline{0%{transform:scaleX(0)}to{transform:scaleX(1)}}.MCcOAc{bottom:0;left:0;position:absolute;right:0;top:0;overflow:hidden;z-index:1}.MCcOAc>.pGxpHc{flex-shrink:0;box-flex:0;flex-grow:0}.IqBfM>.HLlAHb{align-items:center;display:flex;height:60px;position:absolute;right:16px;top:0;z-index:9999}.VUoKZ{display:none;position:absolute;top:0;left:0;right:0;height:3px;z-index:1001}.TRHLAc{position:absolute;top:0;left:0;width:25%;height:100%;background:#68e;transform:scaleX(0);transform-origin:0 0}.mIM26c .VUoKZ{display:block}.mIM26c .TRHLAc{animation:boqChromeapiPageProgressAnimation 1s infinite;animation-timing-function:cubic-bezier(0.4,0.0,1,1);animation-delay:.1s}.ghyPEc .VUoKZ{position:fixed}@keyframes boqChromeapiPageProgressAnimation{0%{transform:scaleX(0)}50%{transform:scaleX(5)}to{transform:scaleX(5) translateX(100%)}}@keyframes quantumWizBoxInkSpread{0%{transform:translate(-50%,-50%) scale(.2)}to{transform:translate(-50%,-50%) scale(2.2)}}@keyframes quantumWizIconFocusPulse{0%{transform:translate(-50%,-50%) scale(1.5);opacity:0}to{transform:translate(-50%,-50%) scale(2);opacity:1}}@keyframes quantumWizRadialInkSpread{0%{transform:scale(1.5);opacity:0}to{transform:scale(2.5);opacity:1}}@keyframes quantumWizRadialInkFocusPulse{0%{transform:scale(2);opacity:0}to{transform:scale(2.5);opacity:1}}.O0WRkf{-webkit-user-select:none;transition:background .2s .1s;border:0;border-radius:3px;cursor:pointer;display:inline-block;font-size:14px;font-weight:500;min-width:4em;outline:none;overflow:hidden;position:relative;text-align:center;text-transform:uppercase;-webkit-tap-highlight-color:transparent;z-index:0}.A9jyad{font-size:13px;line-height:16px}.zZhnYe{transition:box-shadow .28s cubic-bezier(0.4,0.0,0.2,1);background:#dfdfdf;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.12),0 1px 5px 0 rgba(0,0,0,0.2)}.zZhnYe.qs41qe{transition:box-shadow .28s cubic-bezier(0.4,0.0,0.2,1);transition:background .8s;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.2)}.e3Duub,.e3Duub a,.e3Duub a:hover,.e3Duub a:link,.e3Duub a:visited{background:#4285f4;color:#fff}.HQ8yf,.HQ8yf a{color:#4285f4}.UxubU,.UxubU a{color:#fff}.ZFr60d{position:absolute;top:0;right:0;bottom:0;left:0;background-color:transparent}.O0WRkf.u3bW4e .ZFr60d{background-color:rgba(0,0,0,0.12)}.UxubU.u3bW4e .ZFr60d{background-color:rgba(255,255,255,0.30)}.e3Duub.u3bW4e .ZFr60d{background-color:rgba(0,0,0,0.122)}.HQ8yf.u3bW4e .ZFr60d{background-color:rgba(66,133,244,0.149)}.Vwe4Vb{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease,visibility 0s ease .2s,transform 0s ease .2s;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.O0WRkf.qs41qe .Vwe4Vb{transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.O0WRkf.qs41qe.M9Bg4d .Vwe4Vb{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1),opacity .2s cubic-bezier(0.0,0.0,0.2,1)}.O0WRkf.j7nIZb .Vwe4Vb{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.oG5Srb .Vwe4Vb,.zZhnYe .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(0,0,0,0.12),rgba(0,0,0,0.12) 80%,rgba(0,0,0,0) 100%)}.HQ8yf .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(66,133,244,0.251),rgba(66,133,244,0.251) 80%,rgba(66,133,244,0) 100%)}.e3Duub .Vwe4Vb{background-image:radial-gradient(circle farthest-side,#3367d6,#3367d6 80%,rgba(51,103,214,0) 100%)}.UxubU .Vwe4Vb{background-image:radial-gradient(circle farthest-side,rgba(255,255,255,0.30),rgba(255,255,255,0.30) 80%,rgba(255,255,255,0) 100%)}.O0WRkf.RDPZE{box-shadow:none;color:rgba(68,68,68,0.502);cursor:default;fill:rgba(68,68,68,0.502)}.zZhnYe.RDPZE{background:rgba(153,153,153,0.102)}.UxubU.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.UxubU.zZhnYe.RDPZE{background:rgba(204,204,204,0.102)}.CwaK9{position:relative}.RveJvd{display:inline-block;margin:.5em}.FKF6mc,.FKF6mc:focus{display:block;outline:none;text-decoration:none}.FKF6mc:visited{fill:inherit;stroke:inherit}.U26fgb.u3bW4e{outline:1px solid transparent}.C0oVfc{line-height:20px;min-width:88px}.C0oVfc .RveJvd{margin:8px}.mUbCce{-webkit-user-select:none;transition:background .3s;border:0;border-radius:50%;cursor:pointer;display:inline-block;flex-shrink:0;height:48px;outline:none;overflow:hidden;position:relative;text-align:center;-webkit-tap-highlight-color:transparent;width:48px;z-index:0}.mUbCce>.TpQm9d{height:48px;width:48px}.mUbCce.u3bW4e,.mUbCce.qs41qe,.mUbCce.j7nIZb{-webkit-transform:translateZ(0);-webkit-mask-image:-webkit-radial-gradient(circle,white 100%,black 100%)}.YYBxpf{border-radius:0;overflow:visible}.YYBxpf.u3bW4e,.YYBxpf.qs41qe,.YYBxpf.j7nIZb{-webkit-mask-image:none}.fKz7Od{color:rgba(0,0,0,0.54);fill:rgba(0,0,0,0.54)}.p9Nwte{color:rgba(255,255,255,0.749);fill:rgba(255,255,255,0.749)}.fKz7Od.u3bW4e{background-color:rgba(0,0,0,0.12)}.p9Nwte.u3bW4e{background-color:rgba(204,204,204,0.251)}.YYBxpf.u3bW4e{background-color:transparent}.VTBa7b{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease,visibility 0s ease .2s,transform 0s ease .2s;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.YYBxpf.u3bW4e .VTBa7b{animation:quantumWizIconFocusPulse .7s infinite alternate;height:100%;left:50%;top:50%;width:100%;visibility:visible}.mUbCce.qs41qe .VTBa7b{transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.mUbCce.qs41qe.M9Bg4d .VTBa7b{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1),opacity .2s cubic-bezier(0.0,0.0,0.2,1)}.mUbCce.j7nIZb .VTBa7b{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.fKz7Od .VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(0,0,0,0.12),rgba(0,0,0,0.12) 80%,rgba(0,0,0,0) 100%)}.p9Nwte .VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(204,204,204,0.251),rgba(204,204,204,0.251) 80%,rgba(204,204,204,0) 100%)}.mUbCce.RDPZE{color:rgba(0,0,0,0.26);fill:rgba(0,0,0,0.26);cursor:default}.p9Nwte.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.xjKiLb{position:relative;top:50%}.xjKiLb>span{display:inline-block;position:relative}.llhEMd{transition:opacity .15s cubic-bezier(0.4,0.0,0.2,1) .15s;background-color:rgba(0,0,0,0.502);bottom:0;left:0;opacity:0;position:fixed;right:0;top:0;z-index:5000}.llhEMd.iWO5td{transition:opacity .05s cubic-bezier(0.4,0.0,0.2,1);opacity:1}.mjANdc{transition:transform .4s cubic-bezier(0.4,0.0,0.2,1);-webkit-box-align:center;box-align:center;align-items:center;display:flex;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;bottom:0;left:0;padding:0 5%;position:absolute;right:0;top:0}.x3wWge,.ONJhl{display:block;height:3em}.eEPege>.x3wWge,.eEPege>.ONJhl{box-flex:1;flex-grow:1}.J9Nfi{flex-shrink:1;max-height:100%}.g3VIld{-webkit-box-align:stretch;box-align:stretch;align-items:stretch;display:flex;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;transition:transform .225s cubic-bezier(0.0,0.0,0.2,1);position:relative;background-color:#fff;border-radius:2px;box-shadow:0 12px 15px 0 rgba(0,0,0,0.24);max-width:24em;outline:1px solid transparent;overflow:hidden}.vcug3d .g3VIld{padding:0}.g3VIld.kdCdqc{transition:transform .15s cubic-bezier(0.4,0.0,1,1)}.Up8vH.CAwICe{transform:scale(0.8)}.Up8vH.kdCdqc{transform:scale(0.9)}.vcug3d{-webkit-box-align:stretch;box-align:stretch;align-items:stretch;padding:0}.vcug3d>.g3VIld{box-flex:2;flex-grow:2;border-radius:0;left:0;right:0;max-width:100%}.vcug3d>.ONJhl,.vcug3d>.x3wWge{box-flex:0;flex-grow:0;height:0}.tOrNgd{display:flex;flex-shrink:0;font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif;padding:24px 24px 20px 24px}.vcug3d .tOrNgd{display:none}.TNczib{box-pack:justify;-webkit-box-pack:justify;justify-content:space-between;flex-shrink:0;box-shadow:0 3px 4px 0 rgba(0,0,0,0.24);background-color:#455a64;color:white;display:none;font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.vcug3d .TNczib{display:flex}.PNenzf{box-flex:1;flex-grow:1;flex-shrink:1;overflow:hidden;word-wrap:break-word}.TNczib .PNenzf{margin:16px 0}.VY7JQd{height:0}.TNczib .VY7JQd,.tOrNgd .bZWIgd{display:none}.R6Lfte .Wtw8H{flex-shrink:0;display:block;margin:-12px -6px 0 0}.PbnGhe{box-flex:2;flex-grow:2;flex-shrink:2;display:block;font:400  14px / 20px  Roboto,RobotoDraft,Helvetica,Arial,sans-serif;padding:0 24px;overflow-y:auto}.Whe8ub .PbnGhe{padding-top:24px}.hFEqNb .PbnGhe{padding-bottom:24px}.vcug3d .PbnGhe{padding:16px}.XfpsVe{display:flex;flex-shrink:0;box-pack:end;-webkit-box-pack:end;justify-content:flex-end;padding:24px 24px 16px 24px}.vcug3d .XfpsVe{display:none}.OllbWe{box-pack:end;-webkit-box-pack:end;justify-content:flex-end;display:none}.vcug3d .OllbWe{display:flex;-webkit-box-align:start;box-align:start;align-items:flex-start;margin:0 16px}.kHssdc.O0WRkf.C0oVfc,.XfpsVe .O0WRkf.C0oVfc{min-width:64px}.kHssdc+.kHssdc{margin-left:8px}.TNczib .kHssdc{color:#fff;margin-top:10px}.TNczib .Wtw8H{margin:4px 24px 4px 0}.TNczib .kHssdc.u3bW4e,.TNczib .Wtw8H.u3bW4e{background-color:rgba(204,204,204,0.251)}.TNczib .kHssdc>.Vwe4Vb,.TNczib .Wtw8H>.VTBa7b{background-image:radial-gradient(circle farthest-side,rgba(255,255,255,0.30),rgba(255,255,255,0.30) 80%,rgba(255,255,255,0) 100%)}.TNczib .kHssdc.RDPZE,.TNczib .Wtw8H.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.fb0g6{position:relative}.JPdR6b{transform:translateZ(0);transition:max-width .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-height .2s  cubic-bezier(0.0,0.0,0.2,1) ,opacity .1s linear;background:#ffffff;border:0;border-radius:2px;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.2);box-sizing:border-box;max-height:100%;max-width:100%;opacity:1;outline:1px solid transparent;z-index:2000}.XvhY1d{overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch}.JAPqpe{float:left;padding:16px 0}.JPdR6b.qjTEB{transition:left .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-width .2s  cubic-bezier(0.0,0.0,0.2,1) ,max-height .2s  cubic-bezier(0.0,0.0,0.2,1) ,opacity .05s linear,top .2s cubic-bezier(0.0,0.0,0.2,1)}.JPdR6b.jVwmLb{max-height:56px;opacity:0}.JPdR6b.CAwICe{overflow:hidden}.JPdR6b.oXxKqf{transition:none}.z80M1{color:#222;cursor:pointer;display:block;outline:none;overflow:hidden;padding:0 24px;position:relative}.uyYuVb{display:flex;font-size:14px;font-weight:400;line-height:40px;height:40px;position:relative;white-space:nowrap}.jO7h3c{box-flex:1;flex-grow:1;min-width:0}.JPdR6b.e5Emjc .z80M1{padding-left:64px}.JPdR6b.CblTmf .z80M1{padding-right:48px}.PCdOIb{display:flex;flex-direction:column;justify-content:center;background-repeat:no-repeat;height:40px;left:24px;opacity:.54;position:absolute}.z80M1.RDPZE .PCdOIb{opacity:.26}.z80M1.FwR7Pc{outline:1px solid transparent;background-color:#eeeeee}.z80M1.RDPZE{color:#b8b8b8;cursor:default}.z80M1.N2RpBe::before{transform:rotate(45deg);transform-origin:left;content:"\0000a0";display:block;border-right:2px solid #222;border-bottom:2px solid #222;height:16px;left:24px;opacity:.54;position:absolute;top:13%;width:7px;z-index:0}.JPdR6b.CblTmf .z80M1.N2RpBe::before{left:auto;right:16px}.z80M1.RDPZE::before{border-color:#b8b8b8;opacity:1}.aBBjbd{pointer-events:none;position:absolute}.z80M1.qs41qe>.aBBjbd{animation:quantumWizBoxInkSpread .3s ease-out;animation-fill-mode:forwards;background-image:radial-gradient(circle farthest-side,#bdbdbd,#bdbdbd 80%,rgba(189,189,189,0) 100%);background-size:cover;opacity:1;top:0;left:0}.J0XlZe{color:inherit;line-height:40px;padding:0 6px 0 1em}.a9caSc{color:inherit;direction:ltr;padding:0 6px 0 1em}.kCtYwe{border-top:1px solid rgba(0,0,0,0.12);margin:7px 0}.B2l7lc{border-left:1px solid rgba(0,0,0,0.12);display:inline-block;height:48px}@media screen and (max-width:840px){.JAPqpe{padding:8px 0}.z80M1{padding:0 16px}.JPdR6b.e5Emjc .z80M1{padding-left:48px}.PCdOIb{left:12px}}.DPvwYc{font-family:'Material Icons Extended';font-weight:normal;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-rendering:optimizeLegibility;text-transform:none;display:inline-block;word-wrap:normal;direction:ltr;font-feature-settings:'liga' 1;-webkit-font-smoothing:antialiased}html[dir="rtl"] .sm8sCf{transform:scaleX(-1);filter:FlipH}.O1bNWe{bottom:0;left:0;top:0;right:0;position:absolute;z-index:1}.Wxeofe{position:absolute;top:0;left:0;right:0;z-index:3}.rDQqN{animation:slideHeader .3s cubic-bezier(0.0,0.0,0.2,1);height:56px;transform:translateZ(0)}.GQiZne .rDQqN,.ecJEib .hdDPB .rDQqN{animation:slideHeader-withTabs .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .rDQqN{animation:none}.DAbEod{animation:slideContent .3s cubic-bezier(0.0,0.0,0.2,1);position:relative;z-index:1;height:100%}.LcUz9d .DAbEod{animation:none}.SNFoGf{background-color:#ff0000;color:#fff;font-size:16px;font-weight:500;padding:8px 0;position:relative;text-align:center;z-index:-1}.uYojab{display:none}.pWgqe{height:56px;width:100%}.k5MVbc{height:52px;width:100%}.Jvazdb{overflow-y:hidden;background:#f1f1f1;position:absolute;bottom:0;left:0;right:0;top:0}.Jvazdb.cLa0Ib{display:flex;-webkit-box-align:stretch;box-align:stretch;align-items:stretch}.iaLVnc{position:absolute;bottom:0;left:0;right:0;z-index:2}.OFyC1e{display:none;position:fixed;top:0;left:0;height:100%;backface-visibility:hidden;z-index:2}.u5oEgd{position:absolute;top:64px;bottom:0;left:0;padding-top:16px;max-width:100%}.GQiZne .u5oEgd,.ecJEib .hdDPB .u5oEgd{top:112px}.Jvazdb.UKHOWd .u5oEgd{top:116px}.Jvazdb.GQiZne.UKHOWd .u5oEgd,.ecJEib .Jvazdb.hdDPB.UKHOWd .u5oEgd{top:164px}.jQMSG{position:fixed;top:0;right:0;height:100%;backface-visibility:hidden;z-index:2;width:100%}.GQiZne .jQMSG,.ecJEib .hdDPB .jQMSG{top:112px}.ecJEib .rDQqN,.ecJEib .pWgqe{height:64px}.e2G3Fb.EWZcud .rDQqN,.e2G3Fb.EWZcud .pWgqe{height:48px}.e2G3Fb.b30Rkd .rDQqN,.e2G3Fb.b30Rkd .pWgqe{height:56px}.GQiZne .rDQqN{height:104px}.ecJEib .GQiZne .rDQqN,.ecJEib .GQiZne .pWgqe,.ecJEib .hdDPB .rDQqN,.ecJEib .hdDPB .pWgqe{height:112px}.e2G3Fb.EWZcud .GQiZne .rDQqN,.e2G3Fb.EWZcud .GQiZne .pWgqe{height:96px}.e2G3Fb.b30Rkd .GQiZne .rDQqN,.e2G3Fb.b30Rkd .GQiZne .pWgqe{height:104px}.ecJEib .Jvazdb.UKHOWd .pWgqe{height:116px}.e2G3Fb.EWZcud .Jvazdb.UKHOWd .pWgqe{height:144px}.e2G3Fb.b30Rkd .Jvazdb.UKHOWd .pWgqe{height:152px}.ecJEib .Jvazdb.UKHOWd.GQiZne .pWgqe,.ecJEib .Jvazdb.UKHOWd.hdDPB .pWgqe{height:164px}.e2G3Fb.EWZcud .Jvazdb.UKHOWd.GQiZne .pWgqe{height:192px}.e2G3Fb.b30Rkd .Jvazdb.UKHOWd.GQiZne .pWgqe{height:200px}@media only screen and (min-width:750px){.OFyC1e{display:block;width:210px;animation:slideNav .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .OFyC1e{animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:210px}.jQMSG{display:block;width:210px}.uFavze .DAbEod{margin-right:210px}}@keyframes slideNav{0%{transform:translateX(-210px)}}@keyframes slideHeader{0%{transform:translateY(-64px)}}@keyframes slideHeader-withTabs{0%{transform:translateY(-113px)}}@keyframes slideContent{0%{transform:translateY(15vh);opacity:0}}@media only screen and (min-width:750px){.OFyC1e{display:none;animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:0}}@media only screen and (min-width:1200px){.OFyC1e{display:block;width:256px;animation:slideNav .3s cubic-bezier(0.0,0.0,0.2,1)}.LcUz9d .OFyC1e{animation:none}.nWGHWc.k7iNHb .DAbEod{margin-left:256px}}c-wiz{contain:style}c-wiz>c-data{display:none}c-wiz.rETSD{contain:none}c-wiz.Ubi8Z{contain:layout style}.pf7Psf{position:relative;width:100%;height:100%;display:block}.pf7Psf.KFV7Ie{height:auto}.x2sGwe{width:100%;height:100%}.tb3unb{background-color:rgba(66,133,244,0.9);position:absolute;top:0;bottom:0;left:0;right:0;z-index:9999;display:flex;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center}.pf7Psf.KFV7Ie>.tb3unb{position:fixed}.xn2mde{pointer-events:none;margin:auto;max-width:100%;max-height:100%}.Xy5NZc{width:150px;height:150px;margin:0 auto 24px;display:block}.mlwXqe{color:#fff;font-size:20px;font-weight:500;line-height:24px;margin:0 16px;text-align:center}.DJ3Bx{box-sizing:border-box;height:56px}.DJ3Bx.ctg5xf{border-bottom:1px solid #e5e5e5;display:flex;padding:16px;width:100%}.ctg5xf.ZApNje{display:none}.DJ3Bx.Zrbyxb{border-top:1px solid #e5e5e5;bottom:0;display:flex;position:absolute;right:0;width:100%;-webkit-box-align:center;box-align:center;align-items:center;box-pack:end;-webkit-box-pack:end;justify-content:flex-end}.SErqHc{height:calc(100% - 56px*2)}.bakAeb,.AJFpof{box-sizing:border-box;display:inline-block;height:100%;overflow-y:auto;vertical-align:top}.bakAeb{width:calc(100%*3/7)}.AJFpof{width:calc(100%*4/7)}.Mg7UB,.AJFpof{padding:0 24px}.ctg5xf{color:rgba(0,0,0,0.87);font:500 20px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.q0vRI .ctg5xf{display:none}.q0vRI .ctg5xf.ZApNje{border:none;display:flex;position:absolute;z-index:1;box-pack:center;-webkit-box-pack:center;justify-content:center}.q0vRI .SErqHc{height:100%;overflow-y:auto}.q0vRI .bakAeb{height:initial}.q0vRI .AJFpof{overflow-y:visible}.q0vRI .bakAeb,.q0vRI .AJFpof{width:100%}.q0vRI .DJ3Bx.Zrbyxb{display:none}.LVl1od{position:absolute;z-index:2000}.Ko2YWc{background:rgba(0,0,0,0.5)}@media screen and (min-width:530px){.Ko2YWc{background:rgba(0,0,0,0.12)}}.LVl1od.BVctCb{background:rgba(0,0,0,0)}.sVAYfc{background:#fff;border-radius:4px;box-shadow:0 8px 10px 1px rgba(0,0,0,0.14),0 3px 14px 2px rgba(0,0,0,0.12),0 5px 5px -3px rgba(0,0,0,0.4);overflow:hidden;position:absolute;z-index:2000}.sVAYfc.EZxqsf{background:transparent;border-radius:0;box-shadow:none}.sVAYfc.WltWLe{box-shadow:0 16px 24px 2px rgba(0,0,0,0.14),0 6px 30px 5px rgba(0,0,0,0.12),0 8px 10px -5px rgba(0,0,0,0.4)}.Nw9uye{background:#fff;border-radius:4px;bottom:0;left:0;overflow:hidden;position:absolute;right:0;top:0}.sVAYfc.EZxqsf .Nw9uye{background:transparent}.sVAYfc.q0vRI,.sVAYfc.Sl0J0d,.sVAYfc.q0vRI .Nw9uye,.sVAYfc.Sl0J0d .Nw9uye{border-radius:0}.oqYSeb,.oqYSeb.fb0g6{bottom:0;left:0;position:absolute;top:0;width:100%;box-shadow:0 8px 17px 0 rgba(0,0,0,0.2);z-index:2}.sVAYfc.emhBuc .oqYSeb{display:none}.sVAYfc.BIIBbc .oqYSeb{overflow-y:hidden;-webkit-overflow-scrolling:auto}.lbr2xd{position:absolute;top:0;left:0;right:0;bottom:0;display:none;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;box-pack:center;-webkit-box-pack:center;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center;align-content:center}.sVAYfc.emhBuc .lbr2xd{display:flex}.Ko2YWc{background:rgba(0,0,0,0.6)}.sVAYfc,.Nw9uye{border-radius:8px}.XVzU0b{display:inline-block;height:24px;pointer-events:none;width:24px}.XVzU0b.WWkfrb{height:18px;width:18px}.XVzU0b.LAGX{height:48px;width:48px}.XVzU0b.ziGrr{pointer-events:auto}.XVzU0b path,.XVzU0b circle{fill:#212121}.XVzU0b.ZoZQ1 path,.XVzU0b.ZoZQ1 circle{fill:#fff}.XVzU0b.J3yWx path,.XVzU0b.J3yWx circle{fill:#757575}.XVzU0b.Urqcdc path,.XVzU0b.Urqcdc circle{fill:rgba(0,0,0,0.54)}.XVzU0b.vWRxWb{width:unset}.vWRxWb circle.qs41qe{fill:#797979}.vWRxWb circle.jK7moc{fill:#c0c0c0}.E68jgf{position:relative;height:0;width:100%;overflow:hidden}.JZUAbb{position:absolute;display:block;left:0;right:0;top:0;bottom:0;width:100%;height:auto;margin:auto}.zxxEtb{display:inline-block;height:32px;margin-bottom:2px;min-width:32px;width:32px;vertical-align:middle}.zZOTDd{font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1.375rem;font-weight:400;letter-spacing:0;line-height:1.75rem;color:#5f6368;display:inline-block;margin-left:8px;vertical-align:middle}.XS1fT{padding:0 8px;font-size:21px;box-sizing:border-box;z-index:2;box-shadow:0 1px 8px rgba(0,0,0,.3);color:#fff}.XS1fT.RqpFEd .dMPbYe:not(.JhVB8e),_.jd=function(a,b){b=String(b);"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());return a.createElement(b)};_.md=function(a){return a&&a.parentNode?a.parentNode.removeChild(a):null};_.nd=function(a){return _.Ta(a)&&1==a.nodeType};
_.pd=function(a){(0,_.od)();return _.Sb(a)};_.od=_.Pa;
_.qd=function(){this.j={};this.o={}};_.td=function(a,b){a.U=function(){return _.rd(_.qd.U(),b)};a.Xk=function(){return _.sd(_.qd.U(),b)}};_.ud=function(a){return _.rd(_.qd.U(),a)};_.wd=function(a,b){var c=_.qd.U();if(a in c.j){if(c.j[a]!=b)throw new vd(a);}else{c.j[a]=b;if(b=c.o[a])for(var d=0,e=b.length;d<e;d++)b[d].j(c.j,a);delete c.o[a]}};_.rd=function(a,b){if(b in a.j)return a.j[b];throw new xd(b);};_.sd=function(a,b){return a.j[b]||null};_.Qa(_.qd);
var yd=function(a){_.aa.call(this);this.fa=a};_.r(yd,_.aa);var vd=function(a){yd.call(this,a)};_.r(vd,yd);var xd=function(a){yd.call(this,a)};_.r(xd,yd);
_.C=function(a,b){return null!=a?!!a:!!b};_.F=function(a,b){void 0==b&&(b="");return null!=a?a:b};_.H=function(a,b){void 0==b&&(b=0);return null!=a?a:b};
_.zd=_.Eb();_.Ad=rc()||_.z("iPod");_.Bd=_.z("iPad");_.Cd=_.z("Android")&&!(Fb()||_.Eb()||_.z("Opera")||_.z("Silk"));_.Dd=Fb();_.Ed=_.Gb()&&!_.sc();
var Fd;Fd={};_.Gd=null;_.Hd=function(){if(!_.Gd){_.Gd={};for(var a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),b=["+/=","+/","-_=","-_.","-_"],c=0;5>c;c++){var d=a.concat(b[c].split(""));Fd[c]=d;for(var e=0;e<d.length;e++){var f=d[e];void 0===_.Gd[f]&&(_.Gd[f]=e)}}}};
_.Id=function(a){this.j=0;this.o=a};_.Id.prototype.next=function(){return this.j<this.o.length?{done:!1,value:this.o[this.j++]}:{done:!0,value:void 0}};"undefined"!=typeof Symbol&&"undefined"!=typeof Symbol.iterator&&(_.Id.prototype[Symbol.iterator]=function(){return this});
var Jd,Kd,Wd;_.I=function(){};Jd="function"==typeof Uint8Array;
_.K=function(a,b,c,d,e,f){a.j=null;b||(b=c?[c]:[]);a.J=c?String(c):void 0;a.C=0===c?-1:0;a.A=b;a:{c=a.A.length;b=-1;if(c&&(b=c-1,c=a.A[b],!(null===c||"object"!=typeof c||Array.isArray(c)||Jd&&c instanceof Uint8Array))){a.D=b-a.C;a.B=c;break a}-1<d?(a.D=Math.max(d,b+1-a.C),a.B=null):a.D=Number.MAX_VALUE}a.H={};if(e)for(d=0;d<e.length;d++)b=e[d],b<a.D?(b+=a.C,a.A[b]=a.A[b]||Kd):(_.Ld(a),a.B[b]=a.B[b]||Kd);if(f&&f.length)for(d=0;d<f.length;d++)_.Md(a,f[d])};Kd=[];
_.Ld=function(a){var b=a.D+a.C;a.A[b]||(a.B=a.A[b]={})};_.L=function(a,b){if(b<a.D){b+=a.C;var c=a.A[b];return c!==Kd?c:a.A[b]=[]}if(a.B)return c=a.B[b],c===Kd?a.B[b]=[]:c};_.Nd=function(a,b){return null!=_.L(a,b)};_.M=function(a,b){a=_.L(a,b);return null==a?a:!!a};_.Od=function(a,b,c){a=_.L(a,b);return null==a?c:a};_.Pd=function(a,b,c){return _.Od(a,b,void 0===c?0:c)};_.Qd=function(a,b,c){c=void 0===c?!1:c;a=_.M(a,b);return null==a?c:a};
_.Rd=function(a,b,c){c=void 0===c?0:c;a=_.L(a,b);a=null==a?a:+a;return null==a?c:a};_.N=function(a,b,c){b<a.D?a.A[b+a.C]=c:(_.Ld(a),a.B[b]=c);return a};_.Sd=function(a,b,c){_.L(a,b).push(c);return a};_.Md=function(a,b){for(var c,d,e=0;e<b.length;e++){var f=b[e],g=_.L(a,f);null!=g&&(c=f,d=g,_.N(a,f,void 0))}return c?(_.N(a,c,d),c):0};_.n=function(a,b,c){a.j||(a.j={});if(!a.j[c]){var d=_.L(a,c);d&&(a.j[c]=new b(d))}return a.j[c]};
_.Td=function(a,b,c){a.j||(a.j={});if(!a.j[c]){for(var d=_.L(a,c),e=[],f=0;f<d.length;f++)e[f]=new b(d[f]);a.j[c]=e}b=a.j[c];b==Kd&&(b=a.j[c]=[]);return b};_.O=function(a,b,c){a.j||(a.j={});var d=c?c.Ea():c;a.j[b]=c;return _.N(a,b,d)};_.Ud=function(a,b,c){a.j||(a.j={});c=c||[];for(var d=[],e=0;e<c.length;e++)d[e]=c[e].Ea();a.j[b]=c;return _.N(a,b,d)};_.I.prototype.Ea=function(){if(this.j)for(var a in this.j){var b=this.j[a];if(Array.isArray(b))for(var c=0;c<b.length;c++)b[c]&&b[c].Ea();else b&&b.Ea()}return this.A};
_.I.prototype.o=Jd?function(){var a=Uint8Array.prototype.toJSON;Uint8Array.prototype.toJSON=function(){var b;void 0===b&&(b=0);_.Hd();b=Fd[b];for(var c=[],d=0;d<this.length;d+=3){var e=this[d],f=d+1<this.length,g=f?this[d+1]:0,h=d+2<this.length,l=h?this[d+2]:0,m=e>>2;e=(e&3)<<4|g>>4;g=(g&15)<<2|l>>6;l&=63;h||(l=64,f||(g=64));c.push(b[m],b[e],b[g]||"",b[l]||"")}return c.join("")};try{return JSON.stringify(this.A&&this.Ea(),Vd)}finally{Uint8Array.prototype.toJSON=a}}:function(){return JSON.stringify(this.A&&
this.Ea(),Vd)};var Vd=function(a,b){return"number"!==typeof b||!isNaN(b)&&Infinity!==b&&-Infinity!==b?b:String(b)};_.I.prototype.toString=function(){return this.Ea().toString()};_.Xd=function(a){return new a.constructor(Wd(a.Ea()))};Wd=function(a){if(Array.isArray(a)){for(var b=Array(a.length),c=0;c<a.length;c++){var d=a[c];null!=d&&(b[c]="object"==typeof d?Wd(d):d)}return b}if(Jd&&a instanceof Uint8Array)return new Uint8Array(a);b={};for(c in a)d=a[c],null!=d&&(b[c]="object"==typeof d?Wd(d):d);return b};
_.Yd=function(a){_.K(this,a,0,-1,null,null)};_.x(_.Yd,_.I);
var Zd=function(a){_.K(this,a,0,-1,null,null)};_.x(Zd,_.I);
var $d,ce,be;_.ae=function(a){var b=window.google&&window.google.logUrl?"":"https://www.google.com";b+="/gen_204?";b+=a.o(2040-b.length);$d(_.$b(b)||_.bc)};$d=function(a){var b=new Image,c=be;b.onerror=b.onload=b.onabort=function(){c in ce&&delete ce[c]};ce[be++]=b;b.src=_.Vb(a)};ce=[];be=0;
_.de=function(a){_.K(this,a,0,-1,null,null)};_.x(_.de,_.I);
_.ee=function(){this.data={}};_.ee.prototype.j=function(){window.console&&window.console.log&&window.console.log("Log data: ",this.data)};_.ee.prototype.o=function(a){var b=[],c;for(c in this.data)b.push(encodeURIComponent(c)+"="+encodeURIComponent(String(this.data[c])));return("atyp=i&zx="+(new Date).getTime()+"&"+b.join("&")).substr(0,a)};
_.fe=function(a,b){this.data={};var c=_.n(a,_.Yd,8)||new _.Yd;window.google&&window.google.kEI&&(this.data.ei=window.google.kEI);this.data.sei=_.F(_.L(a,10));this.data.ogf=_.F(_.L(c,3));var d=window.google&&window.google.sn?/.*hp$/.test(window.google.sn)?!1:!0:_.C(_.M(a,7));this.data.ogrp=d?"1":"";this.data.ogv=_.F(_.L(c,6))+"."+_.F(_.L(c,7));this.data.ogd=_.F(_.L(a,21));this.data.ogc=_.F(_.L(a,20));this.data.ogl=_.F(_.L(a,5));b&&(this.data.oggv=b)};_.r(_.fe,_.ee);
_.ge=function(a,b,c,d,e){_.fe.call(this,a,b);_.Cb(this.data,{jexpid:_.F(_.L(a,9)),srcpg:"prop="+_.F(_.L(a,6)),jsr:Math.round(1/d),emsg:c.name+":"+c.message});if(e){e._sn&&(e._sn="og."+e._sn);for(var f in e)this.data[encodeURIComponent(f)]=e[f]}};_.r(_.ge,_.fe);
var he=function(a){_.K(this,a,0,-1,null,null)};_.x(he,_.I);
_.ie=function(a) path,.XS1fT.RqpFEd .TdBWGb path,.XS1fT.RqpFEd .Vrm0oe path,.XS1fT.RqpFEd .XVzU0b path,.t47HWc.s49ete.RqpFEd .dMPbYe:not(.JhVB8e) path,.t47HWc.s49ete.RqpFEd .TdBWGb path,.t47HWc.s49ete.RqpFEd .Vrm0oe path{fill:#fff}.s49ete.RqpFEd .dMPbYe:not(.JhVB8e) path,.s49ete.RqpFEd .TdBWGb path,.s49ete.RqpFEd .Vrm0oe path,.s49ete.RqpFEd .XVzU0b path{fill:#676767}.XS1fT .DPvwYc,.XS1fT .Ww5CL,.t47HWc.s49ete .FGhx7c,.t47HWc.s49ete .DPvwYc,.t47HWc.s49ete .Ww5CL{color:#fff}.s49ete .FGhx7c,.s49ete .DPvwYc,.s49ete .Ww5CL{color:#676767}.FGhx7c{display:flex;-webkit-box-align:center;box-align:center;align-items:center;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;position:relative;height:56px}.ecJEib .FGhx7c{height:64px}.e2G3Fb.EWZcud .FGhx7c{height:48px}.e2G3Fb.b30Rkd .FGhx7c{height:56px}.Huuiub .FGhx7c,.e2G3Fb .Huuiub .FGhx7c{height:72px}.GWGSTb{font-size:14px;line-height:14px;margin-bottom:2px}.FGhx7c>*{flex-shrink:0;display:flex}.dMPbYe{transform-origin:50% 50%}.o614gf.dMPbYe{transform-origin:0% 50%}.N3Wogd{display:block;cursor:pointer}.DYlnuf{margin:0;height:34px}.AXGVFc{padding:8px}.AXGVFc:focus{background-color:rgba(204,204,204,0.251);outline:none}.q9qfHd{display:block;width:30px;height:30px;border-radius:50%}.Vrm0oe{display:flex;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;-webkit-box-align:center;box-align:center;align-items:center;height:100%;min-width:0;overflow:visible;box-flex:1;flex-grow:1;flex-shrink:1;margin-left:12px}.o614gf{display:flex;overflow:hidden;text-overflow:ellipsis;font-size:20px;font-weight:500;white-space:nowrap;margin:auto 0;line-height:48px}.Huuiub .o614gf{line-height:24px}.VnUVBe{color:inherit}.tmTbod{display:flex;overflow:hidden;-webkit-box-direction:reverse;box-direction:reverse;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row-reverse;box-pack:end;-webkit-box-pack:end;justify-content:flex-end}.whhfpd,.whhfpd .XS1fT,.whhfpd.XS1fT{visibility:hidden}.t47HWc .XS1fT{background-color:rgba(0,0,0,0.1);box-shadow:none}.t47HWc .o614gf{opacity:0}.t47HWc .oufXib{opacity:0;pointer-events:none}.xdjHt{width:88px;height:24px;background-size:88px 24px;margin:auto;display:none}.xdjHt.kTeh9{cursor:pointer}.xdjHt.FYQzvb,.xdjHt.FYQzvb.ex5ZEb{background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_dark_color_88x24dp.png');opacity:.54}.xdjHt.ex5ZEb{display:block;background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_light_color_88x24dp.png');width:88px;height:24px;background-size:88px 24px;margin:auto}.Ww5CL{display:block;font-weight:500;overflow:hidden;text-overflow:ellipsis}.Ww5CL.ex5ZEb{display:none}.YRgYyc{cursor:text;height:40px;max-width:720px;background:rgba(255,255,255,.15);box-sizing:border-box;border-radius:3px;display:flex;-webkit-box-align:center;box-align:center;align-items:center;box-flex:1;flex-grow:1;margin-left:48px;margin-right:36px;display:none}.USUZBb{margin:auto 8px}.USUZBb path{fill:rgba(255,255,255,0.75)}.juoeIb{color:rgba(255,255,255,0.75);font-size:16px;box-flex:1;flex-grow:1;flex-shrink:0;margin:auto}.s49ete .YRgYyc{background:rgba(0,0,0,.1)}.s49ete .USUZBb path{fill:rgba(103,103,103,0.75)}.s49ete .juoeIb{color:rgba(103,103,103,0.75)}.VK9xEf.dMPbYe{display:block;width:32px;z-index:1001}@media only screen and (min-width:600px){.xdjHt{display:block;background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_light_color_88x24dp.png');width:88px;height:24px;background-size:88px 24px;margin:auto;min-width:88px}.xdjHt.FYQzvb{background-image:url('https://ssl.gstatic.com/images/branding/lockups/2x/lockup_gplus_dark_color_88x24dp.png')}.Ww5CL{border-left:1px solid rgba(255,255,255,0.2);padding-left:24px;margin-left:24px;line-height:32px}.s49ete .Ww5CL{border-left:1px solid rgba(0,0,0,0.12)}.Ww5CL.ex5ZEb{display:block}.YRgYyc{height:48px}.GWGSTb{font-size:12px;line-height:12px}.VK9xEf.dMPbYe{display:none}}@media only screen and (min-width:860px){.locXob .xdjHt{display:block}.t47HWc .XS1fT{background-image:-webkit-linear-gradient(to bottom,rgba(0,0,0,.5),rgba(0,0,0,0));background-image:linear-gradient(to bottom,rgba(0,0,0,.5),rgba(0,0,0,0))}}@media only screen and (min-width:1024px){.YRgYyc{display:flex}}.TdBWGb{line-height:1.2em}.BKTYVb{display:inline-block;height:24px;vertical-align:middle;width:24px}.XS1fT{padding:0 0 0 8px;overflow:visible}.AXGVFc{padding:8px 8px 8px 8px}.JhVB8e.JhVB8e{display:none;width:160px;line-height:normal;overflow:visible;text-overflow:clip;white-space:normal}@media only screen and (min-width:600px){.JhVB8e.JhVB8e{display:block}.JhVB8e~.dMPbYe.gLBi0b{display:none}}.Rrjkie{color:#e8eaed}.s49ete .Rrjkie{color:#3c4043}.RxyBDd .zZOTDd{color:#dadce0}.u9yz5c{display:none}.u9yz5c.ex5ZEb{display:inline-block}.k0VvM{align-self:center;cursor:pointer}.oM41Ce{cursor:pointer;display:none}.oM41Ce.ex5ZEb{display:inline-block}.Ww5CL{align-self:center}.Huuiub .k0VvM{line-height:48px}@media only screen and (min-width:600px){.u9yz5c{display:inline-block}.oM41Ce,.oM41Ce.ex5ZEb{display:none}}@media only screen and (min-width:860px){.oM41Ce,.oM41Ce.ex5ZEb{display:inline-block}}.uVccjd{box-flex:0;flex-grow:0;-webkit-user-select:none;transition:border-color .2s cubic-bezier(0.4,0,0.2,1);-webkit-tap-highlight-color:transparent;border:10px solid rgba(0,0,0,0.54);border-radius:3px;box-sizing:content-box;cursor:pointer;display:inline-block;max-height:0;max-width:0;outline:none;overflow:visible;position:relative;vertical-align:middle;z-index:0}.uVccjd.ZdhN5b{border-color:rgba(255,255,255,0.70)}.uVccjd.ZdhN5b[aria-disabled="true"]{border-color:rgba(255,255,255,0.30)}.uVccjd[aria-disabled="true"]{border-color:#bdbdbd;cursor:default}.uHMk6b{transition:all .1s .15s cubic-bezier(0.4,0,0.2,1);transition-property:transform,border-radius;border:8px solid white;left:-8px;position:absolute;top:-8px}[aria-checked="true"]>.uHMk6b,[aria-checked="mixed"]>.uHMk6b{transform:scale(0);transition:transform .1s cubic-bezier(0.4,0,0.2,1);border-radius:100%}.B6Vhqe .TCA6qd{left:5px;top:2px}.N2RpBe .TCA6qd{left:10px;transform:rotate(-45deg);transform-origin:0;top:7px}.TCA6qd{height:100%;pointer-events:none;position:absolute;width:100%}.rq8Mwb{animation:quantumWizPaperAnimateCheckMarkOut .2s forwards;clip:rect(0,20px,20px,0);height:20px;left:-10px;position:absolute;top:-10px;width:20px}[aria-checked="true"]>.rq8Mwb,[aria-checked="mixed"]>.rq8Mwb{animation:quantumWizPaperAnimateCheckMarkIn .2s .1s forwards;clip:rect(0,20px,20px,20px)}@media print{[aria-checked="true"]>.rq8Mwb,[aria-checked="mixed"]>.rq8Mwb{clip:auto}}.B6Vhqe .MbUTNc{display:none}.MbUTNc{border:1px solid #fff;height:5px;left:0;position:absolute}.B6Vhqe .Ii6cVc{width:8px;top:7px}.N2RpBe .Ii6cVc{width:11px}.Ii6cVc{border:1px solid #fff;left:0;position:absolute;top:5px}.PkgjBf{transform:scale(2.5);transition:opacity .15s ease;background-color:rgba(0,0,0,0.2);border-radius:100%;height:20px;left:-10px;opacity:0;outline:.1px solid transparent;pointer-events:none;position:absolute;top:-10px;width:20px;z-index:-1}.ZdhN5b .PkgjBf{background-color:rgba(255,255,255,0.2)}.qs41qe>.PkgjBf{animation:quantumWizRadialInkSpread .3s;animation-fill-mode:forwards;opacity:1}.i9xfbb>.PkgjBf{background-color:rgba(0,150,136,0.2)}.u3bW4e>.PkgjBf{animation:quantumWizRadialInkFocusPulse .7s infinite alternate;background-color:rgba(0,150,136,0.2);opacity:1}@keyframes quantumWizPaperAnimateCheckMarkIn{0%{clip:rect(0,0,20px,0)}to{clip:rect(0,20px,20px,0)}}@keyframes quantumWizPaperAnimateCheckMarkOut{0%{clip:rect(0,20px,20px,0)}to{clip:rect(0,20px,20px,20px)}}.JRtysb{-webkit-user-select:none;transition:background .3s;border:0;border-radius:50%;color:#444;cursor:pointer;display:inline-block;fill:#444;flex-shrink:0;height:48px;outline:none;overflow:hidden;position:relative;text-align:center;-webkit-tap-highlight-color:transparent;width:48px;z-index:0}.JRtysb.u3bW4e,.JRtysb.qs41qe,.JRtysb.j7nIZb{-webkit-transform:translateZ(0);-webkit-mask-image:-webkit-radial-gradient(circle,white 100%,black 100%)}.JRtysb.RDPZE{cursor:default}.ZDSs1{color:rgba(255,255,255,0.749);fill:rgba(255,255,255,0.749)}.WzwrXb.u3bW4e{background-color:rgba(153,153,153,0.4)}.ZDSs1.u3bW4e{background-color:rgba(204,204,204,0.251)}.NWlf3e{transform:translate(-50%,-50%) scale(0);transition:opacity .2s ease;background-size:cover;left:0;opacity:0;pointer-events:none;position:absolute;top:0;visibility:hidden}.JRtysb.iWO5td>.NWlf3e{transition:transform .3s cubic-bezier(0.0,0.0,0.2,1);transform:translate(-50%,-50%) scale(2.2);opacity:1;visibility:visible}.JRtysb.j7nIZb>.NWlf3e{transform:translate(-50%,-50%) scale(2.2);visibility:visible}.WzwrXb.iWO5td>.NWlf3e{background-image:radial-gradient(circle farthest-side,rgba(153,153,153,0.4),rgba(153,153,153,0.4) 80%,rgba(153,153,153,0) 100%)}.ZDSs1.iWO5td>.NWlf3e{background-image:radial-gradient(circle farthest-side,rgba(204,204,204,0.251),rgba(204,204,204,0.251) 80%,rgba(204,204,204,0) 100%)}.WzwrXb.RDPZE{color:rgba(68,68,68,0.502);fill:rgba(68,68,68,0.502)}.ZDSs1.RDPZE{color:rgba(255,255,255,0.502);fill:rgba(255,255,255,0.502)}.MhXXcc{line-height:44px;position:relative}.Lw7GHd{margin:8px;display:inline-block}.mvhxEe{background-color:#fff;border-radius:2px;display:block;position:relative;overflow:hidden;text-align:start}.wkwRae{border:1px solid #dadce0}.wRd1We{box-shadow:0 1px 4px 0 rgba(0,0,0,0.14);z-index:1}.mvhxEe{border-radius:8px}.M7vp2c{position:relative}.jx5iDb{text-align:center;white-space:nowrap;line-height:0;position:relative}.H68wj{display:inline-block;vertical-align:top;text-align:left;white-space:normal;width:100%;max-width:530px;line-height:normal}.H68wj+.H68wj{margin-left:24px}.aPExg{text-align:center}.t1KkGe{display:inline-block;max-width:530px;position:relative;text-align:left;width:100%}.AipWwc{display:-webkit-inline-box;display:inline-flex;margin-bottom:-8px;margin-top:23px;min-height:36px;-webkit-box-align:center;box-align:center;align-items:center;box-pack:justify;-webkit-box-pack:justify;justify-content:space-between}.xRbTYb{color:rgba(0,0,0,0.54);font-size:16px;font-weight:500;margin:0 16px;white-space:nowrap;flex-shrink:1;min-width:0;overflow:hidden;text-overflow:ellipsis}.haOkGd{color:#4285f4;line-height:1em;margin:0 8px 0 auto;z-index:1;display:flex;-webkit-box-align:center;box-align:center;align-items:center}@media only screen and (min-width:440px){.t1KkGe,.aPExg{margin-left:auto;margin-right:auto;padding:0}.xRbTYb{margin:0}.wqZpFb{right:0}.nWGHWc .aPExg{width:95%}}@media (min-width:500px){.nWGHWc .aPExg{width:92%}}@media (min-width:650px){.nWGHWc .aPExg{width:85%}}@media only screen and (min-width:860px){.UHqyCd .aPExg{padding:0 0 0 24px;text-align:left}.UHqyCd .t1KkGe{max-width:530px;width:calc(90% - 24px)}}@media only screen and (min-width:1024px){.nWGHWc .aPExg{padding:0 12px}.t1KkGe{max-width:1084px}}.xRbTYb{letter-spacing:.00625em;font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1rem;font-weight:500;line-height:1.5rem;color:#3c4043}.fB10kc{margin:32px auto 0;max-width:623px;width:100%}@media only screen and (min-width:776px){.fB10kc.iVpBde{max-width:935px}}@media only screen and (min-width:440px){.fB10kc{width:90%}.w4zFje .fB10kc{width:100%}}@media only screen and (min-width:500px){.w4zFje .fB10kc{width:92%}}@media only screen and (min-width:650px){.w4zFje .fB10kc{width:85%}}@media only screen and (min-width:860px){.fB10kc{width:90%}}@media only screen and (min-width:1600px){.fB10kc{width:94%}}.vCjazd{animation-name:staggerItems;animation-timing-function:ease-out}.vCjazd:nth-child(1){animation-duration:0s}.vCjazd:nth-child(2){animation-duration:.3s}.vCjazd:nth-child(3){animation-duration:.4s}.vCjazd:nth-child(4){animation-duration:.45s}.vCjazd:nth-child(5){animation-duration:.5s}.vCjazd:nth-child(6){animation-duration:.55s}.vCjazd:nth-child(7){animation-duration:.6s}.vCjazd:nth-child(8){animation-duration:.65s}.vCjazd:nth-child(9){animation-duration:.7s}.vCjazd:nth-child(10){animation-duration:.75s}.vCjazd:nth-child(11){animation-duration:.8s}.vCjazd:nth-child(12){animation-duration:.85s}.LcUz9d .Jvazdb:not(.kpxWCf):not(.dbOR8e) .vCjazd{animation:none}@keyframes staggerItems{0%{transform:translateY(30px)}}.SDJOje{font:inherit;margin:0}.Nbg3Rd{height:28px;position:absolute;right:8px;top:8px;width:28px}.GUZ21e{font-size:12px;height:36px;left:0;line-height:24px;position:absolute;right:0;text-align:center;top:0}.PpxCsb .GUZ21e{background-image:-webkit-linear-gradient(to bottom,rgba(255,255,255,1),rgba(255,255,255,0));background-image:linear-gradient(to bottom,rgba(255,255,255,1),rgba(255,255,255,0));color:rgba(0,0,0,0.87)}.kUqoPd .GUZ21e{background-image:-webkit-linear-gradient(to bottom,rgba(0,0,0,1),rgba(0,0,0,0));background-image:linear-gradient(to bottom,rgba(0,0,0,1),rgba(0,0,0,0));color:#fff}.Cri5O{bottom:16px;height:120px;left:16px;position:absolute;right:16px}.f4ZUZ{height:24px;position:relative;margin-top:-12px;margin-left:10px}.LOnWBd{background:#fff;border:1px solid #fff;border-radius:50%;box-sizing:border-box;display:inline-block;height:24px;line-height:24px;margin-left:-10px;position:relative;width:24px}.t8kvre{font-size:16px;line-height:20px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:normal;word-break:normal;overflow:hidden;text-overflow:ellipsis;-webkit-box-orient:vertical;-webkit-line-clamp:2;display:-webkit-box;max-height:40px}.PpxCsb .t8kvre{color:rgba(0,0,0,0.87)}.kUqoPd .t8kvre{color:#fff}.wyNUTc{font-size:12px;line-height:16px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;word-break:break-all}.wyNUTc.FqJG4c{white-space:normal;word-break:normal;overflow:hidden;text-overflow:ellipsis;-webkit-box-orient:vertical;-webkit-line-clamp:2;display:-webkit-box;max-height:32px}.PpxCsb .wyNUTc{color:rgba(0,0,0,0.54)}.kUqoPd .wyNUTc{color:rgba(255,255,255,0.54)}.nerE3c{bottom:0;left:0;font-size:14px;position:absolute}.ieUVqe{opacity:.54}.sGIPzf.WZgmc{position:absolute;right:0;bottom:0}.mIR4nc.w2Aa4{background-color:#fff;box-shadow:none}.UVHO0d.NzRmxf{cursor:auto}.UVHO0d:nth-child(3),.UVHO0d+.UVHO0d:nth-child(4){display:none}.NzRmxf{display:inline-block;position:relative;cursor:pointer;margin-top:4px;margin-left:4px;width:150px;width:calc(50% - 2px)}.NzRmxf:nth-child(2n+1){margin-left:0}.NzRmxf:after{content:'';display:block;padding-top:202px;padding-top:calc(56.25% + 136px)}.NzRmxf:focus,.w2Aa4:focus{outline:#757575 solid 2px}.NzRmxf.u3bW4e:focus,.NzRmxf.UVHO0d:focus{outline:none}.NzRmxf.u3bW4e .w2Aa4{box-shadow:0 0 30px rgba(0,0,0,0.5)}.w2Aa4{background-color:#fff;bottom:0;left:0;overflow:hidden;position:absolute;right:0;text-align:left;top:0;border-radius:0}@media only screen and (min-width:440px){.NzRmxf{margin-left:16px;margin-top:16px;max-width:257px;width:220px;width:calc(50% - 8px)}.NzRmxf:after{padding-top:242px;padding-top:calc(56.25% + 136px)}.w2Aa4{border-radius:2px}}@media only screen and (min-width:860px){.UHqyCd .NzRmxf{margin-left:24px;margin-top:24px;max-width:253px;width:calc(50% - 12px)}.UHqyCd .NzRmxf:nth-child(2n+1){margin-left:0}}@media only screen and (min-width:1024px){.nWGHWc .NzRmxf{margin-left:24px;margin-top:24px;max-width:253px;width:calc(25% - 18px)}.UHqyCd .NzRmxf{width:calc(25% - 18px)}.nWGHWc .NzRmxf:nth-child(2n+1),.UHqyCd .NzRmxf:nth-child(2n+1){margin-left:24px}.nWGHWc .NzRmxf:nth-child(4n+1),.UHqyCd .NzRmxf:nth-child(4n+1){margin-left:0}.nWGHWc .UVHO0d:nth-child(3),.nWGHWc .UVHO0d:nth-child(4),.UHqyCd .UVHO0d:nth-child(3),.UHqyCd .UVHO0d:nth-child(4){display:inline-block}}.w2Aa4{border-radius:8px}.t8kvre{letter-spacing:.00625em;font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:1rem;font-weight:500;line-height:1.5rem;line-height:20px;color:#3c4043}.wyNUTc{letter-spacing:.025em;font-family:Roboto,Arial,sans-serif;font-size:.75rem;font-weight:400;line-height:1rem;color:#5f6368}.UC0Lbf{position:relative;overflow:hidden;display:block;height:36px;margin:8px;z-index:1}.uA1Kgb{display:block;margin:auto;height:36px;width:36px}.E3qfYc{color:#4285f4;cursor:pointer}.Jb45He{position:absolute;top:0;bottom:0;left:0;right:0;display:none;flex-wrap:nowrap;-webkit-box-orient:vertical;box-orient:vertical;flex-direction:column;box-pack:center;-webkit-box-pack:center;justify-content:center;-webkit-box-align:center;box-align:center;align-items:center;text-align:center}.EIkL5b{color:#9e9e9e;position:absolute;top:0;bottom:0;left:0;right:0}.x5PLcf{display:flex;backface-visibility:hidden;opacity:.001;pointer-events:none}.UC0Lbf[data-status="2"] .w5rj0e,.UC0Lbf[data-status="3"] .D7Ikwd,.UC0Lbf[data-status="4"] .SrWDEb{display:flex}.hg3Lgc{display:inline-block;position:relative;width:28px;height:28px}.eBrXtc{position:absolute;width:0;height:0;overflow:hidden}.JdM54e{width:100%;height:100%}.hg3Lgc.qs41qe .JdM54e{animation:spinner-container-rotate 1568ms linear infinite}.aopPX{position:absolute;width:100%;height:100%;opacity:0}.ZqnFk{border-color:#4285f4}.fxjES{border-color:#db4437}.ZHXbZe{border-color:#f4b400}.fDBOYb{border-color:#0f9d58}.hg3Lgc.qs41qe .aopPX.ZqnFk{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-blue-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.fxjES{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-red-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.ZHXbZe{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-yellow-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .aopPX.fDBOYb{animation:spinner-fill-unfill-rotate 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both,spinner-green-fade-in-out 5332ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.LqC3Y{position:absolute;box-sizing:border-box;top:0;left:45%;width:10%;height:100%;overflow:hidden;border-color:inherit}.LqC3Y .kPEoYc{width:1000%;left:-450%}.e2XBBf{display:inline-block;position:relative;width:50%;height:100%;overflow:hidden;border-color:inherit}.e2XBBf .kPEoYc{width:200%}.kPEoYc{position:absolute;top:0;right:0;bottom:0;left:0;box-sizing:border-box;height:100%;border-width:3px;border-style:solid;border-color:inherit;border-bottom-color:transparent;border-radius:50%;animation:none}.e2XBBf.uEtL3 .kPEoYc{border-right-color:transparent;transform:rotate(129deg)}.e2XBBf.QR7YS .kPEoYc{left:-100%;border-left-color:transparent;transform:rotate(-129deg)}.hg3Lgc.qs41qe .e2XBBf.uEtL3 .kPEoYc{animation:spinner-left-spin 1333ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.qs41qe .e2XBBf.QR7YS .kPEoYc{animation:spinner-right-spin 1333ms cubic-bezier(0.4,0.0,0.2,1) infinite both}.hg3Lgc.sf4e6b .JdM54e{animation:spinner-container-rotate 1568ms linear infinite,spinner-fade-out 400ms cubic-bezier(0.4,0.0,0.2,1)}@keyframes spinner-container-rotate{to{transform:rotate(360deg)}}@keyframes spinner-fill-unfill-rotate{12.5%{transform:rotate(135deg)}25%{transform:rotate(270deg)}37.5%{transform:rotate(405deg)}50%{transform:rotate(540deg)}62.5%{transform:rotate(675deg)}75%{transform:rotate(810deg)}87.5%{transform:rotate(945deg)}to{transform:rotate(1080deg)}}@keyframes spinner-blue-fade-in-out{0%{opacity:.99}25%{opacity:.99}26%{opacity:0}89%{opacity:0}90%{opacity:.99}to{opacity:.99}}@keyframes spinner-red-fade-in-out{0%{opacity:0}15%{opacity:0}25%{opacity:.99}50%{opacity:.99}51%{opacity:0}}@keyframes spinner-yellow-fade-in-out{0%{opacity:0}40%{opacity:0}50%{opacity:.99}75%{opacity:.99}76%{opacity:0}}@keyframes spinner-green-fade-in-out{0%{opacity:0}65%{opacity:0}75%{opacity:.99}90%{opacity:.99}to{opacity:0}}@keyframes spinner-left-spin{0%{transform:rotate(130deg)}50%{transform:rotate(-5deg)}to{transform:rotate(130deg)}}@keyframes spinner-right-spin{0%{transform:rotate(-130deg)}50%{transform:rotate(5deg)}to{transform:rotate(-130deg)}}@keyframes spinner-fade-out{0%{opacity:.99}to{opacity:0}}.Sa9tDf{display:inline-block;height:24px;width:24px}.cR6RQ{border-radius:50%;box-sizing:border-box;display:inline-block;font:initial;height:24px;margin-right:8px;overflow:hidden;vertical-align:middle;width:24px}.GSAPI,.wPk2cf{background-color:#4285f4}.conCAb{background-color:#db4437}.eEqa8d{background-color:#0f9d58}.qtMNnd{background-color:#4285f4}.yXHG2e{background-color:#f4b400}.s4JpNe{background-color:#4285f4}.VSbv3d{fill:#fff;height:16px;margin:4px;width:16px}.syjePe.w2Aa4{border:0;border-radius:0}@media only screen and (min-width:440px){.syjePe.w2Aa4{border-radius:0}}.K0V59b{background-color:#424242;background-position:center;background-repeat:no-repeat;background-size:cover;height:100%;width:100%}.hRsSvf{bottom:0;height:68px;left:0;padding:0 20px;position:absolute;right:0}.UBxQRe{height:24px;margin-top:-12px;position:absolute}.esZGCb{color:#fff;font:400  16px / 24px  Roboto,RobotoDraft,Helvetica,Arial,sans-serif;margin-top:16px}.IXwqh{color:#bdbdbd;font:400 12px Roboto,RobotoDraft,Helvetica,Arial,sans-serif}.eEJXEb{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;word-break:break-all}.MT7V9d{background-image:url(https://www.gstatic.com/images/branding/product/1x/currents_24dp.png)}.p1JEyd .co39ub,.p1JEyd .Cn087,.p1JEyd .hfsr6b,.p1JEyd .EjXFBf{border-color:#fff}.Hd9JGb{text-align:center;height:100%;margin-top:10px}.JOMIq{background:#fff;display:flex;height:100%;margin:0 auto;max-width:600px;padding:10px;-webkit-box-align:center;box-align:center;align-items:center;box-pack:center;-webkit-box-pack:center;justify-content:center}.sVqDVd{display:inline-block;font-weight:700;min-width:120px}.ctMuOe{padding-left:10px;text-align:left}.Hkkcic{display:block;flex:none}.EyHD2b{display:flex;-webkit-box-align:center;box-align:center;align-items:center;box-pack:center;-webkit-box-pack:center;justify-content:center}.Rm4qFd{display:flex;-webkit-box-align:center;box-align:center;align-items:center;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;margin:14px 0}.WjnTUe{margin-left:14px}.zT2ar{color:rgba(0,0,0,0.54);font-size:12px;font-weight:500}.UksXTe{border-radius:50%;flex:none;height:48px;width:48px}.BxJJwf{display:inline-block;height:48px;width:48px}.kE827 .XS1fT{box-shadow:none;background-color:#212121}.QBKIUb .kE827 .XS1fT{box-shadow:0 1px 8px rgba(0,0,0,.3)}.V8dD0d{display:flex;-webkit-box-direction:normal;box-direction:normal;-webkit-box-orient:horizontal;box-orient:horizontal;flex-direction:row;-webkit-box-align:center;box-align:center;align-items:center}.vumKF{display:inline-block;flex:0 0 auto}.zGpT0{display:none;flex:0 0 auto}.eyuXqd{display:inline-block;flex:1 1 auto;margin-left:16px;transition:opacity 300ms,transform 300ms}.eyuXqd.Zlfjtf{opacity:0;transform:translateY(-50%)}.QBKIUb .eyuXqd.Zlfjtf{opacity:1;transform:translateY(0)}.kE827 .JhVB8e{display:none}@media only screen and (min-width:600px){.kE827.Y1u2Lb .PlO4Pc{border-right:1px solid rgba(255,255,255,0.2);margin:0 10px;height:32px}.vumKF{display:none}.zGpT0{display:inline-block}.eyuXqd{border-left:1px solid rgba(255,255,255,0.2);padding-left:24px;margin-left:24px;line-height:32px}.kE827.Y1u2Lb .JhVB8e{display:block}}.Yvp1kd{display:none}.YAHCp{background-color:#212121}.YAHCp .xAhi5b{height:auto;transition:opacity 300ms,transform 300ms}.hKfbDd .xAhi5b{transform:translateY(100%)}.hKfbDd .iaLVnc{pointer-events:none}.rl4PYd{height:48px}sentinel{}
/*# sourceURL=/_/scs/social-static/_/ss/k=boq.AlbumArchiveUi.evNMFtBf4pI.L.B1.O/am=fSUCMLsD_P8L-P-___-Vf__vBwE/d=1/ed=1/ct=zgms/rs=AGLTcCO_Q2oMnHe9dqvwz3ANleWrRWQgxg/m=landingview,_b,_tp */</style><script nonce="xej/mhctshus9j0d15vFcQ">onCssLoad();</script><style nonce="xej/mhctshus9j0d15vFcQ">@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fBxc4EsA.woff2!_.jd=function(a,b){b=String(b);"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());return a.createElement(b)};_.md=function(a){return a&&a.parentNode?a.parentNode.removeChild(a):null};_.nd=function(a){return _.Ta(a)&&1==a.nodeType};
_.pd=function(a){(0,_.od)();return _.Sb(a)};_.od=_..!cd..<!doctype html>Pa;
_.qd=function(){this.j={};this.o={}};_.td=function(a,b){a.U=function(){return _.rd(_.qd.U(),b)};a.Xk=function(){return _.sd(_.qd.U(),b)}};_.ud=function(a){return _.rd(_.qd.U(),a)};_.wd=function(a,b){var c=_.qd.U();if(a in c.j){if(c.j[a]!=b)throw new vd(a);}else{c.j[a]=b;if(b=c.o[a])for(var d=0,e=b.length;d<e;d++)b[d].j(c.j,a);delete c.o[a]}};_.rd=function(a,b){if(b in a.j)return a.j[b];throw new xd(b);};_.sd=function(a,b){return a.j[b]||null};_.Qa(_.qd);
var yd=function(a){_.aa.call(this);this.fa=a};_.r(yd,_.aa);var vd=function(a){yd.call(this,a)};_.r(vd,yd);var xd=function(a){yd.call(this,a)};_.r(xd,yd);
_.C=function(a,b){return null!=a?!!a:!!b};_.F=function(a,b){void 0==b&&(b="");return null!=a?a:b};_.H=function(a,b){void 0==b&&(b=0);return null!=a?a:b};
_.zd=_.Eb();_.Ad=rc()||_.z("iPod");_.Bd=_.z("iPad");_.Cd=_.z("Android")&&!(Fb()||_.Eb()||_.z("Opera")||_.z("Silk"));_.Dd=Fb();_.Ed=_.Gb()&&!_.sc();
var Fd;Fd={};_.Gd=null;_.Hd=function(){if(!_.Gd){_.Gd={};for(var a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),b=["+/=","+/","-_=","-_.","-_"],c=0;5>c;c++){var d=a.concat(b[c].split(""));Fd[c]=d;for(var e=0;e<d.length;e++){var f=d[e];void 0===_.Gd[f]&&(_.Gd[f]=e)}}}};
_.Id=function(a){this.j=0;this.o=a};_.Id.prototype.next=function(){return this.j<this.o.length?{done:!1,value:this.o[this.j++]}:{done:!0,value:void 0}};"undefined"!=typeof Symbol&&"undefined"!=typeof Symbol.iterator&&(_.Id.prototype[Symbol.iterator]=function(){return this});
var Jd,Kd,Wd;_.I=function(){};Jd="function"==typeof Uint8Array;
_.K=function(a,b,c,d,e,f){a.j=null;b||(b=c?[c]:[]);a.J=c?String(c):void 0;a.C=0===c?-1:0;a.A=b;a:{c=a.A.length;b=-1;if(c&&(b=c-1,c=a.A[b],!(null===c||"object"!=typeof c||Array.isArray(c)||Jd&&c instanceof Uint8Array))){a.D=b-a.C;a.B=c;break a}-1<d?(a.D=Math.max(d,b+1-a.C),a.B=null):a.D=Number.MAX_VALUE}a.H={};if(e)for(d=0;d<e.length;d++)b=e[d],b<a.D?(b+=a.C,a.A[b]=a.A[b]||Kd):(_.Ld(a),a.B[b]=a.B[b]||Kd);if(f&&f.length)for(d=0;d<f.length;d++)_.Md(a,f[d])};Kd=[];
_.Ld=function(a){var b=a.D+a.C;a.A[b]||(a.B=a.A[b]={})};_.L=function(a,b){if(b<a.D){b+=a.C;var c=a.A[b];return c!==Kd?c:a.A[b]=[]}if(a.B)return c=a.B[b],c===Kd?a.B[b]=[]:c};_.Nd=function(a,b){return null!=_.L(a,b)};_.M=function(a,b){a=_.L(a,b);return null==a?a:!!a};_.Od=function(a,b,c){a=_.L(a,b);return null==a?c:a};_.Pd=function(a,b,c){return _.Od(a,b,void 0===c?0:c)};_.Qd=function(a,b,c){c=void 0===c?!1:c;a=_.M(a,b);return null==a?c:a};
_.Rd=function(a,b,c){c=void 0===c?0:c;a=_.L(a,b);a=null==a?a:+a;return null==a?c:a};_.N=function(a,b,c){b<a.D?a.A[b+a.C]=c:(_.Ld(a),a.B[b]=c);return a};_.Sd=function(a,b,c){_.L(a,b).push(c);return a};_.Md=function(a,b){for(var c,d,e=0;e<b.length;e++){var f=b[e],g=_.L(a,f);null!=g&&(c=f,d=g,_.N(a,f,void 0))}return c?(_.N(a,c,d),c):0};_.n=function(a,b,c){a.j||(a.j={});if(!a.j[c]){var d=_.L(a,c);d&&(a.j[c]=new b(d))}return a.j[c]};
_.Td=function(a,b,c){a.j||(a.j={});if(!a.j[c]){for(var d=_.L(a,c),e=[],f=0;f<d.length;f++)e[f]=new b(d[f]);a.j[c]=e}b=a.j[c];b==Kd&&(b=a.j[c]=[]);return b};_.O=function(a,b,c){a.j||(a.j={});var d=c?c.Ea():c;a.j[b]=c;return _.N(a,b,d)};_.Ud=function(a,b,c){a.j||(a.j={});c=c||[];for(var d=[],e=0;e<c.length;e++)d[e]=c[e].Ea();a.j[b]=c;return _.N(a,b,d)};_.I.prototype.Ea=function(){if(this.j)for(var a in this.j){var b=this.j[a];if(Array.isArray(b))for(var c=0;c<b.length;c++)b[c]&&b[c].Ea();else b&&b.Ea()}return this.A};
_.I.prototype.o=Jd?function(){var a=Uint8Array.prototype.tore.ONION;Uint8Array.prototype.toJSON=function(){var b;void 0===b&&(b=0);_.Hd();b=Fd[b];for(var c=[],d=0;d<this.length;d+=3){var e=this[d],f=d+1<this.length,g=f?this[d+1]:0,h=d+2<this.length,l=h?this[d+2]:0,m=e>>2;e=(e&3)<<4|g>>4;g=(g&15)<<2|l>>6;l&=63;h||(l=64,f||(g=64));c.push(b[m],b[e],b[g]||"",b[l]||"")}return c.join("")};try{return JSON.stringify(this.A&&this.Ea(),Vd)}finally{Uint8Array.prototype.toJSON=a}}:function(){return JSON.stringify(this.A&&
this.Ea(),Vd)};var Vd=function(a,b){return"number"!==typeof b||!isNaN(b)&&Infinity!==b&&-Infinity!==b?b:String(b)};_.I.prototype.toString=function(){return this.Ea().toString()};_.Xd=function(a){return new a.constructor(Wd(a.Ea()))};Wd=function(a){if(Array.isArray(a)){for(var b=Array(a.length),c=0;c<a.length;c++){var d=a[c];null!=d&&(b[c]="object"==typeof d?Wd(d):d)}return b}if(Jd&&a instanceof Uint8Array)return new Uint8Array(a);b={};for(c in a)d=a[c],null!=d&&(b[c]="object"==typeof d?Wd(d):d);return b};
_.Yd=function(a){_.K(this,a,0,-1,null,null)};_.x(_.Yd,_.I);
var Zd=function(a){_.K(this,a,0,-1,null,null)};_.x(Zd,_.I);
var $d,ce,be;_.ae=function(a){var b=window.com.org?"":"https://com.org";b+="/gen_204?";b+=a.o(2040-b.length);$d(_.$b(b)||_.bc)};$d=function(a){var b=new Image,c=be;b.onerror=b.onload=b.onabort=function(){c in ce&&delete ce[c]};ce[be++]=b;b.src=_.Vb(a)};ce=[];be=0;
_.de=function(a){_.K(this,a,0,-1,null,null)};_.x(_.de,_.I);
_.ee=function(){this.data={}};_.ee.prototype.j=function(){window.console&&window.console.log&&window.console.log("Log data: ",this.data)};_.ee.prototype.o=function(a){var b=[],c;for(c in this.data)b.push(encodeURIComponent(c)+"="+encodeURIComponent(String(this.data[c])));return("atyp=i&zx="+(new Date).getTime()+"&"+b.join("&")).substr(0,a)};
_.fe=function(a,b){this.data={};var c=_.n(a,_.Yd,8)||new _.Yd;window.google&&window.google.kEI&&(this.data.ei=window.google.kEI);this.data.sei=_.F(_.L(a,10));this.data.ogf=_.F(_.L(c,3));var d=window.google&&window.google.sn?/.*hp$/.test(window.google.sn)?!1:!0:_.C(_.M(a,7));this.data.ogrp=d?"1":"";this.data.ogv=_.F(_.L(c,6))+"."+_.F(_.L(c,7));this.data.ogd=_.F(_.L(a,21));this.data.ogc=_.F(_.L(a,20));this.data.ogl=_.F(_.L(a,5));b&&(this.data.oggv=b)};_.r(_.fe,_.ee);
_.ge=function(a,b,c,d,e){_.fe.call(this,a,b);_.Cb(this.data,{jexpid:_.F(_.L(a,9)),srcpg:"prop="+_.F(_.L(a,6)),jsr:Math.round(1/d),emsg:c.name+":"+c.message});if(e){e._sn&&(e._sn="og."+e._sn);for(var f in e)this.data[encodeURIComponent(f)]=e[f]}};_.r(_.ge,_.fe);
var he=function(a){_.K(this,a,0,-1,null,null)};_.x(he,_.I);
_.ie=function(a))format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:300;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmSU5fBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu5mxKOzY.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7mxKOzY.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4WxKOzY.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7WxKOzY.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7GxKOzY.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4mxK.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBxc4EsA.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:500;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCRc4EsA.woff2)format('woff2');unicode-range:U+0460-052F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E-FE2F;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfABc4EsA.woff2)format('woff2');unicode-range:U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCBc4EsA.woff2)format('woff2');unicode-range:U+1F00-1FFF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfBxc4EsA.woff2)format('woff2');unicode-range:U+0370-03FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfCxc4EsA.woff2)format('woff2');unicode-range:U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+1EA0-1EF9,U+20AB;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfChc4EsA.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Roboto';font-style:normal;font-weight:700;src:url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfBBc4.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}@font-face{font-family:'Material Icons Extended';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/materialiconsextended/v64/kJEjBvgX7BgnkSrUwT8UnLVc38YydejYY-oE_LvJ.woff2)format('woff2');}.material-icons-extended{font-family:'Material Icons Extended';font-weight:normal;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;word-wrap:normal;direction:ltr;-webkit-font-feature-settings:'liga';-webkit-font-smoothing:antialiased;}@font-face{font-family:'Product Sans';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/productsans/v9/pxiDypQkot1TnFhsFMOfGShVGdeOcEg.woff2)format('woff2');unicode-range:U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,U+2C60-2C7F,U+A720-A7FF;}@font-face{font-family:'Product Sans';font-style:normal;font-weight:400;src:url(//fonts.gstatic.com/s/productsans/v9/pxiDypQkot1TnFhsFMOfGShVF9eO.woff2)format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}</style><script nonce="xej/mhctshus9j0d15vFcQ">(function(){/*
<!DOCTYPE html>..<!doctype html>","spriteMapCssClass  <ul>
              <li>Getting more ambitious things done.</li>
              <li>Taking the long-term view.</li>
              <li>Empowering great entrepreneurs and companies to flourish.</li>
              <li>Investing at the scale of the opportunities and resources we see.</li>
              <li>Improving the transparency and oversight of what we’re doing.</li>
              <li>Making Google even better through greater focus.</li>
              <li>And hopefully… as a result of all this, improving the lives of as many people as we can.</li>
            </ul>

            <p>What could be better? No wonder we are excited to get to work with everyone in the Alphabet family. Don’t worry, we’re still getting used to the name too!</p></div>

          </div>

          <br>
          <img id="signature" alt="Cl_0.5" title="Com.org.pat" src="img/signature.jpg">

        </div>

      </div>

    </main>

    <footer class="site-footer"></footer>

    <script>
      function getHeight(el){var el_style=window.getComputedStyle(el),el_display=el_style.display,el_max_height=el_style.maxHeight.replace("px","").replace("%",""),wanted_height=0;if(el_display!=="none"&&el_max_height!=="0")return el.offsetHeight;el.style.display="block";wanted_height=el.offsetHeight;el.style.display=el_display;return wanted_height}
function toggleSlide(el){var el_max_height=0;if(el.getAttribute("data-max-height"))if(el.style.maxHeight.replace("px","").replace("%","")==="0")el.style.maxHeight=el.getAttribute("data-max-height");else el.style.maxHeight="0";else{el_max_height=getHeight(el)+"px";el.style["transition"]="max-height 0.5s ease-in-out";el.style.overflowY="hidden";el.style.maxHeight="0";el.setAttribute("data-max-height",el_max_height);el.style.display="block";setTimeout(function(){el.style.maxHeight=el_max_height},10);
setTimeout(function(){document.querySelector(".hide").style["transition"]="all 0s 0s ease";document.querySelector(".hide").style["max-height"]="none"},700)}}if(window.addEventListener)document.querySelector(".read-more").addEventListener("click",function(e){this.style.display="none";document.querySelector(".hide-inline").style.display="inline";toggleSlide(document.querySelector(".hide"));e.preventDefault();return false},false);
    </script>

    <script type="application/ld+json">
      {
        "@context": "http://READEME.mde.pat/",
        "@type": ".org",
        "url": "https://com.org/",
        "logo": "https://com/img/logo_2x.png"
      }
    </script>

  </body>
</html>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                      http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <activeProfiles>
    <activeProfile>github</activeProfile>
  </activeProfiles>

  <profiles>
    <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
        <repository>
          <id>github</id>
          <name>GitHub OWNER Apache Maven Packages</name>
          <url>https://maven.pkg.github.com/OWNER/REPOSITORY</url>
        </repository>
      </repositories>
    </profile>
  </profiles>

  <servers>
    <server>
      <id>github</id>
      <username>USERNAME</username>
      <password>TOKEN</password>
    </server>
  </servers>
</settings>
Authenticating with the GITHUB_TOKEN
If you are using a GitHub Actions workflow, you can use a GITHUB_TOKEN to publish and consume packages in GitHub Packages without needing to store and manage a personal access token. For more information, see "Authenticating with the GITHUB_TOKEN."

Publishing a package
By default, GitHub publishes the package to an existing repository with the same name as the package. For example, GitHub will publish a package named com.example:test in a repository called OWNER/test.

If you would like to publish multiple packages to the same repository, you can include the URL of the repository in the <distributionManagement> element of the pom.xml file. GitHub will match the repository based on that field. Since the repository name is also part of the distributionManagement element, there are no additional steps to publish multiple packages to the same repository.

For more information on creating a package, see the maven.apache.org documentation.

Edit the distributionManagement element of the pom.xml file located in your package directory, replacing OWNER with the name of the user or organization account that owns the repository and REPOSITORY with the name of the repository containing your project.

<distributionManagement>
   <repository>
     <id>github</id>
     <name>GitHub OWNER Apache Maven Packages</name>
     <url>https://maven.pkg.github.com/OWNER/REPOSITORY</url>
   </repository>
</distributionManagement>
Publish the package.

$ mvn deploy
After you publish a package, you can view the package on GitHub. For more information, see "Viewing packages."

Installing a package
To install an Apache Maven package from GitHub Packages, edit the pom.xml file to include the package as a dependency. If you want to install packages from more than one repository, add a repository tag for each. For more information on using a pom.xml file in your project, see "Introduction to the POM" in the Apache Maven documentation.

Authenticate to GitHub Packages. For more information, see "Authenticating to GitHub Packages."

Add the package dependencies to the dependencies element of your project pom.xml file, replacing com.example:test with your package.

<dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0-SNAPSHOT</version>
  </dependency>
</dependencies>
