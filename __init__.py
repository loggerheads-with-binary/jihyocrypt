"""
python3 -m pip install pycryptodome pretty_traceback

annautils personal cryptography toolbox
Python code to pretty much encrypt and decrypt files, binary, standard objects into each other

syntax: enc/dec_x2x
	where x: s -> Pickleable object; f-> File ; b -> Binary data
	enc/dec : enc -> Encryption , dec -> Decryption
	example: enc_s2f means encrypt from a standard object to a file
"""

BUFFER_SIZE  : int = 3*1024*1024						#3 MB
__version__ : str = '2.0.0'								##Optional Progress Bar Added for most functions
DEFAULT_OBFUSCATION_ROUNDS : int = 6					##N rounds of computation for key_decryptor and first_block_blender

password_to_bytes= lambda password : (password.encode('utf8')) if isinstance(password , str) else password
password_to_str = lambda password: (password.decode('utf8')) if isinstance(password , bytes) else password

"""Copy the following classes into self.password_generators script as well, this is copy pasted for more efficient albeit longer and dirtier code"""


import os, sys
from Crypto.Cipher import Salsa20
from hashlib import sha512 , sha256
import io 
import time 
import warnings

class PasswordError(ValueError):
	pass

class CorruptionError(ValueError):
	pass

def key_decryptor(nonce : bytes , password : bytes , rounds : int = DEFAULT_OBFUSCATION_ROUNDS):

	r = nonce
	password = password_to_bytes(password)

	for i in range(rounds):
		r = sha256(r + password).digest()

	return r

def first_block_blender(nonce : bytes , enc_password : bytes , user_password : bytes ,  rounds : int = DEFAULT_OBFUSCATION_ROUNDS):

	s = nonce
	major_pass = password_to_bytes(enc_password) + password_to_bytes(user_password)


	for i in range(rounds):
		s = sha512(s + major_pass).digest()

	return s

def key_maker( password : bytes ,nonce : bytes = None , rounds : int = DEFAULT_OBFUSCATION_ROUNDS , redundant : bool = True):

	if nonce == None:

		nonce = os.urandom(8)

	password = password_to_bytes(password)

	r = key_decryptor(nonce , password )

	if redundant:
		s = first_block_blender(nonce , r , password )
		return (nonce , r , s)

	return (nonce , r)

"""Function Classes Copy Stop Here"""

	
FULL_BLOCK , EMPTY_BLOCK , BLOCK_LENGTH = "🟢" , "🔴" , 25

def eprint(*args, **kwargs):


	print(*args, file=sys.stderr, **kwargs)

make_block = lambda processed , total , blocks = 25 : \
			FULL_BLOCK*(-(processed*blocks)//-total) + EMPTY_BLOCK*(((total-processed)*blocks)//total)
							##Ceiling												##Floor 

def enc_redundant_warning():

	warnings.warn("Encryption being executed using non-redundant mode. This is risky and has no mode of verification/check in decryption.\
	Use this mode only if you understand what you're doing" , Warning)

def dec_redundant_warning():

	warnings.warn("Decryption being conducted using non-redundant mode. Make sure the file was definitely encrypted using \
	non-redundant mode" , Warning)

def enc_b2b(data : bytes , password: bytes , redundant: bool = True , **kwargs ):

	if not redundant:
		enc_redundant_warning() 

	vals= key_maker(password, redundant = redundant)
	cipher = Salsa20.new(vals[1] , vals[0])

	if redundant:
		return vals[0] + vals[-1] + cipher.encrypt(data)

	return vals[0] + cipher.encrypt(data)

def dec_b2b(data : bytes , password: bytes , redundant : bool = True , **kwargs):

	if not redundant:
		dec_redundant_warning()

	counter = 0 
	n = len(data)

	if n < 8:
		raise CorruptionError("The input data is corrupted, since it does not contain nonce")

	counter +=8 
	nonce = data[:8]

	vals = key_maker(password, nonce = nonce , redundant = redundant)
	cipher = Salsa20.new(vals[1] , vals[0])

	if redundant:

		if n < 72 : 
			raise CorruptionError("The input data is corrupted, does not possess JPIC block")

		if  vals[-1] != data[8:72]:
			raise PasswordError("Incorrect password inputted")

		counter += 64

	
	return cipher.decrypt(data[counter:])

def subroutine_major(	cipher, function : str  , i_handle , o_handle, size : int , 
						progress_bar : bool = True , buffer_size : int = BUFFER_SIZE ,
						**kwargs) :
	running_size = 0 
	EXECUTED_FLAG = False 
	func_ = getattr(cipher , function)

	def display():
		
		nonlocal running_size , size, EXECUTED_FLAG, st_time 

		while not ((EXECUTED_FLAG) and (running_size == size)):

			eprint( f'{(running_size*100)//size}% |{make_block(running_size , size)}| {running_size}/{size}B @{int(running_size/(time.time()-st_time))>>3}KBps' , 
			end = '')
			time.sleep(0.2)

		return None 

	def execute():

		nonlocal buffer_size , i_handle, o_handle, func_ , EXECUTED_FLAG , running_size 

		input_line = i_handle.read(buffer_size)

		while input_line != b'':

			o_handle.write(func_(input_line))
			running_size += buffer_size 
			input_line = i_handle.read(buffer_size)

		EXECUTED_FLAG = False 
		running_size = size 

		return None 

	if progress_bar:
		
		from multiprocessing import Process 

		d = Process(target = display )
		e = Process(target = execute)

		st_time = time.time() 
		time.sleep(10**(-4))		##To avoid divide by zero errors 

		d.start()
		e.start()

		e.join()
		d.join() 

		return d.exitcode, e.exitcode 
	else:

		return execute()
		
def enc_major(	i_handle , o_handle , size : int  , password : bytes , 
				redundant : bool = True , progress_bar : bool = False , buffer_size = BUFFER_SIZE , 
				**kwargs):

	if not redundant:
		enc_redundant_warning() 

	vals = key_maker(password , redundant = redundant)
	cipher = Salsa20.new(vals[1] , vals[0] ) 

	o_handle.write(vals[0])

	if redundant:
		o_handle.write(vals[-1])

	return subroutine_major(cipher , 'encrypt' , 
							i_handle , o_handle, size , 
							progress_bar, buffer_size , **kwargs)

def dec_major(	i_handle , o_handle, size: int , password : bytes , 	
				redundant: bool = True , progress_bar : bool = False , buffer_size : int = BUFFER_SIZE , **kwargs):

	if not redundant:
		dec_redundant_warning()

	nonce = i_handle.read(8)
	size -=8 

	if len(nonce) < 8:
		raise CorruptionError("The input source is corrupted as it doesnt even contain nonce")

	vals = key_maker(password , nonce = nonce, redundant = redundant )
	cipher = Salsa20.new(vals[1] , vals[0])

	if redundant:

		f_block = i_handle.read(64)

		if len(f_block) < 64:
			raise CorruptionError("The input source is corrupted as it doesnt contain enough data for JPIC")

		if f_block != vals[-1]:

			raise PasswordError("Incorrect Password input by user")
		
		size -= 64 

	return subroutine_major(cipher , 'decrypt' , 
							i_handle , o_handle, size , 
							progress_bar , buffer_size , **kwargs)

def enc_b2f(data : bytes , filename : str , password: str , redundant : bool = True , progress_bar : bool = False , 
			buffer_size : int = BUFFER_SIZE ):

	i_handle = io.BytesIO(data)
	size = len(data)
	
	with open(filename , 'wb') as o_handle:

		enc_major(i_handle , o_handle , size , password , redundant, progress_bar , buffer_size )

	return True 

def enc_f2f(input_file : str , output_file : str , password : bytes , redundant : bool = True, progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	size = os.stat(input_file).st_size

	with open(input_file  , 'rb' ) as i_handle:
		with open(output_file , 'wb' ) as o_handle:

			enc_major(i_handle , o_handle , size , password , redundant , progress_bar , buffer_size)
	
	return True 

def enc_f2b(input_file : str , password: bytes , redundant : bool = True, progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	size = os.stat(input_file).st_size 
	o_handle = io.BytesIO()

	with open(input_file  , 'rb' ) as i_handle:

		enc_major(	i_handle , o_handle , size, 
					password , redundant , progress_bar , buffer_size )

	return o_handle.getvalue() 

def dec_f2f(input_file : str , output_file : str , password : bytes , redundant : bool = True, progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	size = os.stat(input_file).st_size

	with open(input_file, 'rb') as i_handle:
		with open(output_file, 'wb') as o_handle:

			dec_major(	i_handle , o_handle , size , 
						password, redundant , progress_bar , buffer_size)

	return True 
 
def dec_f2b(input_file : str , password: bytes , redundant : bool = True, progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	size = os.stat(input_file).st_size 
	o_handle = io.BytesIO()  

	with open(input_file , 'rb') as i_handle:

		dec_major(	i_handle , o_handle , size , 
					password , redundant , progress_bar , buffer_size ) 

	return o_handle.getvalue() 

def dec_b2f(data : bytes , password: bytes , output_file : str , redundant : bool = True , progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	size = len(data)
	i_handle = io.BytesIO(data)
	
	with open(output_file , 'wb') as o_handle:

		dec_major(	i_handle , o_handle , size ,
					password , redundant , progress_bar , buffer_size)

	return True 

"""Dependent Functions"""

#enc_b2f
def enc_s2f(data : bytes , filename : str , password: str , redundant : bool = True , progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	import _pickle as pickle

	data = pickle.dumps(data)

	return enc_b2f(	data = data , filename = filename , password = password , 
					redundant = redundant , progress_bar = progress_bar , buffer_size = buffer_size)

#enc_b2b
def enc_s2b(data : bytes , password : bytes, redundant : bool = True):

	import _pickle as pickle

	data = pickle.dumps(data)

	return enc_b2b(data = data , password = password , redundant = redundant)

#dec_f2b
def dec_f2s(input_file : str , password: bytes , redundant : bool = True, progress_bar : bool = False , buffer_size : int = BUFFER_SIZE):

	import _pickle as pickle

	return pickle.loads(dec_f2b(input_file = input_file, 
								password = password , redundant = redundant , progress_bar = progress_bar , buffer_size = buffer_size ))

#dec_b2b
def dec_b2s(data : bytes, password: bytes , redundant : bool = True):

	import _pickle as pickle

	return pickle.loads(dec_b2b(data = data , password = password , redundant = redundant))
