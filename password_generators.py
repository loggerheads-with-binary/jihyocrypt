
password_to_bytes = lambda password : (password.encode('utf8')) if isinstance(password , str) else password
password_to_str = lambda password: (password.decode('utf8')) if instance(password , bytes) else password

class PasswordError(ValueError):
	pass

class CorruptionError(ValueError):
	pass

def key_decryptor(nonce : bytes , password : bytes , rounds : int = 6):


	from hashlib import sha512 , sha256

	r = nonce
	password = password_to_bytes(password)

	for i in range(rounds):
		r = sha256(r + password).digest()

	return r

def first_block_blender(nonce : bytes , enc_password : bytes , user_password : bytes ,  rounds : int = 6):

	from hashlib import sha512

	s = nonce
	major_pass = password_to_bytes(enc_password) + password_to_bytes(user_password)


	for i in range(rounds):
		s = sha512(s + major_pass).digest()

	return s

def key_maker( password : bytes = b'',nonce : bytes = None , rounds : int = 6 , redundant : bool = True):

	if nonce == None:
		import os
		nonce = os.urandom(8)

	password = password_to_bytes(password)

	r = key_decryptor(nonce , password )

	if redundant:
		s = first_block_blender(nonce , r , password )
		return (nonce , r , s)

	return (nonce , r)
