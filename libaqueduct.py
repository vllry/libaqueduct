#from os import makedirs
import gnupg



class GPG:

	def __init__(self, name):
		gpg = gnupg.GPG(gnupghome='/home/vallery/.gnupg')
		keyid = ""
		for key in gpg.list_keys():
			if key['uids'][0].startswith(name):
				keyid = key['keyid']
				print("Found key")
				break
		if not keyid:
			input_data = gpg.gen_key_input(key_type="RSA", key_length=1024, name_real=name)
			key = gpg.gen_key(input_data)
			print("Created key")


#GPG('Aqueduct Builder')
