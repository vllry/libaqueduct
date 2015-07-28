import gnupg
from os import remove



class GPG:

	def __init__(self, name):
		self.gpg = gnupg.GPG(gnupghome='/etc/aqueduct/gpg')
		self.keyid = ""
		for key in self.gpg.list_keys():
			if key['uids'][0].startswith(name):
				self.keyid = key['keyid']
				self.fingerprint = key['fingerprint']
				print("Found gpg key " + self.keyid)
				break
		if not self.keyid:
			input_data = self.gpg.gen_key_input(key_type="RSA", key_length=1024, name_real=name)
			key = self.gpg.gen_key(input_data) #Investigate rng-tools if VMs have trouble with lack of entropy
			print(key)
			print("Created new gpg key")


	def import_key(self, keypath):
		with open(keypath) as f:
			import_result = self.gpg.import_keys(f.read())


	def export_key(self, fingerprint=''):
		if not fingerprint:
			fingerprint = self.fingerprint
		return self.gpg.export_keys(fingerprint)


	def encrypt_file(self, filepath, recipient):
		with open(filepath, 'rb') as f:
			status = self.gpg.encrypt_file(f, [recipient], sign=self.fingerprint, output=filepath+'.gpg')
			print('status: ' + status.status)
			print('stderr: ' + status.stderr)
			if status.ok:
				#signature = self.gpg.sign('This is some text :)')
				signature = self.gpg.sign_file(f, keyid=self.keyid, output=filepath+'.sig')
				with open(filepath+'.asc', 'w') as asc:
					print(signature)
					asc.write(str(signature))


	def decrypt_file(self, filepath, newfile, delete=True):
		with open(filepath, 'rb') as f:
			status = self.gpg.decrypt_file(f, output=newfile)
			if delete:
				remove(filepath)
			return status


	def verify_file(self, filepath):
		with open(filepath, 'rb') as f:
			verified = self.gpg.verify_file(f)
			if verified:
				return True
			else:
				print('ERROR: Could not verify ' + filepath)
				return False



gpg = GPG('Aqueduct Builder')
gpg.encrypt_file('/home/vallery/Development/Aqueduct/libaqueduct/LICENSE', 'B66C2FD3BA1F3B64')
gpg.verify_file('/home/vallery/Development/Aqueduct/libaqueduct/LICENSE.asc')
