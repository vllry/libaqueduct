import gnupg
from os import path, remove
import requests
import tarfile



def targz(source_dir, output_filename):
    with tarfile.open(output_filename, 'w:gz') as tar:
        tar.add(source_dir, arcname=path.basename(source_dir))



def untargz(filepath, dest):
	with tarfile.open(filepath, 'r:gz') as tfile:
		tfile.extractall(dest)
		name = tfile.getnames()[0]
		remove(filepath)
		return name



def upload(filepath, url, postdata={}):
	f = open(filepath, 'rb')
	r = requests.post(
		url,
		postdata,
		files =  {'data' : f}
	)
	f.close()
	return r.text



class GPG:

	def __init__(self, name, recursed=False):
		self.gpg = gnupg.GPG(gnupghome='/etc/aqueduct/gpg')
		self.keyid = ""
		for key in self.gpg.list_keys():
			if key['uids'][0].startswith(name):
				self.keyid = key['keyid']
				self.fingerprint = key['fingerprint']
				print("Loaded gpg key " + self.keyid)
				break
		if not self.keyid and not recursed:
			input_data = self.gpg.gen_key_input(key_type="RSA", key_length=2048, name_real=name)
			self.gpg.gen_key(input_data) #Investigate rng-tools if VMs have trouble with lack of entropy
			print("Created new gpg key")
			self.__init__(name, True)


	def import_key(self, keypath):
		with open(keypath) as f:
			import_result = self.gpg.import_keys(f.read())


	def export(self, fingerprint=''):
		if not fingerprint:
			fingerprint = self.fingerprint
		return self.gpg.export_keys(fingerprint)


	def encrypt_file(self, filepath, recipient):
		with open(filepath, 'rb') as f:
			status = self.gpg.encrypt_file(f, [recipient], sign=self.fingerprint, output=filepath+'.gpg')
			print('status: ' + status.status)
			print('stderr: ' + status.stderr)
			#if status.ok:
				#with open(filepath, 'rb') as f:
					#self.gpg.sign_file(f, keyid=self.keyid, output=filepath+'.asc') #Using output on this function requires >=0.3.7 (I think)


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
