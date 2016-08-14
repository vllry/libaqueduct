from os import path, remove
import queue
import requests
import tarfile
import time

import gnupg


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


def download(url, accept_errors=False):
	try:
		r = requests.get(url)
	except requests.exceptions.ConnectionError:
		return None
	else:
		if not accept_errors and (r.status_code < 200 or r.status_code >= 300):
			return None
		else:
			return r.content


# http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class PriorityQueue(metaclass=Singleton):
	def __init__(self, maxsize=0):  # Only runs during the first call to PriorityQueue
		self.queue = queue.PriorityQueue(maxsize) #Mon Capitaine

	def __dict_from_tup__(self, keys, values):
		dictionary = {}
		for k in range(0,len(keys)):
			dictionary[keys[k]] = values[k]
		return dictionary

	def enqueue(self, dictionary, prioritymod=0):
		self.enqueue_with_priority(dictionary, time.time()-prioritymod)

	def enqueue_nowait(self, dictionary, prioritymod=0):
		self.enqueue_with_priority(dictionary, time.time()-prioritymod, wait=False)

	def enqueue_with_priority(self, dictionary, priority, wait=True):
		keys = []
		values = []
		for k in dictionary.keys():
			keys.append(k)
			values.append(dictionary[k])
		self.queue.put((priority, keys, values), wait)

	def dequeue(self, block=True):
		return self.dequeue_with_priority(block)[0]

	def dequeue_with_priority(self, block=True):
		score,keys,values = self.queue.get(block)
		return self.__dict_from_tup__(keys, values), score

	def list(self):
		items = []
		items_nice = []
		while True:
			try:
				i = self.queue.get_nowait()
			except queue.Empty:
				break
			else:
				items.append(i)
				items_nice.append(self.__dict_from_tup__(i[1], i[2]))

		for i in items:
			self.queue.put(i) #Don't enqueue, since we want to preserve the priority
		return items_nice

	def delete(self, tup):
		deleted = False
		items = []
		while True:
			try:
				i = self.queue.get_nowait()
			except queue.Empty:
				break
			finally:
				if i[1] == tup:
					deleted = True
					break
				else:
					items.append(i)

		for i in items:
			self.queue.put(i) #Don't enqueue, since we want to preserve the priority
		return deleted


class GPG:
	def __init__(self, name, gpg_dir, create=False, alert_notexists=True):
		self.gpg = gnupg.GPG(gnupghome=gpg_dir)
		self.keyid = ''
		for key in self.gpg.list_keys():
			if key['uids'][0].startswith(name):
				self.keyid = key['keyid']
				self.fingerprint = key['fingerprint']
				print('Loaded gpg key ' + self.keyid)
				break

		if not self.keyid:
			if create:
				input_data = self.gpg.gen_key_input(key_type='RSA', key_length=2048, name_real=name)
				self.gpg.gen_key(input_data) #Investigate rng-tools if VMs have trouble with lack of entropy
				print('Created new gpg key')
				self.__init__(name, gpg_dir, False) #I'm a bad girl
			elif alert_notexists:
				print('Unable to find GPG key for %s in %s' % (name, gpg_dir))

	def import_key(self, keydata):
		import_result = self.gpg.import_keys(keydata)
		fingerprint = import_result.fingerprints[0]
		for key in self.pubkeys():
			if key['fingerprint'] == fingerprint:
				return key['keyid']

	def import_key_file(self, keypath):
		with open(keypath) as f:
			self.import_key(f.read())

	def export(self, keyid=''):
		if not keyid: #Can't reference self in the function definition
			keyid = self.keyid
		return self.gpg.export_keys(keyid)

	def encrypt_file(self, filepath, recipient, sign=False):
		with open(filepath, 'rb') as f:
			status = self.gpg.encrypt_file(f, [recipient], output=filepath+'.gpg', always_trust=True)
			print('status: ' + status.status)
			print('stderr: ' + status.stderr)
			if status.ok and sign:
				self.sign_file(filepath)

	def sign_file(self, filepath):
		with open(filepath, 'rb') as f:
			self.gpg.sign_file(f, keyid=self.keyid, detach=True, output=filepath+'.asc') #Using output on this function requires python3-gnupg >=0.3.7

	def sign_and_encrypt_file(self, filepath, recipient):
		self.sign_file(filepath)
		self.encrypt_file(filepath, recipient)

	def decrypt_file(self, filepath, newfile, delete=True):
		with open(filepath, 'rb') as f:
			status = self.gpg.decrypt_file(f, output=newfile)
			if delete and status:
				remove(filepath)
			return status

	def verify_file(self, datafile, sigfile):
		with open(sigfile, 'rb') as f:
			verified = self.gpg.verify_file(f, datafile)
			if verified:
				return verified.key_id
			print('ERROR: Could not verify ' + datafile)
			return None

	def decrypt_and_verify_file(self, datafile, sigfile, outfile):
		self.decrypt_file(datafile, outfile, True)
		verified = self.verify_file(outfile, sigfile)
		remove(sigfile)
		return verified

	def pubkeys(self):
		return self.gpg.list_keys(False)
