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



#http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]



class PriorityQueue(metaclass=Singleton):
	def __init__(self, maxsize=0): #Only runs during the first call to PriorityQueue
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

	def dequeue(self):
		return self.dequeue_with_priority()[0]

	def dequeue_with_priority(self):
		score,keys,values = self.queue.get()
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
