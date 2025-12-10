
import hashlib

#this is my filepath that works for me you probably need to change it to mark it 
sample = r"C:\Users\usayd\Downloads\ProcessMonitor\Procmon.exe"


def compute_hash(path, algorithm):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

print("MD5:   ", compute_hash(sample, "md5"))
print("SHA1:  ", compute_hash(sample, "sha1"))
print("SHA256:", compute_hash(sample, "sha256"))