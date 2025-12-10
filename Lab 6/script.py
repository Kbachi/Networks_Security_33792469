import hashlib
import pefile
import re
import yara

#this is my filepath that works for me you probably need to change it to mark it 
sample = r"C:\Users\usayd\Downloads\ProcessMonitor\Procmon.exe"

def compute_hashes(path):
    algos = ["md5", "sha1", "sha256"]
    out = {}
    for algo in algos:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            h.update(f.read())
        out[algo] = h.hexdigest()
    return out

def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()
    return re.findall(rb"[ -~]{4,}", data)

print("=== HASHES ===")
hashes = compute_hashes(sample)
for algo, value in hashes.items():
    print(f"{algo.upper()}: {value}")

print("\n=== STRINGS (first 15) ===")
strings = extract_strings(sample)
for s in strings[:15]:
    print(s.decode(errors="ignore"))

print("\n=== IMPORTED DLLs ===")
pe = pefile.PE(sample)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(" ", entry.dll.decode())

print("\n=== IOCs (URLs & IPs) ===")
decoded = open(sample, "rb").read().decode(errors="ignore")
urls = re.findall(r"https?://[^\s\"']+", decoded)
ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", decoded)

print("URLs found:")
for u in urls:
    print(" -", u)

print("IPs found:")
for ip in ips:
    print(" -", ip)

print("\n=== YARA ===")
rule_source = """
rule ContainsHTTP {
    strings:
        $s = "http"
    condition:
        $s
}
"""
rules = yara.compile(source=rule_source)
matches = rules.match(sample)

print("Matches:", [m.rule for m in matches])
