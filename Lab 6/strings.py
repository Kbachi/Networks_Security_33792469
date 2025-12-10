import re


#this is my filepath that works for me you probably need to change it to mark it 
sample = r"C:\Users\usayd\Downloads\ProcessMonitor\Procmon.exe"

def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()

    pattern = rb"[ -~]{4,}"
    return re.findall(pattern, data)

strings = extract_strings(sample)

# Show the first 20 strings
for s in strings[:20]:
    print(s.decode(errors="ignore"))
