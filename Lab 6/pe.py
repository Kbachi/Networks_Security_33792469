
import pefile

#this is my filepath that works for me you probably need to change it to mark it 
sample = r"C:\Users\usayd\Downloads\ProcessMonitor\Procmon.exe"

pe = pefile.PE(sample)

print("Entry Point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("Image Base:", hex(pe.OPTIONAL_HEADER.ImageBase))

print("\nImported DLLs and functions:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(" ", entry.dll.decode())
    # Print first 5 imported functions from this DLL
    for imp in entry.imports[:5]:
        name = imp.name.decode() if imp.name else "None"
        print("   -", name)
