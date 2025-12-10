
import yara

#this is my filepath that works for me you probably need to change it to mark it 
sample = r"C:\Users\usayd\Downloads\ProcessMonitor\Procmon.exe"

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
print(matches)
