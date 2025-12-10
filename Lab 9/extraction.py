import subprocess 

def ask(prompt): 
    out = subprocess.run(["ollama", "run", "smollm2:1.7b"], 
                         input=prompt.encode(), 
                         stdout=subprocess.PIPE) 
    return out.stdout.decode() 

# Structured repeated queries 
inputs = [ 
    "Summarise the concept of Gen AI security in one sentence.",
    "Summarise the concept of Gen AI security in one sentence." 
] 
print("=== Model Extraction Pattern Test ===") 
for i, prompt in enumerate(inputs): 
    print(f"\nAttempt {i+1}") 
    print(ask(prompt))
