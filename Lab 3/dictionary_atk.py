
import hashlib

def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def dictionary_attack(target_hash: str, wordlist, algo: str = "md5"):
    print(f"Starting dictionary attack using {algo}")
    for i, word in enumerate(wordlist, start=1):
        if algo == "md5":
            candidate_hash = hash_md5(word)
        elif algo == "sha256":
            candidate_hash = hash_sha256(word)
        else:
            raise ValueError("Unsupported")

        if candidate_hash == target_hash:
            print(f"[+] Found password: {word!r} after {i} attempts")
            return word
    print("[-] Password not found in wordlist.")
    return None

if __name__ == "__main__":
    common_passwords = [
        "password", "123456", "123456789", "qwerty",
        "111111", "abc123", "chaomain", "monk", "dragooon"
    ]

    secret_password = "dragooon"
    target_hash_md5 = hash_md5(secret_password)
    target_hash_sha = hash_sha256(secret_password)

    print("Target MD5 hash:", target_hash_md5)
    dictionary_attack(target_hash_md5, common_passwords, algo="md5")

    print("\nTarget SHA-256 hash:", target_hash_sha)
    dictionary_attack(target_hash_sha, common_passwords, algo="sha256")
