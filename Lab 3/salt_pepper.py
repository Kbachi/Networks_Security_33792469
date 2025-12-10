
import os
import base64
import hashlib

PEPPER = "SUPER_SECRET_PEPPER_VALUE"  
def generate_salt(n_bytes: int = 16) -> str:
    return base64.b64encode(os.urandom(n_bytes)).decode("utf-8")

def sha256_no_salt(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def sha256_with_salt(password: str, salt: str) -> str:
    to_hash = (password + salt).encode("utf-8")
    return hashlib.sha256(to_hash).hexdigest()

def sha256_with_salt_and_pepper(password: str, salt: str, pepper: str = PEPPER) -> str:
    to_hash = (password + salt + pepper).encode("utf-8")
    return hashlib.sha256(to_hash).hexdigest()

if __name__ == "__main__":
    pw = "MyP@ssw0rd@"

    print("=== No salt ===")
    h1 = sha256_no_salt(pw)
    h2 = sha256_no_salt(pw)
    print("Hash 1:", h1)
    print("Hash 2:", h2)
    print("Same?", h1 == h2)

    print("\n=== With salt ===")
    salt1 = generate_salt()
    salt2 = generate_salt()
    hs1 = sha256_with_salt(pw, salt1)
    hs2 = sha256_with_salt(pw, salt2)
    print("Salt1:", salt1)
    print("Hash1:", hs1)
    print("Salt2:", salt2)
    print("Hash2:", hs2)

    print("\n=== With salt + pepper ===")
    hsp1 = sha256_with_salt_and_pepper(pw, salt1)
    hsp2 = sha256_with_salt_and_pepper(pw, salt2)
    print("Salt1 + pepper ->", hsp1)
    print("Salt2 + pepper ->", hsp2)
    print("Same?", hsp1 == hsp2)