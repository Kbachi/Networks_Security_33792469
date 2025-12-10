
import hashlib
import bcrypt

def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_bcrypt(password: str, rounds: int = 12) -> bytes:
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def verify_bcrypt(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)

if __name__ == "__main__":
    pw = "MyP@ssw0rd@"

    md5_hash = hash_md5(pw)
    sha_hash = hash_sha256(pw)
    bcrypt_hash = hash_bcrypt(pw)

    print("Password:", pw)
    print("MD5:      ", md5_hash)
    print("SHA-256:  ", sha_hash)
    print("bcrypt:   ", bcrypt_hash)

    print("Verify bcrypt (correct):", verify_bcrypt(pw, bcrypt_hash))
    print("Verify bcrypt (wrong):  ", verify_bcrypt("wrongpass", bcrypt_hash))
