
import math
import string

COMMON_PASSWORDS = {
    "111111", "password1", "12345", "qwerty", "abc123",
    "password", "1234567", "123456789", "12345678", "123456"
}

def password_entropy(password: str) -> float:
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)

def check_password_strength(password: str):
    if password.lower() in COMMON_PASSWORDS:
        return 0, "Very Weak (common password)"

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = 0

    # Length points
    if length >= 8:
        score += 2
    if length >= 12:
        score += 2
    if length >= 16:
        score += 1

    # Variety points
    score += has_lower + has_upper + has_digit + has_symbol

    # Entropy points
    ent = password_entropy(password)
    if ent >= 40:
        score += 1
    if ent >= 60:
        score += 1

    # Map score to verdict
    if score <= 2:
        verdict = "Very Weak"
    elif score <= 4:
        verdict = "Weak"
    elif score <= 7:
        verdict = "Medium"
    elif score <= 9:
        verdict = "Strong"
    else:
        verdict = "Very Strong"

    return score, verdict

if __name__ == "__main__":
    tests = ["Pass123", "MyP@ssw0rd@", "password", "MapleBatterySyrup2!"]
    for pwd in tests:
        s, v = check_password_strength(pwd)
        print(f"{pwd!r} -> score={s}, verdict={v}, entropy={password_entropy(pwd):.2f} bits")
