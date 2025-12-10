
import bcrypt
import pyotp
import qrcode

from password_str import check_password_strength
from hashing import hash_bcrypt, verify_bcrypt

class AuthSystem:
    def __init__(self, issuer: str = "MySecureApp"):
        self.users = {}  # username  {password_hash, totp_secret}
        self.issuer = issuer

    def register_user(self, username: str, password: str) -> str:
        if username in self.users:
            raise ValueError("Username already exists")

        score, verdict = check_password_strength(password)
        print(f"Password strength: score={score}, verdict={verdict}")
        if verdict in ("Very Weak", "Weak"):
            raise ValueError("Password too weak. Choose a stronger password.")

        pw_hash = hash_bcrypt(password)  # bcrypt hash (includes salt)
        secret = pyotp.random_base32()

        self.users[username] = {
            "password_hash": pw_hash,
            "totp_secret": secret,
        }

        # Generate QR code for TOTP
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name=self.issuer)
        qr_filename = f"{username}_totp_qr.png"
        img = qrcode.make(uri)
        img.save(qr_filename)

        print(f"User {username!r} registered.")
        print(f"Scan the QR code in file: {qr_filename}")
        return qr_filename

    def authenticate(self, username: str, password: str, totp_code: str):
        user = self.users.get(username)
        if not user:
            return False, "Unknown username"

        pw_hash = user["password_hash"]
        if not verify_bcrypt(password, pw_hash):
            return False, "Invalid password"

        secret = user["totp_secret"]
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code):
            return False, "Invalid TOTP code"

        return True, "Authentication successful"

if __name__ == "__main__":
    auth = AuthSystem()

    # 1) Register a user
    username = "billybob"
    password = "Billybooba23!#"

    try:
        qr_file = auth.register_user(username, password)
    except ValueError as e:
        print("Registration error:", e)
        exit(1)

    print("\nNow open your authenticator app and scan the QR code:", qr_file)
    print("Once configured, try logging in.\n")

    # 2) Attempt login
    login_user = input("Username to login: ").strip()
    login_pw = input("Password: ").strip()
    login_totp = input("Enter the 6-digit TOTP code from your app: ").strip()

    ok, msg = auth.authenticate(login_user, login_pw, login_totp)
    print(msg)
