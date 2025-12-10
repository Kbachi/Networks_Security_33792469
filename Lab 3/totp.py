
import pyotp
import qrcode

def create_totp_secret() -> str:
    return pyotp.random_base32()

def generate_totp_uri(secret: str, username: str, issuer: str = "SecureLogin") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def save_qr_code(data: str, filename: str):
    img = qrcode.make(data)
    img.save(filename)
    print(f"QR code saved to {filename}")

def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

if __name__ == "__main__":
    username = "arisu"
    secret = create_totp_secret()
    print("TOTP secret (store this for the user):", secret)

    uri = generate_totp_uri(secret, username=username, issuer="SecureLogin")
    print("Provisioning URI:", uri)

    qr_filename = f"{username}_totp_qr.png"
    save_qr_code(uri, qr_filename)
    print("Scan this QR with Google Authenticator / Authy.")

    # Example verification loop:
    while True:
        code = input("Enter the 6-digit code from your authenticator app (or 'q' to quit): ").strip()
        if code.lower() == "q":
            break
        if verify_totp_code(secret, code):
            print("Code is valid!")
        else:
            print("Invalid code, try again.")
