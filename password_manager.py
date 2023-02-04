import hashlib
import base64
import os
import json
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, password):
        self.key = self.generate_key(password)
        self.passwords = {}
        self.load_passwords()

    def generate_key(self, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(key)

    def encrypt(self, password):
        f = Fernet(self.key)
        password_encrypted = f.encrypt(password.encode())
        return password_encrypted

    def decrypt(self, password_encrypted):
        f = Fernet(self.key)
        password = f.decrypt(password_encrypted).decode()
        return password

    def save_passwords(self):
        passwords_encrypted = {}
        for account, password in self.passwords.items():
            passwords_encrypted[account] = self.encrypt(password)
        with open('passwords.json', 'w') as f:
            json.dump(passwords_encrypted, f)

    def load_passwords(self):
        try:
            with open('passwords.json', 'r') as f:
                passwords_encrypted = json.load(f)
            for account, password_encrypted in passwords_encrypted.items():
                password = self.decrypt(password_encrypted)
                self.passwords[account] = password
        except:
            pass

    def add_password(self, account, password):
        self.passwords[account] = password
        self.save_passwords()

    def get_password(self, account):
        return self.passwords.get(account)

