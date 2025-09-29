import hashlib

password = 'abc123'
ph = hashlib.md5(password.encode())

with open('pass.txt', 'w') as f:
    f.write(f"user:{ph.hexdigest()}")