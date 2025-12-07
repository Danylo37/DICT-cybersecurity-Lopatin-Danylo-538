from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
import os
from typing import Optional, Union


ORIGINAL_MESSAGE = "Lopatin Danylo\nGroup 538"


class CryptoSystem:
    """Base class for encrypting and decrypting data using AES and RSA."""

    def __init__(self) -> None:
        """Initialize crypto system with CFB mode by default."""
        self.__sessionkey: Optional[bytes] = None
        self.__rsa_private_key: Optional[RSA.RsaKey] = None
        self.__rsa_public_key: Optional[RSA.RsaKey] = None
        self.__signature_private_key: Optional[RSA.RsaKey] = None
        self.__signature_public_key: Optional[RSA.RsaKey] = None
        self.mode: int = AES.MODE_CFB

    def generate_key(self, key_size: int = 128) -> bytes:
        """Generate a random session key of specified size."""
        key_bytes = key_size // 8
        self.__sessionkey = Random.new().read(key_bytes)
        return self.__sessionkey

    def get_key(self) -> Optional[bytes]:
        """Return the current session key."""
        return self.__sessionkey

    def set_key(self, key: bytes) -> None:
        """Set the session key."""
        self.__sessionkey = key

    def set_mode(self, mode: int) -> None:
        """Set the AES encryption mode."""
        self.mode = mode

    def save_key_to_file(self, filename: str) -> None:
        """Save the session key to a file."""
        if self.__sessionkey is None:
            raise ValueError("Session key is not set")
        with open(filename, 'wb') as f:
            f.write(self.__sessionkey)

    def generate_rsa_keys(self) -> None:
        """Generate RSA key pair (2048 bits)."""
        self.__rsa_private_key = RSA.generate(2048)
        self.__rsa_public_key = self.__rsa_private_key.publickey()

    def get_public_key(self) -> Optional[RSA.RsaKey]:
        """Return the public RSA key."""
        return self.__rsa_public_key

    def set_public_key(self, public_key: RSA.RsaKey) -> None:
        """Set the public RSA key."""
        self.__rsa_public_key = public_key

    def save_rsa_keys(self, private_filename: str, public_filename: str) -> None:
        """Save RSA keys to files in PEM format."""
        if self.__rsa_private_key is None or self.__rsa_public_key is None:
            raise ValueError("RSA keys are not generated")

        with open(private_filename, 'wb') as f:
            f.write(self.__rsa_private_key.exportKey('PEM'))

        with open(public_filename, 'wb') as f:
            f.write(self.__rsa_public_key.exportKey('PEM'))

    def load_rsa_key(self, filename: str, is_private: bool = False) -> None:
        """Load RSA key from file."""
        with open(filename, 'rb') as f:
            key_data = f.read()

        if is_private:
            self.__rsa_private_key = RSA.importKey(key_data)
            self.__rsa_public_key = self.__rsa_private_key.publickey()
        else:
            self.__rsa_public_key = RSA.importKey(key_data)

    def encrypt_rsa(self, data: bytes) -> bytes:
        """Encrypt data using RSA public key."""
        if self.__rsa_public_key is None:
            raise ValueError("RSA public key is not set")

        cipher_rsa = PKCS1_OAEP.new(self.__rsa_public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        return encrypted_data

    def decrypt_rsa(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using RSA private key."""
        if self.__rsa_private_key is None:
            raise ValueError("RSA private key is not set")

        cipher_rsa = PKCS1_OAEP.new(self.__rsa_private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)
        return decrypted_data

    def encrypt(self, text: Union[str, bytes]) -> bytes:
        """Encrypt text or bytes using AES."""
        if self.__sessionkey is None:
            raise ValueError("Session key is not set")

        iv = Random.new().read(16)

        if isinstance(text, str):
            text = text.encode('utf-8')

        if self.mode in [AES.MODE_CBC, AES.MODE_ECB]:
            pad_length = 16 - (len(text) % 16)
            text = text + bytes([pad_length] * pad_length)

        cipher = AES.new( # type: ignore[misc]
            self.__sessionkey,
            self.mode,
            iv if self.mode != AES.MODE_ECB else None
        )
        encrypted_text = iv + cipher.encrypt(text)
        return encrypted_text

    def decrypt(self, encrypted_text: bytes) -> str:
        """Decrypt encrypted data and return string."""
        if self.__sessionkey is None:
            raise ValueError("Session key is not set")

        iv = encrypted_text[:16]

        cipher = AES.new( # type: ignore[misc]
            self.__sessionkey,
            self.mode,
            iv if self.mode != AES.MODE_ECB else None
        )
        decrypted_text = cipher.decrypt(encrypted_text[16:])

        if self.mode in [AES.MODE_CBC, AES.MODE_ECB]:
            unpad_length = decrypted_text[-1]
            decrypted_text = decrypted_text[:-unpad_length]

        return decrypted_text.decode('utf-8')

    def decrypt_bytes(self, encrypted_text: bytes) -> bytes:
        """Decrypt encrypted data and return bytes."""
        if self.__sessionkey is None:
            raise ValueError("Session key is not set")

        iv = encrypted_text[:16]

        cipher = AES.new( # type: ignore[misc]
            self.__sessionkey,
            self.mode,
            iv if self.mode != AES.MODE_ECB else None
        )
        decrypted_text = cipher.decrypt(encrypted_text[16:])

        if self.mode in [AES.MODE_CBC, AES.MODE_ECB]:
            unpad_length = decrypted_text[-1]
            decrypted_text = decrypted_text[:-unpad_length]

        return decrypted_text

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """Encrypt file contents and save to another file."""
        with open(input_file, 'rb') as f:
            data = f.read()

        encrypted_data = self.encrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """Decrypt encrypted file and save the result."""
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self.decrypt(encrypted_data)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)

    def generate_signature_keys(self) -> None:
        """Generate RSA key pair for digital signature (2048 bits)."""
        self.__signature_private_key = RSA.generate(2048)
        self.__signature_public_key = self.__signature_private_key.publickey()

    def get_signature_public_key(self) -> Optional[RSA.RsaKey]:
        """Return the public signature key."""
        return self.__signature_public_key

    def set_signature_public_key(self, public_key: RSA.RsaKey) -> None:
        """Set the public signature key."""
        self.__signature_public_key = public_key

    def save_signature_keys(self, private_filename: str, public_filename: str) -> None:
        """Save signature keys to files in PEM format."""
        if self.__signature_private_key is None or self.__signature_public_key is None:
            raise ValueError("Signature keys are not generated")

        with open(private_filename, 'wb') as f:
            f.write(self.__signature_private_key.exportKey('PEM'))

        with open(public_filename, 'wb') as f:
            f.write(self.__signature_public_key.exportKey('PEM'))

    def load_signature_key(self, filename: str, is_private: bool = False) -> None:
        """Load signature key from file."""
        with open(filename, 'rb') as f:
            key_data = f.read()

        if is_private:
            self.__signature_private_key = RSA.importKey(key_data)
            self.__signature_public_key = self.__signature_private_key.publickey()
        else:
            self.__signature_public_key = RSA.importKey(key_data)

    def sha256(self, data: Union[str, bytes]) -> bytes:
        """Compute SHA256 hash of data."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_obj = SHA256.new(data)
        return hash_obj.digest()

    def sign(self, data: Union[str, bytes]) -> bytes:
        """Create digital signature for data."""
        if self.__signature_private_key is None:
            raise ValueError("Signature private key is not set")

        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_obj = SHA256.new(data)
        signer = PKCS1_v1_5.new(self.__signature_private_key)
        signature = signer.sign(hash_obj)
        return signature

    def verify(self, data: Union[str, bytes], signature: bytes) -> bool:
        """Verify digital signature for data."""
        if self.__signature_public_key is None:
            raise ValueError("Signature public key is not set")

        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_obj = SHA256.new(data)
        verifier = PKCS1_v1_5.new(self.__signature_public_key)
        return verifier.verify(hash_obj, signature)

    def sign_file(self, input_file: str) -> bytes:
        """Create digital signature for file contents."""
        with open(input_file, 'rb') as f:
            data = f.read()
        return self.sign(data)

    def verify_file(self, input_file: str, signature: bytes) -> bool:
        """Verify digital signature for file contents."""
        with open(input_file, 'rb') as f:
            data = f.read()
        return self.verify(data, signature)


class Sender(CryptoSystem):
    """Message sender class."""

    def generate_session_key(self, key_size: int = 256) -> bytes:
        """Generate a new session key for current transmission round."""
        return self.generate_key(key_size)


class Receiver(CryptoSystem):
    """Message receiver class."""
    pass


def demonstrate_digital_signature() -> None:
    """Demonstrate digital signature creation and verification."""
    print("Digital Signature Demonstration:")

    sender = Sender()
    receiver = Receiver()

    sender.generate_signature_keys()

    os.makedirs("./files", exist_ok=True)
    sender.save_signature_keys(
        os.path.join('files', 'signature_private_key.pem'),
        os.path.join('files', 'signature_public_key.pem')
    )

    receiver.set_signature_public_key(sender.get_signature_public_key())

    print(f"\nOriginal message:\n{ORIGINAL_MESSAGE}")
    print(f"Original message in hex: {ORIGINAL_MESSAGE.encode('utf-8').hex()}")

    hash_value = sender.sha256(ORIGINAL_MESSAGE)
    print(f"\nSHA256 hash of original message: {hash_value.hex()}")

    signature = sender.sign(ORIGINAL_MESSAGE)
    print(f"\nDigital signature: {signature.hex()}")

    is_valid = receiver.verify(ORIGINAL_MESSAGE, signature)
    print(f"\nSignature verification result: {is_valid}")

    modified_message = "Modified message"
    is_valid_modified = receiver.verify(modified_message, signature)
    print(f"\nVerification with modified message: {is_valid_modified}")


def demonstrate_full_cycle() -> None:
    """Demonstrate full encryption and signature cycle."""
    print("\nFull Cycle: Encryption + Digital Signature:")

    sender = Sender()
    receiver = Receiver()

    receiver.generate_rsa_keys()
    sender.generate_signature_keys()

    sender.set_public_key(receiver.get_public_key())
    receiver.set_signature_public_key(sender.get_signature_public_key())

    session_key = sender.generate_session_key(256)
    print(f"\nSession key: {session_key.hex()}")

    encrypted_session_key = sender.encrypt_rsa(session_key)
    print(f"Encrypted session key in hex: {encrypted_session_key.hex()}")

    decrypted_session_key = receiver.decrypt_rsa(encrypted_session_key)
    receiver.set_key(decrypted_session_key)

    print(f"\nOriginal message:\n{ORIGINAL_MESSAGE}")
    print(f"Original message in hex: {ORIGINAL_MESSAGE.encode('utf-8').hex()}")

    hash_before = sender.sha256(ORIGINAL_MESSAGE)
    print(f"\nSHA256 hash before encryption: {hash_before.hex()}")

    signature = sender.sign(ORIGINAL_MESSAGE)
    print(f"\nDigital signature: {signature.hex()}")

    encrypted_message = sender.encrypt(ORIGINAL_MESSAGE)
    print(f"\nEncrypted message in hex: {encrypted_message.hex()}")

    encrypted_signature = sender.encrypt(signature)
    print(f"Encrypted signature in hex: {encrypted_signature.hex()}")

    decrypted_signature = receiver.decrypt_bytes(encrypted_signature)
    print(f"\nDecrypted signature: {decrypted_signature.hex()}")

    decrypted_message = receiver.decrypt(encrypted_message)
    print(f"\nDecrypted message:\n{decrypted_message}")
    print(f"Decrypted message in hex: {decrypted_message.encode('utf-8').hex()}")

    hash_after = receiver.sha256(decrypted_message)
    print(f"\nSHA256 hash after decryption: {hash_after.hex()}")

    is_valid = receiver.verify(decrypted_message, decrypted_signature)
    print(f"\nSignature verification result: {is_valid}")
    print(f"Message integrity confirmed: {hash_before.hex() == hash_after.hex()}")


def demonstrate_file_signature() -> None:
    """Demonstrate file signing and verification."""
    print("\nFile Signing and Verification:")

    sender = Sender()
    receiver = Receiver()

    sender.generate_signature_keys()
    receiver.set_signature_public_key(sender.get_signature_public_key())

    os.makedirs("./files", exist_ok=True)

    file_to_sign = os.path.join('files', 'file_to_sign.txt')
    with open(file_to_sign, 'w', encoding='utf-8') as f:
        f.write(ORIGINAL_MESSAGE)

    file_signature = sender.sign_file(file_to_sign)
    print(f"File signature: {file_signature.hex()}")

    with open(os.path.join('files', 'signature.bin'), 'wb') as f:
        f.write(file_signature)

    is_valid = receiver.verify_file(file_to_sign, file_signature)
    print(f"\nFile signature verification: {is_valid}")


def main() -> None:
    """Main function to demonstrate crypto system functionality."""
    os.makedirs("./files", exist_ok=True)

    demonstrate_digital_signature()
    demonstrate_full_cycle()
    demonstrate_file_signature()


if __name__ == "__main__":
    main()