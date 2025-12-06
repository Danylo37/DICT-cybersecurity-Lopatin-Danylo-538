from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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


class Sender(CryptoSystem):
    """Message sender class."""

    def generate_session_key(self, key_size: int = 256) -> bytes:
        """Generate a new session key for current transmission round."""
        return self.generate_key(key_size)


class Receiver(CryptoSystem):
    """Message receiver class."""
    pass


def demonstrate_aes_encryption() -> None:
    """Demonstrate AES encryption in CFB and CBC modes with file operations."""
    print("AES encryption demonstration:")

    sender = Sender()
    receiver = Receiver()

    key = sender.generate_key(256)
    print(f"\nSession key: {key.hex()}")

    receiver.set_key(sender.get_key())

    os.makedirs("./files", exist_ok=True)
    sender.save_key_to_file(os.path.join('files', 'session_key.bin'))

    print(f"\nDemonstration in CFB mode:")
    print(f"\nOriginal message:\n{ORIGINAL_MESSAGE}")
    print(f"Original message in bytes: {ORIGINAL_MESSAGE.encode('utf-8')}")
    print(f"Original message in hex: {ORIGINAL_MESSAGE.encode('utf-8').hex()}")

    encrypted = sender.encrypt(ORIGINAL_MESSAGE)
    print(f"\nEncrypted message in hex: {encrypted.hex()}")

    decrypted = receiver.decrypt(encrypted)
    print(f"\nDecrypted message:\n{decrypted}")
    print(f"Decrypted message in bytes: {decrypted.encode('utf-8')}")
    print(f"Decrypted message in hex: {decrypted.encode('utf-8').hex()}")

    with open(os.path.join('files', 'original_message.txt'), 'w', encoding='utf-8') as f:
        f.write(ORIGINAL_MESSAGE)

    sender.encrypt_file(os.path.join('files', 'original_message.txt'),
                        os.path.join('files', 'encrypted_message.bin'))
    receiver.decrypt_file(os.path.join('files', 'encrypted_message.bin'),
                          os.path.join('files', 'decrypted_message.txt'))

    sender.set_mode(AES.MODE_CBC)
    receiver.set_mode(AES.MODE_CBC)

    print(f"\nDemonstration in CBC mode:")
    print(f"\nOriginal message:\n{ORIGINAL_MESSAGE}")
    print(f"Original message in bytes: {ORIGINAL_MESSAGE.encode('utf-8')}")
    print(f"Original message in hex: {ORIGINAL_MESSAGE.encode('utf-8').hex()}")

    encrypted = sender.encrypt(ORIGINAL_MESSAGE)
    print(f"\nEncrypted message in hex: {encrypted.hex()}")

    decrypted = receiver.decrypt(encrypted)
    print(f"\nDecrypted message:\n{decrypted}")
    print(f"Decrypted message in bytes: {decrypted.encode('utf-8')}")
    print(f"Decrypted message in hex: {decrypted.encode('utf-8').hex()}")


def demonstrate_rsa_encryption() -> None:
    """Demonstrate RSA encryption and decryption."""
    print("\nRSA encryption demonstration:")

    sender = Sender()
    receiver = Receiver()

    receiver.generate_rsa_keys()

    os.makedirs("./files", exist_ok=True)
    receiver.save_rsa_keys(
        os.path.join('files', 'private_key.pem'),
        os.path.join('files', 'public_key.pem')
    )

    sender.set_public_key(receiver.get_public_key())

    original_data = ORIGINAL_MESSAGE.encode('utf-8')
    print(f"\nOriginal data: {original_data}")
    print(f"Original data in hex: {original_data.hex()}")

    encrypted_rsa = sender.encrypt_rsa(original_data)
    print(f"\nEncrypted with RSA in hex: {encrypted_rsa.hex()}")

    decrypted_rsa = receiver.decrypt_rsa(encrypted_rsa)
    print(f"\nDecrypted data: {decrypted_rsa}")
    print(f"Decrypted data in hex: {decrypted_rsa.hex()}")


def demonstrate_combined_encryption() -> None:
    """Demonstrate combined symmetric and asymmetric encryption."""
    print("\nCombined encryption scheme (AES + RSA):")

    sender = Sender()
    receiver = Receiver()

    receiver.generate_rsa_keys()

    receiver.save_rsa_keys(
        os.path.join('files', 'private_key_rec.pem'),
        os.path.join('files', 'public_key_rec.pem')
    )

    sender.set_public_key(receiver.get_public_key())

    session_key = sender.generate_session_key(256)
    print(f"\nSession key: {session_key.hex()}")

    encrypted_session_key = sender.encrypt_rsa(session_key)
    print(f"Encrypted session key in hex: {encrypted_session_key.hex()}")

    decrypted_session_key = receiver.decrypt_rsa(encrypted_session_key)
    print(f"Decrypted session key: {decrypted_session_key.hex()}")
    receiver.set_key(decrypted_session_key)

    print(f"\nOriginal message:\n{ORIGINAL_MESSAGE}")
    print(f"Original message in hex: {ORIGINAL_MESSAGE.encode('utf-8').hex()}")

    encrypted_message = sender.encrypt(ORIGINAL_MESSAGE)
    print(f"\nEncrypted message in hex: {encrypted_message.hex()}")

    decrypted_message = receiver.decrypt(encrypted_message)
    print(f"\nDecrypted message:\n{decrypted_message}")
    print(f"Decrypted message in hex: {decrypted_message.encode('utf-8').hex()}")


def main() -> None:
    """Main function to demonstrate crypto system functionality."""
    os.makedirs("./files", exist_ok=True)

    # demonstrate_aes_encryption()
    demonstrate_rsa_encryption()
    demonstrate_combined_encryption()


if __name__ == "__main__":
    main()