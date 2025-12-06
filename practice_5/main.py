from Crypto.Cipher import AES
from Crypto import Random
import os
from typing import Optional, Union


class CryptoSystem:
    """Base class for encrypting and decrypting data using AES."""

    def __init__(self) -> None:
        """Initialize crypto system with CFB mode by default."""
        self.__sessionkey: Optional[bytes] = None
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
    pass


class Receiver(CryptoSystem):
    """Message receiver class."""
    pass


def demonstrate_encryption(sender: Sender, receiver: Receiver,
                          original_message: str, mode_name: str = "CFB") -> None:
    """Demonstrate encryption and decryption with detailed output."""
    print(f"\nDemonstration in {mode_name} mode:")

    print(f"\nOriginal message:\n{original_message}")
    print(f"Original message in bytes: {original_message.encode('utf-8')}")
    print(f"Original message in hex: {original_message.encode('utf-8').hex()}")

    encrypted = sender.encrypt(original_message)
    print(f"\nEncrypted message in hex: {encrypted.hex()}")

    decrypted = receiver.decrypt(encrypted)
    print(f"\nDecrypted message:\n{decrypted}")
    print(f"Decrypted message in bytes: {decrypted.encode('utf-8')}")
    print(f"Decrypted message in hex: {decrypted.encode('utf-8').hex()}")


def main() -> None:
    """Main function to demonstrate crypto system functionality."""
    sender = Sender()
    receiver = Receiver()

    key = sender.generate_key(256)
    print(f"Session key: {key.hex()}")

    receiver.set_key(sender.get_key())

    os.makedirs("./files", exist_ok=True)

    sender.save_key_to_file(os.path.join('files', 'session_key.bin'))

    original_message = "Lopatin Danylo\nGroup 538"

    demonstrate_encryption(sender, receiver, original_message, "CFB")

    with open(os.path.join('files', 'original_message.txt'), 'w', encoding='utf-8') as f:
        f.write(original_message)

    sender.encrypt_file(os.path.join('files', 'original_message.txt'), os.path.join('files', 'encrypted_message.bin'))
    receiver.decrypt_file(os.path.join('files', 'encrypted_message.bin'),
                          os.path.join('files', 'decrypted_message.txt'))

    sender.set_mode(AES.MODE_CBC)
    receiver.set_mode(AES.MODE_CBC)
    demonstrate_encryption(sender, receiver, original_message, "CBC")


if __name__ == "__main__":
    main()
