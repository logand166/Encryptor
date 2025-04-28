import os
import secrets
from PyQt5.QtCore import QThread, pyqtSignal, QMutex
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Constants
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB


class CryptoManager:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Secure key derivation with error handling"""
        if not password:
            raise ValueError("Password cannot be empty")
        if len(salt) != SALT_SIZE:
            raise ValueError("Invalid salt size")

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_SIZE,
                salt=salt,
                iterations=ITERATIONS,
            )
            return kdf.derive(password.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")

    @staticmethod
    def encrypt_file(
        src_path: str, dest_path: str, password: str, progress_callback=None
    ) -> None:
        """Secure file encryption with chunk processing using unique nonce per chunk"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        salt = secrets.token_bytes(SALT_SIZE)
        key = CryptoManager.derive_key(password, salt)

        file_size = os.path.getsize(src_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(
                f"File too large ({file_size/1024/1024:.2f}MB > {MAX_FILE_SIZE/1024/1024}MB"
            )

        try:
            with open(src_path, "rb") as fin, open(dest_path, "wb") as fout:
                # Write salt first
                fout.write(salt)

                # Calculate total chunks
                total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                bytes_processed = 0

                for chunk_num in range(total_chunks):
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Generate unique nonce for each chunk
                    nonce = secrets.token_bytes(NONCE_SIZE)
                    aesgcm = AESGCM(key)

                    # Include chunk number in additional data to prevent reordering
                    additional_data = f"chunk_{chunk_num}_of_{total_chunks}".encode()

                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, additional_data)

                    # Write nonce followed by encrypted chunk
                    fout.write(nonce + encrypted_chunk)

                    bytes_processed += len(chunk)
                    if progress_callback:
                        progress = int((bytes_processed / file_size) * 100)
                        progress_callback(progress)

        except Exception as e:
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except:
                    pass
            raise RuntimeError(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt_file(
        src_path: str, dest_path: str, password: str, progress_callback=None
    ) -> None:
        """Secure file decryption with chunk validation"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        try:
            with open(src_path, "rb") as fin:
                # Read salt
                salt = fin.read(SALT_SIZE)
                if len(salt) != SALT_SIZE:
                    raise ValueError("Invalid salt size")

                key = CryptoManager.derive_key(password, salt)

                # Get remaining file size
                remaining_size = os.path.getsize(src_path) - SALT_SIZE
                if remaining_size <= 0:
                    raise ValueError("Invalid file structure")

                # Calculate total chunks
                total_chunks = 0
                while True:
                    # Read nonce
                    nonce = fin.read(NONCE_SIZE)
                    if len(nonce) == 0:
                        break  # End of file
                    if len(nonce) != NONCE_SIZE:
                        raise ValueError("Invalid nonce size")

                    # Read encrypted chunk (data + tag)
                    encrypted_chunk = fin.read(CHUNK_SIZE + 16)
                    if not encrypted_chunk:
                        break

                    total_chunks += 1

                # Reset file pointer
                fin.seek(SALT_SIZE)
                bytes_processed = SALT_SIZE

                with open(dest_path, "wb") as fout:
                    for chunk_num in range(total_chunks):
                        # Read nonce
                        nonce = fin.read(NONCE_SIZE)
                        if len(nonce) != NONCE_SIZE:
                            raise ValueError("Invalid nonce size")

                        # Read encrypted chunk
                        encrypted_chunk = fin.read(CHUNK_SIZE + 16)
                        if not encrypted_chunk:
                            break

                        aesgcm = AESGCM(key)
                        additional_data = (
                            f"chunk_{chunk_num}_of_{total_chunks}".encode()
                        )

                        try:
                            decrypted_chunk = aesgcm.decrypt(
                                nonce, encrypted_chunk, additional_data
                            )
                            fout.write(decrypted_chunk)
                        except InvalidTag:
                            raise ValueError(
                                f"Chunk {chunk_num} authentication failed - possible tampering"
                            )

                        bytes_processed += len(encrypted_chunk) + NONCE_SIZE
                        if progress_callback:
                            progress = int(
                                (bytes_processed / (remaining_size + SALT_SIZE)) * 100
                            )
                            progress_callback(progress)

        except InvalidTag:
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except:
                    pass
            raise ValueError("Incorrect password or corrupted file")
        except Exception as e:
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except:
                    pass
            raise RuntimeError(f"Decryption failed: {str(e)}")


class CryptoWorker(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    operation_completed = pyqtSignal(bool, str)
    error_occurred = pyqtSignal(str)
    delete_original_requested = pyqtSignal(str)

    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
        self._is_running = True
        self.mutex = QMutex()
        self.delete_original = False

    def set_delete_original(self, delete):
        self.delete_original = delete

    def stop(self):
        with self.mutex:
            self._is_running = False

    def run(self):
        try:
            if not self._is_running:
                return

            if self.operation == "encrypt":
                src_path, dest_path, password = self.args
                CryptoManager.encrypt_file(
                    src_path,
                    dest_path,
                    password,
                    progress_callback=self.progress_updated.emit,
                )

                if self.delete_original:
                    try:
                        os.remove(src_path)
                        self.delete_original_requested.emit(src_path)
                    except Exception as e:
                        self.error_occurred.emit(
                            f"Failed to delete original file: {str(e)}"
                        )

            elif self.operation == "decrypt":
                src_path, dest_path, password = self.args
                CryptoManager.decrypt_file(
                    src_path,
                    dest_path,
                    password,
                    progress_callback=self.progress_updated.emit,
                )

                if self.delete_original:
                    try:
                        os.remove(src_path)
                        self.delete_original_requested.emit(src_path)
                    except Exception as e:
                        self.error_occurred.emit(
                            f"Failed to delete original file: {str(e)}"
                        )

            self.operation_completed.emit(True, "Operation completed successfully")

        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
            self.operation_completed.emit(False, str(e))


class DriveCrypto:
    def __init__(self, drive_path):
        self.drive_path = drive_path
        self.crypto_worker = None
        self.directory_structure = {}
        self.file_structure = {}
        self.get_directory_structure()

    def get_directory_structure(self):
        """Get the directory structure of the drive"""
        for root, dirs, files in os.walk(self.drive_path):
            relative_path = os.path.relpath(root, self.drive_path)
            self.directory_structure[relative_path] = dirs
            for file in files:
                file_path = os.path.join(relative_path, file)
                self.file_structure[file_path] = os.path.getsize(
                    os.path.join(root, file)
                )
        return self.directory_structure, self.file_structure

    def get_file_size(self, file_path):
        """Get the size of a file"""
        if file_path in self.file_structure:
            return self.file_structure[file_path]
        else:
            raise FileNotFoundError(f"File not found: {file_path}")

    def encrypt(self, password):
        """
        Encrypt the files in the drive while preserving the directory structure
        and then also delete the original files
        """

        for file_path, size in self.file_structure.items():
            if not file_path.endswith(".enc"):
                print(f"Encrypting {file_path}")
                src_path = os.path.join(self.drive_path, file_path)
                dest_path = os.path.join(self.drive_path, f"{file_path}.enc")
                self.crypto_worker = CryptoWorker(
                    "encrypt", src_path, dest_path, password
                )
                self.crypto_worker.set_delete_original(True)
                self.crypto_worker.run()
                print(f"Encrypted {file_path} to {dest_path}")

    def decrypt(self, password):
        """
        Decrypt the files in the drive while preserving the directory structure
        and then also delete the original files
        """

        for file_path, size in self.file_structure.items():
            if file_path.endswith(".enc"):
                print(f"Decrypting {file_path}")
                src_path = os.path.join(self.drive_path, file_path)
                dest_path = os.path.join(self.drive_path, file_path[:-4])
                self.crypto_worker = CryptoWorker(
                    "decrypt", src_path, dest_path, password
                )
                self.crypto_worker.set_delete_original(True)
                self.crypto_worker.run()
                print(f"Decrypted {file_path} to {dest_path}")

    def visualize_directory_structure(self):
        """Visualize the directory structure"""
        for dir_path, dirs in self.directory_structure.items():
            print(f"Directory: {dir_path}")
            for file_path, size in self.file_structure.items():
                if os.path.dirname(file_path) == dir_path:
                    print(f"  File: {os.path.basename(file_path)} - Size: {size} bytes")
        return self.directory_structure, self.file_structure


if __name__ == "__main__":
    # Example usage
    # drive is a usb called Test Drive
    drive_path = "/media/lenovo/Test Drive"
    if not os.path.exists(drive_path):
        print(f"Drive not found: {drive_path}")
        exit(1)
    print(f"Drive path: {drive_path}")
    drive_crypto = DriveCrypto(drive_path)
    
    # drive_crypto.visualize_directory_structure()
    # drive_crypto.encrypt("testpassword")
    drive_crypto.decrypt("testpassword")
    drive_crypto.visualize_directory_structure()
