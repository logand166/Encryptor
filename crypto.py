import ast
import hashlib
import os
import secrets
import time

import serial
import serial.tools.list_ports


from PyQt5.QtCore import QThread, pyqtSignal, QMutex

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from utilities import generate_seed_phrase, log_activity

# Constants
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB


class CryptoManager:
    """
    CryptoManager

    A utility class for secure file encryption and decryption using AES-GCM with PBKDF2 key derivation.
    This class provides methods to encrypt and decrypt files with chunk-based processing, ensuring
    data integrity and confidentiality.

    Methods:
        derive_key(password: str, salt: bytes) -> bytes:
            Derives a cryptographic key from a password and salt using PBKDF2 with HMAC-SHA256.

        encrypt_file(src_path: str, dest_path: str, password: str, progress_callback=None) -> None:
            Encrypts a file securely using AES-GCM with a unique nonce per chunk. Supports progress tracking.

        decrypt_file(src_path: str, dest_path: str, password: str, progress_callback=None) -> None:
            Decrypts a file securely using AES-GCM with chunk validation. Supports progress tracking.

    Constants (not defined in this snippet but required):
        SALT_SIZE: int
            The size of the salt in bytes.
        KEY_SIZE: int
            The size of the derived key in bytes.
        ITERATIONS: int
            The number of iterations for PBKDF2 key derivation.
        CHUNK_SIZE: int
            The size of each chunk to be processed in bytes.
        NONCE_SIZE: int
            The size of the nonce in bytes.
        MAX_FILE_SIZE: int
            The maximum allowed file size for encryption in bytes.

    Exceptions:
        ValueError:
            Raised for invalid input parameters or failed operations.
        FileNotFoundError:
            Raised if the source file does not exist.
        RuntimeError:
            Raised for general encryption or decryption failures.
        InvalidTag:
            Raised during decryption if authentication fails (e.g., incorrect password or tampered file).
    """

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Secure key derivation with error handling
        Args:
            password (str): The password to derive the key from.
            salt (bytes): The salt used for key derivation.
        Returns:
            bytes: The derived key.
        """
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
        """Secure file encryption with chunk processing using unique nonce per chunk
        Args:
            src_path (str): The path to the source file to encrypt.
            dest_path (str): The path to save the encrypted file.
            password (str): The password for encryption.
            progress_callback (callable, optional): A callback function to report progress.
        Raises:
            FileNotFoundError: If the source file does not exist.
            ValueError: If the file is too large or if the password is invalid.
            RuntimeError: If encryption fails.
        """
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
        """Secure file decryption with chunk validation
        Args:
            src_path (str): The path to the encrypted file.
            dest_path (str): The path to save the decrypted file.
            password (str): The password for decryption.
            progress_callback (callable, optional): A callback function to report progress.
        Raises:
            FileNotFoundError: If the source file does not exist.
            ValueError: If the file structure is invalid or if the password is incorrect.
            RuntimeError: If decryption fails.
        """
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
    """
    CryptoWorker
    A worker thread for performing encryption and decryption operations.
    This class inherits from QThread and emits signals to update the progress,
    status, and completion of the operation.
    It handles the encryption and decryption of files using the CryptoManager class.
    It also manages the deletion of original files if requested.
    It provides a thread-safe way to perform long-running operations without blocking the GUI.
    It emits signals to update the progress, status, and completion of the operation.
    It also handles errors and exceptions that may occur during the operation.
    It provides a way to stop the operation gracefully.

    Args:
        QThread (QThread): Inherits from QThread to run the encryption/decryption in a separate thread.
    Attributes:
        operation (str): The operation to perform ("encrypt" or "decrypt").
        args (tuple): The arguments for the operation (source path, destination path, password).
        _is_running (bool): Flag to indicate if the thread is running.
        mutex (QMutex): Mutex for thread safety.
        delete_original (bool): Flag to indicate if the original file should be deleted after encryption/decryption.
    Signals:
        progress_updated (int): Signal emitted to update the progress of the operation.
        status_updated (str): Signal emitted to update the status of the operation.
        operation_completed (bool, str): Signal emitted when the operation is completed.
        error_occurred (str): Signal emitted when an error occurs during the operation.
        delete_original_requested (str): Signal emitted when a request to delete the original file is made.
    Methods:
        set_delete_original(delete: bool) -> None:
            Sets the flag to indicate if the original file should be deleted.
        stop() -> None:
            Stops the operation gracefully.
        run() -> None:
            Runs the encryption/decryption operation in a separate thread.
    """

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
        """Set the flag to indicate if the original file should be deleted."""
        self.delete_original = delete

    def stop(self):
        """Stop the operation gracefully."""
        with self.mutex:
            self._is_running = False

    def run(self):
        """Run the encryption/decryption operation in a separate thread."""
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


class DriveCrypto(QThread):
    """
    DriveCrypto
    A worker thread for performing encryption and decryption operations on a drive.
    This class inherits from QThread and emits signals to update the progress,
    status, and completion of the operation.
    It handles the encryption and decryption of files using the CryptoManager class.
    It also manages the deletion of original files if requested.
    It provides a thread-safe way to perform long-running operations without blocking the GUI.
    It emits signals to update the progress, status, and completion of the operation.
    It also handles errors and exceptions that may occur during the operation.

    Args:
        QThread (QThread): Inherits from QThread to run the encryption/decryption in a separate thread.
    Attributes:
        drive_path (str): The path to the drive to encrypt/decrypt.
        operation (str): The operation to perform ("encrypt" or "decrypt").
        password (str): The password for encryption/decryption.
        delete_original (bool): Flag to indicate if the original file should be deleted after encryption/decryption.
        directory_structure (dict): Dictionary to store the directory structure of the drive.
        file_structure (dict): Dictionary to store the file structure of the drive.
        _is_running (bool): Flag to indicate if the thread is running.
        mutex (QMutex): Mutex for thread safety.
    Signals:
        result_ready (int): Signal emitted when the operation is completed.
        progress_updated (int): Signal emitted to update the progress of the operation.
        status_updated (str): Signal emitted to update the status of the operation.
        operation_completed (bool, str): Signal emitted when the operation is completed.
        error_occurred (str): Signal emitted when an error occurs during the operation.
        delete_original_requested (str): Signal emitted when a request to delete the original file is made.
    Methods:
        stop() -> None:
            Stops the operation gracefully.
        get_directory_structure() -> None:
            Gets the directory structure of the drive.
        visualize_directory_structure_as_string() -> str:
            Visualizes the directory structure as a string.
        visualize_directory_structure_as_single_line_string() -> str:
            Visualizes the directory structure as a single line string.
        run() -> None:
            Runs the encryption/decryption operation in a separate thread.
    """

    result_ready = pyqtSignal(int)
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    operation_completed = pyqtSignal(bool, str)
    error_occurred = pyqtSignal(str)
    delete_original_requested = pyqtSignal(str)

    def __init__(
        self,
        drive_path: str,
        operation: str,
        password: str,
        delete_original: bool = False,
    ):
        super().__init__()
        if not os.path.isdir(drive_path):
            raise ValueError(f"Invalid drive path: {drive_path}")
        self.drive_path = drive_path
        self.operation = operation
        self.password = password
        self.delete_original = delete_original
        self.directory_structure = {}
        self.file_structure = {}
        self._is_running = True
        self.mutex = QMutex()
        self.get_directory_structure()

    def stop(self):
        """Stop the operation gracefully."""
        with self.mutex:
            self._is_running = False

    def get_directory_structure(self) -> None:
        """Get the directory structure of the drive."""
        for root, dirs, files in os.walk(self.drive_path):
            relative_path = os.path.relpath(root, self.drive_path)
            self.directory_structure[relative_path] = dirs
            for file in files:
                file_path = os.path.join(relative_path, file)
                self.file_structure[file_path] = os.path.getsize(
                    os.path.join(root, file)
                )

    def visualize_directory_structure_as_string(self) -> str:
        """Visualize the directory structure as a string"""
        structure_str = ""
        for dir_path, dirs in self.directory_structure.items():
            structure_str += f"Directory: {dir_path}\n"
            for file_path, size in self.file_structure.items():
                if os.path.dirname(file_path) == dir_path:
                    structure_str += (
                        f"  File: {os.path.basename(file_path)} - Size: {size} bytes\n"
                    )
        return structure_str

    def visualize_directory_structure_as_single_line_string(self) -> str:
        """Visualize the directory structure as a string"""
        structure_str = ""
        for dir_path, dirs in self.directory_structure.items():
            structure_str += f"Directory: {dir_path};"
            for file_path, size in self.file_structure.items():
                if os.path.dirname(file_path) == dir_path:
                    structure_str += (
                        f"  File: {os.path.basename(file_path)} - Size: {size} bytes;"
                    )
        return structure_str

    def run(self):
        """Run the encryption/decryption operation in a separate thread."""
        try:
            print("Starting encryption/decryption process...")
            if not self._is_running:
                print("Process stopped by user.")
                return

            print("Directory structure:")
            log_activity(
                "directory-structure",
                self.drive_path,
                self.visualize_directory_structure_as_single_line_string(),
            )
            if self.operation == "encrypt":
                print("Encrypting files...")
                print(self.file_structure)
                for file_path, size in self.file_structure.items():
                    print(f"Processing file: {file_path} - Size: {size} bytes")
                    if (
                        not file_path.endswith(".enc")
                        and not file_path.endswith(".key")
                        and not file_path.endswith(".log")
                    ):
                        src_path = os.path.join(self.drive_path, file_path)
                        dest_path = os.path.join(self.drive_path, f"{file_path}.enc")
                        self.status_updated.emit(f"Encrypting {file_path}")
                        print(f"Encrypting {src_path} to {dest_path}")
                        CryptoManager.encrypt_file(
                            src_path,
                            dest_path,
                            self.password,
                            progress_callback=self.progress_updated.emit,
                        )
                        if self.delete_original:
                            try:
                                os.remove(src_path)
                                self.delete_original_requested.emit(src_path)
                            except Exception as e:
                                self.error_occurred.emit(
                                    f"Failed to delete {src_path}: {str(e)}"
                                )

            elif self.operation == "decrypt":
                for file_path, size in self.file_structure.items():
                    if (
                        file_path.endswith(".enc")
                        and not file_path.endswith(".key")
                        and not file_path.endswith(".log")
                    ):
                        src_path = os.path.join(self.drive_path, file_path)
                        dest_path = os.path.join(self.drive_path, file_path[:-4])
                        self.status_updated.emit(f"Decrypting {file_path}")
                        CryptoManager.decrypt_file(
                            src_path,
                            dest_path,
                            self.password,
                            progress_callback=self.progress_updated.emit,
                        )
                        if self.delete_original:
                            try:
                                os.remove(src_path)
                                self.delete_original_requested.emit(src_path)
                            except Exception as e:
                                self.error_occurred.emit(
                                    f"Failed to delete {src_path}: {str(e)}"
                                )

            self.operation_completed.emit(True, "Operation completed successfully")
            self.result_ready.emit(True)

        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
            self.operation_completed.emit(False, str(e))
            self.result_ready.emit(False)


class PasswordRecovery:
    def __init__(self, path: str, key: str = None):
        if not os.path.isdir(path):
            path = os.path.dirname(path)
        self.drive_path: str = path
        self.key: str = key
        self.recovery_key: str = None
        self.strategy = None

    def setup_key_recovery(
        self, strategy: str, recovery_key: str, additional_info: dict = {}
    ) -> None:
        """
        Setup key recovery strategy
        Args:
            strategy (str): The recovery strategy to use (e.g., "seed_phrase", "security_questions
            recovery_key (str): The recovery key to use.
            additional_info (dict): Additional information for the recovery strategy.
        """

        self.strategy = strategy

        if self.strategy == "seed_phrase":
            self.recovery_key = recovery_key
        elif self.strategy == "security_questions":
            self.recovery_key = recovery_key
            questions_path = os.path.join(self.drive_path, "security.questions")
            with open(questions_path, "w") as f:
                for question in additional_info.items():
                    f.write(f"{question}\n")
            print(f"Security questions saved to {questions_path}")
        elif self.strategy == "hardware_token":
            # self.recovery_keys = [seed_phrase for _, seed_phrase in additional_info]
            self.recovery_key = recovery_key

    def encrypt_recovery_key(self) -> None:
        """
        Encrypt the recovery key
        """
        if not self.recovery_key:
            raise ValueError("Recovery key not set")

        # Encrypt the recovery key with the password
        salt = secrets.token_bytes(SALT_SIZE)
        key = CryptoManager.derive_key(self.recovery_key, salt)

        # Encrypt the recovery key
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        encrypted_key = aesgcm.encrypt(nonce, self.key.encode(), None)

        # Save the encrypted key to a file
        encrypted_key_path = os.path.join(self.drive_path, "encrypted.key")
        with open(encrypted_key_path, "wb") as f:
            f.write(salt + nonce + encrypted_key)
        print(f"Encrypted recovery key saved to {encrypted_key_path}")
        return encrypted_key_path

    def decrypt_recovery_key(self) -> str:
        """
        Decrypt the recovery key
        """
        # if self.strategy == "hardware_token":
        #     return self.decrypt_against_multiple()

        encrypted_key_path = os.path.join(self.drive_path, "encrypted.key")
        if not os.path.exists(encrypted_key_path):
            raise FileNotFoundError(f"Encrypted key not found: {encrypted_key_path}")

        with open(encrypted_key_path, "rb") as f:
            data = f.read()
            salt = data[:SALT_SIZE]
            nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
            encrypted_key = data[SALT_SIZE + NONCE_SIZE :]

        # Derive the key from the password
        key = CryptoManager.derive_key(self.recovery_key, salt)

        # Decrypt the recovery key
        aesgcm = AESGCM(key)
        decrypted_key = aesgcm.decrypt(nonce, encrypted_key, None)
        print(f"Decrypted recovery key: {decrypted_key.decode()}")
        return decrypted_key.decode()

    def decrypt_against_multiple(self):
        """
        Decrypt the recovery key against multiple hardware tokens
        """
        for recovery_key in self.recovery_keys:
            try:
                encrypted_key_path = os.path.join(self.drive_path, "encrypted.key")
                if not os.path.exists(encrypted_key_path):
                    raise FileNotFoundError(
                        f"Encrypted key not found: {encrypted_key_path}"
                    )

                with open(encrypted_key_path, "rb") as f:
                    data = f.read()
                    salt = data[:SALT_SIZE]
                    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
                    encrypted_key = data[SALT_SIZE + NONCE_SIZE :]

                if self.strategy == "hardware_token":
                    self.decrypt_against_multiple()

                # Derive the key from the password
                key = CryptoManager.derive_key(self.recovery_key, salt)

                # Decrypt the recovery key
                aesgcm = AESGCM(key)
                decrypted_key = aesgcm.decrypt(nonce, encrypted_key, None)
                print(f"Decrypted recovery key: {decrypted_key.decode()}")
                return decrypted_key.decode()
            except Exception as e:
                print(e)
        return None


class HardwareToken:
    """
    HardwareToken
    A class for managing a hardware token (e.g., Pico Key) for secure storage of seed phrases.
    This class provides methods to connect to the token, check available space,
    write and retrieve seed phrases, and clear the token's data.
    It uses the serial library to communicate with the token over a serial port.
    It provides a way to securely store and retrieve seed phrases using the hardware token.
    """
    def __init__(self):
        self.ser = None
        self.token_port = None
        self.token_name = "No - Token"

    def find_token_port(self):
        """Find the token's serial port."""
        ports = serial.tools.list_ports.comports()
        for port in ports:
            if (
                "Board in FS mode" in port.description
                or "MicroPython" in port.description
                or "Board CDC" in port.description
            ):
                return port.device
        raise Exception("Token not found - is it plugged in?")

    def connect(self):
        """Connect to the token."""
        try:
            self.token_port = self.find_token_port()
            self.ser = serial.Serial(self.token_port, baudrate=115200, timeout=4)
            print(f"Connected to token on {self.token_port}")

            # Send commands and receive responses
            self.ser.write(b"search:\n")
            response: str = self.ser.readline().decode().strip()
            if response.find("Key") == -1:
                raise Exception("Valid Hardware Token not found - is it plugged in?")
            else:
                self.token_name = response
        except Exception as e:
            print("Error:", e)
            self.disconnect()
            raise

    def has_space(self) -> bool:
        """Check if the hardware token has enough space for storing data."""
        if not self.ser or not self.ser.is_open:
            raise Exception("Token is not connected")
        self.ser.write(b"check:space\n")
        response = self.ser.readline().decode().strip()
        if response == "OK":
            return True
        elif response == "NO_SPACE":
            return False
        else:
            raise Exception(f"Unexpected response from token: {response}")

    def get_space(self) -> int:
        """Retrieve the available space on the hardware token."""
        if not self.ser or not self.ser.is_open:
            raise Exception("Token is not connected")
        self.ser.write(b"get:space\n")
        response = self.ser.readline().decode().strip()
        if response.startswith("SPACE:"):
            try:
                return int(response.split("SPACE:")[1])
            except ValueError:
                raise Exception(f"Invalid space value received from token: {response}")
        else:
            raise Exception(f"Failed to retrieve space from token: {response}")

    def write_seed_phrase_to_token(self, seed_phrase: str) -> None:
        """Write a seed phrase to the hardware token."""
        if not self.ser or not self.ser.is_open:
            raise Exception("Token is not connected")
        if not self.has_space():
            raise Exception("Token does not have enough space to store the seed phrase")
        self.ser.write(f"add:{seed_phrase}\n".encode())
        response = self.ser.readline().decode().strip()
        if response != "OK":
            raise Exception(f"Failed to write seed phrase to token: {response}")

    def get_seed_phrase_from_token(self) -> dict:
        """Retrieve the seed phrase from the hardware token."""
        if not self.ser or not self.ser.is_open:
            raise Exception("Token is not connected")
        self.ser.write(b"get\n")
        response = self.ser.readline().decode().strip()
        if response.startswith("SEED:"):
            list_seed_phrases = ast.literal_eval(response.split("SEED:")[1])
            dict_seed_phrases = {
                f"Seed {i+1}": phrase for i, phrase in enumerate(list_seed_phrases)
            }
            return dict_seed_phrases
        else:
            raise Exception(f"Failed to retrieve seed phrase from token: {response}")

    def empty_token(self):
        """Erase all data stored on the hardware token."""
        if not self.ser or not self.ser.is_open:
            raise Exception("Token is not connected")
        self.ser.write(b"clear\n")
        response = self.ser.readline().decode().strip()
        if response != "OK":
            raise Exception(f"Failed to clear token: {response}")
        print("Token successfully cleared")

    def disconnect(self):
        """Disconnect from the token."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            print(f"Disconnected from {self.token_name}")


if __name__ == "__main__":
    token = HardwareToken()
    try:
        token.connect()
        token.empty_token()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        token.disconnect()
