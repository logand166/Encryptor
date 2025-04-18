#!/usr/bin/env python3

"""
Secure File Encryptor/Decryptor
- Uses AES-GCM with unique nonce per chunk
- Includes chunk sequence validation
- Password strength checking
- Progress reporting
- Secure file handling
"""

import os
import sys
import secrets
import re
from functools import partial
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget,
                             QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
                             QLabel, QFileDialog, QTextEdit, QProgressBar, QMessageBox, QCheckBox)
from PyQt5.QtCore import QThread, pyqtSignal, QMutex, QCoreApplication, Qt
from PyQt5.QtGui import QIcon, QColor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from qt_material import apply_stylesheet

# Constants
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB

class PasswordStrengthMeter:
    @staticmethod
    def calculate_strength(password):
        if not password:
            return 0
        
        strength = 0
        
        # Length check
        length = len(password)
        if length >= 8:
            strength += 1
        if length >= 12:
            strength += 1
        if length >= 16:
            strength += 1
            
        # Character diversity
        if re.search(r'[A-Z]', password):
            strength += 1
        if re.search(r'[a-z]', password):
            strength += 1
        if re.search(r'[0-9]', password):
            strength += 1
        if re.search(r'[^A-Za-z0-9]', password):
            strength += 1
            
        # Normalize to 0-100 range
        max_possible = 7  # 3 for length + 4 for diversity
        return int((strength / max_possible) * 100)
    
    @staticmethod
    def get_strength_color(strength):
        if strength < 30:
            return QColor(255, 0, 0)  # Red
        elif strength < 70:
            return QColor(255, 255, 0)  # Yellow
        else:
            return QColor(0, 255, 0)  # Green

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
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")

    @staticmethod
    def encrypt_file(src_path: str, dest_path: str, password: str, progress_callback=None) -> None:
        """Secure file encryption with chunk processing using unique nonce per chunk"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        salt = secrets.token_bytes(SALT_SIZE)
        key = CryptoManager.derive_key(password, salt)

        file_size = os.path.getsize(src_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large ({file_size/1024/1024:.2f}MB > {MAX_FILE_SIZE/1024/1024}MB")

        try:
            with open(src_path, 'rb') as fin, open(dest_path, 'wb') as fout:
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
    def decrypt_file(src_path: str, dest_path: str, password: str, progress_callback=None) -> None:
        """Secure file decryption with chunk validation"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        try:
            with open(src_path, 'rb') as fin:
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
                
                with open(dest_path, 'wb') as fout:
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
                        additional_data = f"chunk_{chunk_num}_of_{total_chunks}".encode()
                        
                        try:
                            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, additional_data)
                            fout.write(decrypted_chunk)
                        except InvalidTag:
                            raise ValueError(f"Chunk {chunk_num} authentication failed - possible tampering")
                        
                        bytes_processed += len(encrypted_chunk) + NONCE_SIZE
                        if progress_callback:
                            progress = int((bytes_processed / (remaining_size + SALT_SIZE)) * 100)
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

            if self.operation == 'encrypt':
                src_path, dest_path, password = self.args
                CryptoManager.encrypt_file(
                    src_path, dest_path, password,
                    progress_callback=self.progress_updated.emit
                )
                
                if self.delete_original:
                    try:
                        os.remove(src_path)
                        self.delete_original_requested.emit(src_path)
                    except Exception as e:
                        self.error_occurred.emit(f"Failed to delete original file: {str(e)}")

            elif self.operation == 'decrypt':
                src_path, dest_path, password = self.args
                CryptoManager.decrypt_file(
                    src_path, dest_path, password,
                    progress_callback=self.progress_updated.emit
                )
                
                if self.delete_original:
                    try:
                        os.remove(src_path)
                        self.delete_original_requested.emit(src_path)
                    except Exception as e:
                        self.error_occurred.emit(f"Failed to delete original file: {str(e)}")

            self.operation_completed.emit(True, "Operation completed successfully")

        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
            self.operation_completed.emit(False, str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Secure File Cryptor")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(self.load_icon())
        
        self.setWindowFlags(
            self.windowFlags() | 
            Qt.WindowSystemMenuHint |
            Qt.WindowMinMaxButtonsHint |
            Qt.WindowCloseButtonHint
        )
        
        self.init_ui()
        self.worker = None
        self.current_operation = None

    def load_icon(self):
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")
        
        icon_path = os.path.join(base_path, 'main_icon.ico')
        
        if os.path.exists(icon_path):
            return QIcon(icon_path)
        else:
            return QIcon()

    def init_ui(self):
        self.tabs = QTabWidget()
        self.encrypt_tab = self.create_encrypt_tab()
        self.decrypt_tab = self.create_decrypt_tab()
        self.tabs.addTab(self.encrypt_tab, "Encrypt")
        self.tabs.addTab(self.decrypt_tab, "Decrypt")
        self.setCentralWidget(self.tabs)

    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # File selection
        self.encrypt_file_line = QLineEdit()
        self.encrypt_file_btn = QPushButton("Select File")
        self.encrypt_file_btn.clicked.connect(partial(self.select_files, self.encrypt_file_line, False))
        
        # Output path
        self.encrypt_output_line = QLineEdit()
        self.encrypt_output_btn = QPushButton("Select Output Path")
        self.encrypt_output_btn.clicked.connect(partial(self.select_output_file, self.encrypt_output_line, "encrypted"))
        
        # Password fields
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        self.encrypt_password.textChanged.connect(self.update_password_strength)
        
        self.encrypt_confirm = QLineEdit()
        self.encrypt_confirm.setEchoMode(QLineEdit.Password)
        
        # Show password checkbox
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        
        # Delete original file checkbox
        self.delete_original_checkbox = QCheckBox("Delete original file after encryption")
        
        # Password strength meter
        self.password_strength_label = QLabel("Password Strength:")
        self.password_strength_meter = QProgressBar()
        self.password_strength_meter.setRange(0, 100)
        self.password_strength_meter.setTextVisible(False)
        
        # Progress
        self.encrypt_progress = QProgressBar()
        self.encrypt_log = QTextEdit()
        self.encrypt_log.setReadOnly(True)

        # Buttons
        self.encrypt_btn = QPushButton("Start Encryption")
        self.encrypt_btn.clicked.connect(partial(self.start_operation, 'encrypt'))

        # Layout organization
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.encrypt_file_line)
        file_layout.addWidget(self.encrypt_file_btn)

        output_layout = QHBoxLayout()
        output_layout.addWidget(self.encrypt_output_line)
        output_layout.addWidget(self.encrypt_output_btn)

        password_layout = QVBoxLayout()
        
        password_row1 = QHBoxLayout()
        password_row1.addWidget(QLabel("Password:"))
        password_row1.addWidget(self.encrypt_password)
        password_row1.addWidget(QLabel("Confirm:"))
        password_row1.addWidget(self.encrypt_confirm)
        
        password_row2 = QHBoxLayout()
        password_row2.addWidget(self.show_password_checkbox)
        password_row2.addWidget(self.delete_original_checkbox)
        
        password_layout.addLayout(password_row1)
        password_layout.addLayout(password_row2)
        
        strength_layout = QHBoxLayout()
        strength_layout.addWidget(self.password_strength_label)
        strength_layout.addWidget(self.password_strength_meter)
        password_layout.addLayout(strength_layout)

        layout.addLayout(file_layout)
        layout.addLayout(output_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.encrypt_progress)
        layout.addWidget(self.encrypt_log)
        
        tab.setLayout(layout)
        return tab

    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # File selection
        self.decrypt_file_line = QLineEdit()
        self.decrypt_file_btn = QPushButton("Select File")
        self.decrypt_file_btn.clicked.connect(partial(self.select_files, self.decrypt_file_line, False))
        
        # Output path
        self.decrypt_output_line = QLineEdit()
        self.decrypt_output_btn = QPushButton("Select Output Path")
        self.decrypt_output_btn.clicked.connect(partial(self.select_output_file, self.decrypt_output_line, "decrypted"))
        
        # Password field
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        
        # Show password checkbox
        self.show_password_checkbox_decrypt = QCheckBox("Show Password")
        self.show_password_checkbox_decrypt.stateChanged.connect(self.toggle_password_visibility_decrypt)
        
        # Delete original file checkbox
        self.delete_original_checkbox_decrypt = QCheckBox("Delete encrypted file after decryption")
        
        # Progress
        self.decrypt_progress = QProgressBar()
        self.decrypt_log = QTextEdit()
        self.decrypt_log.setReadOnly(True)

        # Buttons
        self.decrypt_btn = QPushButton("Start Decryption")
        self.decrypt_btn.clicked.connect(partial(self.start_operation, 'decrypt'))

        # Layout organization
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.decrypt_file_line)
        file_layout.addWidget(self.decrypt_file_btn)

        output_layout = QHBoxLayout()
        output_layout.addWidget(self.decrypt_output_line)
        output_layout.addWidget(self.decrypt_output_btn)

        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        password_layout.addWidget(self.decrypt_password)
        password_layout.addWidget(self.show_password_checkbox_decrypt)
        password_layout.addWidget(self.delete_original_checkbox_decrypt)

        layout.addLayout(file_layout)
        layout.addLayout(output_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.decrypt_progress)
        layout.addWidget(self.decrypt_log)
        
        tab.setLayout(layout)
        return tab

    def toggle_password_visibility(self, state):
        if state == Qt.Checked:
            self.encrypt_password.setEchoMode(QLineEdit.Normal)
            self.encrypt_confirm.setEchoMode(QLineEdit.Normal)
        else:
            self.encrypt_password.setEchoMode(QLineEdit.Password)
            self.encrypt_confirm.setEchoMode(QLineEdit.Password)
    
    def toggle_password_visibility_decrypt(self, state):
        if state == Qt.Checked:
            self.decrypt_password.setEchoMode(QLineEdit.Normal)
        else:
            self.decrypt_password.setEchoMode(QLineEdit.Password)
    
    def update_password_strength(self):
        password = self.encrypt_password.text()
        strength = PasswordStrengthMeter.calculate_strength(password)
        color = PasswordStrengthMeter.get_strength_color(strength)
        
        self.password_strength_meter.setValue(strength)
        self.password_strength_meter.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color.name()}; }}"
        )

    def select_files(self, line_edit, multi):
        if multi:
            files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
            if files:
                line_edit.setText(";".join(files))
        else:
            file, _ = QFileDialog.getOpenFileName(self, "Select File")
            if file:
                line_edit.setText(file)

    def select_output_file(self, line_edit, default_suffix):
        file, _ = QFileDialog.getSaveFileName(
            self, 
            "Select Output File",
            "",
            f"Encrypted Files (*.{default_suffix})"
        )
        if file:
            line_edit.setText(file)

    def start_operation(self, operation):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Warning", "Another operation is in progress")
            return

        try:
            if operation == 'encrypt':
                file_path = self.encrypt_file_line.text()
                output_path = self.encrypt_output_line.text()
                password = self.encrypt_password.text()
                confirm = self.encrypt_confirm.text()

                if not file_path:
                    raise ValueError("Please select a file to encrypt")
                if not output_path:
                    raise ValueError("Please select output path")
                if password != confirm:
                    raise ValueError("Passwords do not match")
                if not password:
                    raise ValueError("Password cannot be empty")

                # Add .encrypted extension if not present
                if not output_path.endswith('.encrypted'):
                    output_path += '.encrypted'

                self.worker = CryptoWorker(operation, file_path, output_path, password)
                self.worker.set_delete_original(self.delete_original_checkbox.isChecked())
                self.encrypt_log.append(f"Starting encryption of {file_path}...")
                
            elif operation == 'decrypt':
                file_path = self.decrypt_file_line.text()
                output_path = self.decrypt_output_line.text()
                password = self.decrypt_password.text()

                if not file_path:
                    raise ValueError("Please select a file to decrypt")
                if not output_path:
                    raise ValueError("Please select output path")
                if not password:
                    raise ValueError("Password cannot be empty")

                self.worker = CryptoWorker(operation, file_path, output_path, password)
                self.worker.set_delete_original(self.delete_original_checkbox_decrypt.isChecked())
                self.decrypt_log.append(f"Starting decryption of {file_path}...")

            self.setup_worker_connections(operation)
            self.worker.start()

        except Exception as e:
            self.show_error(str(e))

    def setup_worker_connections(self, operation):
        if operation == 'encrypt':
            log = self.encrypt_log
            progress = self.encrypt_progress
            btn = self.encrypt_btn
        else:
            log = self.decrypt_log
            progress = self.decrypt_progress
            btn = self.decrypt_btn

        btn.setEnabled(False)
        progress.setValue(0)
        self.worker.progress_updated.connect(progress.setValue)
        self.worker.status_updated.connect(log.append)
        self.worker.operation_completed.connect(
            lambda success, msg: self.on_operation_complete(success, msg, btn, log)
        )
        self.worker.error_occurred.connect(
            lambda err: self.show_error(err, log)
        )
        self.worker.delete_original_requested.connect(
            lambda path: log.append(f"Original file deleted: {path}"))

    def on_operation_complete(self, success, message, btn, log):
        btn.setEnabled(True)
        if success:
            log.append("Operation completed successfully")
            QMessageBox.information(self, "Success", message)
        else:
            log.append(f"Operation failed: {message}")
            QMessageBox.critical(self, "Error", message)

    def show_error(self, message, log=None):
        if log:
            log.append(f"Error: {message}")
        QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)  # Wait up to 2 seconds for clean exit
        event.accept()

if __name__ == "__main__":
    QCoreApplication.setAttribute(Qt.AA_DisableWindowContextHelpButton)
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_teal.xml')
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
