#!/usr/bin/env python3
"""
Secure File Encryptor/Decryptor - Fixed Version
"""

import os
import sys
import secrets
from functools import partial
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget,
                             QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
                             QLabel, QFileDialog, QTextEdit, QProgressBar, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, QMutex, QCoreApplication, Qt
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
        """Safe file encryption with chunk processing"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        salt = secrets.token_bytes(SALT_SIZE)
        key = CryptoManager.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_SIZE)

        file_size = os.path.getsize(src_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large ({file_size/1024/1024:.2f}MB > {MAX_FILE_SIZE/1024/1024}MB)")

        try:
            with open(src_path, 'rb') as fin, open(dest_path, 'wb') as fout:
                fout.write(salt + nonce)
                total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                bytes_processed = 0

                for chunk_num in range(total_chunks):
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    fout.write(encrypted_chunk)
                    
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
        """Safe file decryption with chunk processing"""
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        try:
            with open(src_path, 'rb') as fin:
                salt = fin.read(SALT_SIZE)
                nonce = fin.read(NONCE_SIZE)
                
                if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
                    raise ValueError("Invalid file format - missing salt or nonce")

                key = CryptoManager.derive_key(password, salt)
                aesgcm = AESGCM(key)

                file_size = os.path.getsize(src_path) - SALT_SIZE - NONCE_SIZE
                if file_size <= 0:
                    raise ValueError("Invalid file structure")

                with open(dest_path, 'wb') as fout:
                    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                    bytes_processed = 0

                    for _ in range(total_chunks):
                        chunk = fin.read(CHUNK_SIZE + 16)  # Account for GCM tag
                        if not chunk:
                            break

                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        fout.write(decrypted_chunk)

                        bytes_processed += len(chunk)
                        if progress_callback:
                            progress = int((bytes_processed / file_size) * 100)
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

    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
        self._is_running = True
        self.mutex = QMutex()

    def stop(self):
        with self.mutex:
            self._is_running = False

    def run(self):
        try:
            if not self._is_running:
                return

            if self.operation == 'encrypt':
                CryptoManager.encrypt_file(
                    *self.args,
                    progress_callback=self.progress_updated.emit
                )
            elif self.operation == 'decrypt':
                CryptoManager.decrypt_file(
                    *self.args,
                    progress_callback=self.progress_updated.emit
                )

            self.operation_completed.emit(True, "Operation completed successfully")

        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
            self.operation_completed.emit(False, str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.current_operation = None
        self.init_ui()
        self.setWindowTitle("Secure File Cryptor")
        self.setGeometry(100, 100, 800, 600)

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
        self.encrypt_confirm = QLineEdit()
        self.encrypt_confirm.setEchoMode(QLineEdit.Password)
        
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

        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        password_layout.addWidget(self.encrypt_password)
        password_layout.addWidget(QLabel("Confirm:"))
        password_layout.addWidget(self.encrypt_confirm)

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

        layout.addLayout(file_layout)
        layout.addLayout(output_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.decrypt_progress)
        layout.addWidget(self.decrypt_log)
        
        tab.setLayout(layout)
        return tab

    # File selection methods
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

    # Operation handling
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

                self.worker = CryptoWorker(operation, file_path, output_path, password)
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