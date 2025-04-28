from functools import partial
from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QFileDialog,
    QTextEdit,
    QProgressBar,
    QMessageBox,
    QCheckBox,
)
from PyQt5.QtGui import QIcon, QFontDatabase
import sys
import os
from PyQt5.QtCore import Qt

from crypto import CryptoWorker
from utilities import PasswordStrengthMeter


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure File Cryptor")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(self.load_icon())

        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowSystemMenuHint
            | Qt.WindowMinMaxButtonsHint
            | Qt.WindowCloseButtonHint
        )

        self.init_ui()
        self.worker = None
        self.current_operation = None

    def load_icon(self):
        # get icon from current directory
        base_path = os.path.dirname(os.path.abspath(__file__))
        
        icon_path = os.path.join(base_path, "app-logo.ico")

        
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
        self.encrypt_file_btn.clicked.connect(
            partial(self.select_files, self.encrypt_file_line, False)
        )

        # Output path
        self.encrypt_output_line = QLineEdit()
        self.encrypt_output_btn = QPushButton("Select Output Path")
        self.encrypt_output_btn.clicked.connect(
            partial(self.select_output_file, self.encrypt_output_line, "encrypted")
        )

        # Password fields
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        self.encrypt_password.textChanged.connect(self.update_password_strength)

        self.encrypt_confirm = QLineEdit()
        self.encrypt_confirm.setEchoMode(QLineEdit.Password)

        # Show password checkbox
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.stateChanged.connect(
            self.toggle_password_visibility
        )

        # Delete original file checkbox
        self.delete_original_checkbox = QCheckBox(
            "Delete original file after encryption"
        )

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
        self.encrypt_btn.clicked.connect(partial(self.start_operation, "encrypt"))

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
        self.decrypt_file_btn.clicked.connect(
            partial(self.select_files, self.decrypt_file_line, False)
        )

        # Output path
        self.decrypt_output_line = QLineEdit()
        self.decrypt_output_btn = QPushButton("Select Output Path")
        self.decrypt_output_btn.clicked.connect(
            partial(self.select_output_file, self.decrypt_output_line, "decrypted")
        )

        # Password field
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)

        # Show password checkbox
        self.show_password_checkbox_decrypt = QCheckBox("Show Password")
        self.show_password_checkbox_decrypt.stateChanged.connect(
            self.toggle_password_visibility_decrypt
        )

        # Delete original file checkbox
        self.delete_original_checkbox_decrypt = QCheckBox(
            "Delete encrypted file after decryption"
        )

        # Progress
        self.decrypt_progress = QProgressBar()
        self.decrypt_log = QTextEdit()
        self.decrypt_log.setReadOnly(True)

        # Buttons
        self.decrypt_btn = QPushButton("Start Decryption")
        self.decrypt_btn.clicked.connect(partial(self.start_operation, "decrypt"))

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
            self, "Select Output File", "", f"Encrypted Files (*.{default_suffix})"
        )
        if file:
            line_edit.setText(file)

    def start_operation(self, operation):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Warning", "Another operation is in progress")
            return

        try:
            if operation == "encrypt":
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
                if not output_path.endswith(".encrypted"):
                    output_path += ".encrypted"

                self.worker = CryptoWorker(operation, file_path, output_path, password)
                self.worker.set_delete_original(
                    self.delete_original_checkbox.isChecked()
                )
                self.encrypt_log.append(f"Starting encryption of {file_path}...")

            elif operation == "decrypt":
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
                self.worker.set_delete_original(
                    self.delete_original_checkbox_decrypt.isChecked()
                )
                self.decrypt_log.append(f"Starting decryption of {file_path}...")

            self.setup_worker_connections(operation)
            self.worker.start()

        except Exception as e:
            self.show_error(str(e))

    def setup_worker_connections(self, operation):
        if operation == "encrypt":
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
        self.worker.error_occurred.connect(lambda err: self.show_error(err, log))
        self.worker.delete_original_requested.connect(
            lambda path: log.append(f"Original file deleted: {path}")
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
