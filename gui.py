from functools import partial
import re
import time
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
    QRadioButton,
    QComboBox,
)
from PyQt5.QtGui import QIcon, QFontDatabase
import sys
import os
from PyQt5.QtCore import Qt

from crypto import CryptoWorker, DriveCrypto, HardwareToken, PasswordRecovery
from utilities import PasswordStrengthMeter

from utilities import generate_seed_phrase

from qt_material import apply_stylesheet
import hashlib


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
        self.encrypt_type = None

        self.hardware_token = None
        self.hardware_token_seed_phrase = None
        self.recovery_hardware_token_seed_phrases = {}

    def load_icon(self):
        # get icon from current directory
        base_path = os.path.dirname(os.path.abspath(__file__))

        icon_path = os.path.join(base_path, "app-logo.ico")

        if os.path.exists(icon_path):
            return QIcon(icon_path)
        else:
            return QIcon()

    def load_security_questions(self):
        # Load security questions from a file or database
        # For simplicity, we will use hardcoded questions
        self.security_questions = []

        # load from security_questions.txt
        try:
            with open("security_questions.txt", "r") as f:
                self.security_questions_text = [line.strip() for line in f.readlines()]

                # create a dictionary with hashes of the questions as key and questions as values
                self.security_questions = {
                    hashlib.sha256(question.encode()).hexdigest(): question
                    for question in self.security_questions_text
                }

        except FileNotFoundError:
            QMessageBox.warning(
                self,
                "Error",
                "Security questions file not found. Please create a file named 'security_questions.txt' with your questions.",
            )
            return
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while loading security questions: {str(e)}",
            )
            return
        if len(self.security_questions) < 2:
            QMessageBox.warning(
                self,
                "Error",
                "Please provide at least two security questions in the 'security_questions.txt' file.",
            )
            return

    def load_security_questions_for_recovery(self):
        recovery_path = self.recovery_drive_line.text().strip()
        if not recovery_path:
            QMessageBox.warning(
                self, "Warning", "Please select a file or folder for recovery."
            )
            return

        # Determine the directory of the selected file or folder
        if os.path.isfile(recovery_path):
            directory = os.path.dirname(recovery_path)
        else:
            directory = recovery_path

        # Construct the path to the security questions file
        questions_file_path = os.path.join(directory, "security.questions")

        # Load security questions from the file
        try:
            with open(questions_file_path, "r") as f:
                questions = [line.strip() for line in f.readlines()]
            if len(questions) < 2:
                raise ValueError(
                    "The security questions file must contain at least two questions."
                )

            question_hashes = []

            for question in questions:
                match = re.search(r"'([a-fA-F0-9]{64})'", question)
                if match:
                    extracted_hash = match.group(1)
                    question_hashes.append(extracted_hash)
                else:
                    print("No valid hash found in the string.")

            if len(question_hashes) < 2:
                raise ValueError(
                    "The security questions file must contain at least two questions."
                )

            self.recovery_question1.setText(
                self.security_questions.get(question_hashes[0])
            )
            self.recovery_question2.setText(
                self.security_questions.get(question_hashes[1])
            )

        except FileNotFoundError:
            QMessageBox.warning(
                self, "Warning", f"Security questions file not found in {directory}."
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while loading security questions: {str(e)}",
            )

    def init_ui(self):
        self.tabs = QTabWidget()
        self.encrypt_tab = self.create_encrypt_tab()
        self.decrypt_tab = self.create_decrypt_tab()
        self.recovery_tab = self.create_recovery_tab()
        self.tabs.addTab(self.encrypt_tab, "Encrypt")
        self.tabs.addTab(self.decrypt_tab, "Decrypt")
        self.tabs.addTab(self.recovery_tab, "Recover Key")
        self.setCentralWidget(self.tabs)

    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # File selection (existing code remains the same)
        self.encrypt_file_line = QLineEdit()
        self.encrypt_file_btn = QPushButton("Select File")
        self.encrypt_file_btn.clicked.connect(
            partial(self.select_files, self.encrypt_file_line, False)
        )
        self.encrypt_directory_btn = QPushButton("Select Directory")
        self.encrypt_directory_btn.clicked.connect(
            partial(self.select_folder, self.encrypt_file_line, True)
        )

        # Password fields (existing code remains the same)
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        self.encrypt_password.textChanged.connect(self.update_password_strength)

        self.encrypt_confirm = QLineEdit()
        self.encrypt_confirm.setEchoMode(QLineEdit.Password)

        # Show password checkbox (existing code remains the same)
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.stateChanged.connect(
            self.toggle_password_visibility
        )

        # Delete original file checkbox (existing code remains the same)
        self.delete_original_checkbox = QCheckBox(
            "Delete original file after encryption"
        )

        # Password strength meter (existing code remains the same)
        self.password_strength_label = QLabel("Password Strength:")
        self.password_strength_meter = QProgressBar()
        self.password_strength_meter.setRange(0, 100)
        self.password_strength_meter.setTextVisible(False)

        # ===== NEW KEY RECOVERY SECTION =====
        self.recovery_section = QWidget()
        self.recovery_section.setVisible(False)  # Start collapsed
        recovery_layout = QVBoxLayout()

        # Seed phrase recovery
        self.seed_phrase_radio_btn = QRadioButton("Enable Seed Phrase Recovery")
        self.seed_phrase_text = QTextEdit()
        self.seed_phrase_text.setReadOnly(True)
        self.seed_phrase_text.setMaximumHeight(60)
        self.generate_seed_btn = QPushButton("Generate 12-word Phrase")
        self.generate_seed_btn.clicked.connect(self.generate_seed_phrase)

        # Security questions
        self.security_questions_radio_btn = QRadioButton("Enable Security Questions")
        self.security_questions_widget = QWidget()
        sq_layout = QVBoxLayout()

        self.load_security_questions()

        # Dropdown for selecting questions
        self.question1 = QComboBox()
        self.question1.addItems(self.security_questions.values())
        self.answer1 = QLineEdit()
        self.answer1.setPlaceholderText("Answer for Question 1")
        self.answer1.setEchoMode(QLineEdit.Password)

        self.question2 = QComboBox()
        self.question2.addItems(self.security_questions.values())
        self.answer2 = QLineEdit()
        self.answer2.setPlaceholderText("Answer for Question 2")
        self.answer2.setEchoMode(QLineEdit.Password)

        sq_layout.addWidget(self.question1)
        sq_layout.addWidget(self.answer1)
        sq_layout.addWidget(self.question2)
        sq_layout.addWidget(self.answer2)
        self.security_questions_widget.setLayout(sq_layout)

        # Hardware token
        self.hardware_token_radio_btn = QRadioButton(
            "Enable Hardware Token (e.g., YubiKey)"
        )
        self.register_token_btn = QPushButton("Register Device")
        self.register_token_btn.clicked.connect(self.register_hardware_token)

        # Add to recovery layout
        recovery_layout.addWidget(self.seed_phrase_radio_btn)
        recovery_layout.addWidget(self.seed_phrase_text)
        recovery_layout.addWidget(self.generate_seed_btn)
        recovery_layout.addWidget(self.security_questions_radio_btn)
        recovery_layout.addWidget(self.security_questions_widget)
        recovery_layout.addWidget(self.hardware_token_radio_btn)
        recovery_layout.addWidget(self.register_token_btn)
        self.recovery_section.setLayout(recovery_layout)

        # Toggle button for the section
        self.toggle_recovery_btn = QPushButton("▼ Set up Key Recovery Options")
        self.toggle_recovery_btn.setCheckable(True)
        self.toggle_recovery_btn.setChecked(False)
        self.toggle_recovery_btn.setStyleSheet("text-align: left;")
        self.toggle_recovery_btn.clicked.connect(self.toggle_recovery_section)

        # Progress (existing code remains the same)
        self.encrypt_progress = QProgressBar()
        self.encrypt_log = QTextEdit()
        self.encrypt_log.setReadOnly(True)

        # Buttons (existing code remains the same)
        self.encrypt_btn = QPushButton("Start Encryption")
        self.encrypt_btn.clicked.connect(partial(self.start_operation, "encrypt"))

        # Layout organization (modified to include recovery section)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.encrypt_file_line)
        file_layout.addWidget(self.encrypt_file_btn)
        file_layout.addWidget(self.encrypt_directory_btn)

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
        layout.addLayout(password_layout)
        layout.addWidget(self.toggle_recovery_btn)  # Add the toggle button
        layout.addWidget(self.recovery_section)  # Add the recovery section
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

        self.decrypt_directory_btn = QPushButton("Select Directory")
        self.decrypt_directory_btn.clicked.connect(
            partial(self.select_folder, self.decrypt_file_line, True)
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
        file_layout.addWidget(self.decrypt_directory_btn)

        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        password_layout.addWidget(self.decrypt_password)
        password_layout.addWidget(self.show_password_checkbox_decrypt)
        password_layout.addWidget(self.delete_original_checkbox_decrypt)

        layout.addLayout(file_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.decrypt_progress)
        layout.addWidget(self.decrypt_log)

        tab.setLayout(layout)
        return tab

    def create_recovery_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Recovery key file selection
        self.recovery_key_line = QLineEdit()
        self.recovery_key_btn = QPushButton("Select Recovery Key File")
        self.recovery_key_btn.clicked.connect(
            partial(self.select_files, self.recovery_key_line, False)
        )

        # Drive or file selection for re-encryption/recovery
        self.recovery_drive_line = QLineEdit()
        self.recovery_drive_btn = QPushButton("Select Drive/Folder/File")
        self.recovery_drive_btn.clicked.connect(
            partial(self.select_files, self.recovery_drive_line, True)
        )

        # Recovery options
        self.recovery_seed_phrase_radio_btn = QRadioButton("Use Seed Phrase")
        self.recovery_seed_phrase_text = QTextEdit()
        self.recovery_seed_phrase_text.setPlaceholderText("Enter your seed phrase here")
        self.recovery_seed_phrase_text.setMaximumHeight(60)

        self.recovery_security_questions_radio_btn = QRadioButton(
            "Use Security Questions"
        )
        self.recovery_security_questions_radio_btn.toggled.connect(
            self.load_security_questions_for_recovery
        )
        self.recovery_question1 = QLineEdit(placeholderText="Question 1")
        self.recovery_question1.setReadOnly(True)
        self.recovery_answer1 = QLineEdit(placeholderText="Answer")
        self.recovery_question2 = QLineEdit(placeholderText="Question 2")
        self.recovery_question1.setReadOnly(True)
        self.recovery_answer2 = QLineEdit(placeholderText="Answer")

        self.recovery_hardware_token_radio_btn = QRadioButton("Use Hardware Token")
        self.verify_token_btn = QPushButton("Verify Hardware Token")
        self.verify_token_btn.clicked.connect(self.verify_hardware_token)

        # New password fields
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.textChanged.connect(self.update_new_password_strength)

        self.confirm_new_password = QLineEdit()
        self.confirm_new_password.setEchoMode(QLineEdit.Password)

        self.show_new_password_checkbox = QCheckBox("Show Password")
        self.show_new_password_checkbox.stateChanged.connect(
            self.toggle_new_password_visibility
        )

        # Password strength meter
        self.new_password_strength_label = QLabel("Password Strength:")
        self.new_password_strength_meter = QProgressBar()
        self.new_password_strength_meter.setRange(0, 100)
        self.new_password_strength_meter.setTextVisible(False)

        # Recover button
        self.recover_btn = QPushButton("Recover Key")
        self.recover_btn.clicked.connect(self.recover_password)

        # Layout organization
        recovery_key_layout = QHBoxLayout()
        recovery_key_layout.addWidget(self.recovery_key_line)
        recovery_key_layout.addWidget(self.recovery_key_btn)

        recovery_drive_layout = QHBoxLayout()
        recovery_drive_layout.addWidget(self.recovery_drive_line)
        recovery_drive_layout.addWidget(self.recovery_drive_btn)

        security_questions_layout = QVBoxLayout()
        security_questions_layout.addWidget(self.recovery_question1)
        security_questions_layout.addWidget(self.recovery_answer1)
        security_questions_layout.addWidget(self.recovery_question2)
        security_questions_layout.addWidget(self.recovery_answer2)

        password_layout = QVBoxLayout()
        password_row1 = QHBoxLayout()
        password_row1.addWidget(QLabel("New Password:"))
        password_row1.addWidget(self.new_password)
        password_row1.addWidget(QLabel("Confirm:"))
        password_row1.addWidget(self.confirm_new_password)

        password_row2 = QHBoxLayout()
        password_row2.addWidget(self.show_new_password_checkbox)

        password_layout.addLayout(password_row1)
        password_layout.addLayout(password_row2)

        strength_layout = QHBoxLayout()
        strength_layout.addWidget(self.new_password_strength_label)
        strength_layout.addWidget(self.new_password_strength_meter)
        password_layout.addLayout(strength_layout)

        layout.addLayout(recovery_key_layout)
        layout.addLayout(recovery_drive_layout)
        layout.addWidget(self.recovery_seed_phrase_radio_btn)
        layout.addWidget(self.recovery_seed_phrase_text)
        layout.addWidget(self.recovery_security_questions_radio_btn)
        layout.addLayout(security_questions_layout)
        layout.addWidget(self.recovery_hardware_token_radio_btn)
        layout.addWidget(self.verify_token_btn)
        layout.addLayout(password_layout)
        layout.addWidget(self.recover_btn)

        tab.setLayout(layout)
        return tab

    def toggle_new_password_visibility(self, state):
        if state == Qt.Checked:
            self.new_password.setEchoMode(QLineEdit.Normal)
            self.confirm_new_password.setEchoMode(QLineEdit.Normal)
        else:
            self.new_password.setEchoMode(QLineEdit.Password)
            self.confirm_new_password.setEchoMode(QLineEdit.Password)

    def recover_password(self):
        try:
            if self.recovery_seed_phrase_radio_btn.isChecked():
                seed_phrase = self.recovery_seed_phrase_text.toPlainText().strip()
                if not seed_phrase:
                    raise ValueError("Seed phrase cannot be empty")

            if self.recovery_security_questions_radio_btn.isChecked():
                question1 = self.recovery_question1.text().strip()
                answer1 = self.recovery_answer1.text().strip()
                question2 = self.recovery_question2.text().strip()
                answer2 = self.recovery_answer2.text().strip()
                if not (question1 and answer1 and question2 and answer2):
                    raise ValueError(
                        "All security questions and answers must be filled"
                    )

            if self.recovery_hardware_token_radio_btn.isChecked():
                if len(self.recovery_hardware_token_seed_phrases) < 1:
                    raise Exception(
                        "Seed Phrases not Retrieved From Hardware Token"
                    )

            # Validate new password
            new_password = self.new_password.text()
            confirm_password = self.confirm_new_password.text()
            if not new_password:
                raise ValueError("New password cannot be empty")
            if new_password != confirm_password:
                raise ValueError("Passwords do not match")

            self.recover_key()

            # Perform password recovery (implementation depends on your logic)
            QMessageBox.information(
                self,
                "Success",
                "Password recovery successful. Your new password has been set.",
            )

        except Exception as e:
            self.show_error(str(e))

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

    def update_new_password_strength(self):
        password = self.new_password.text()
        strength = PasswordStrengthMeter.calculate_strength(password)
        color = PasswordStrengthMeter.get_strength_color(strength)

        self.new_password_strength_meter.setValue(strength)
        self.new_password_strength_meter.setStyleSheet(
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

        self.encrypt_type = "file" if not multi else "files"

    def select_folder(self, line_edit, multi):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            line_edit.setText(folder)

        self.encrypt_type = "folder" if folder else None

    def select_output_file(self, line_edit, default_suffix):
        file, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "", f"Encrypted Files (*.{default_suffix})"
        )
        if file:
            line_edit.setText(file)

    def folder_operation(self, driveCrypto: DriveCrypto, operation):
        if operation == "encrypt":
            self.encrypt_log.append(
                driveCrypto.visualize_directory_structure_as_string()
            )
            self.encrypt_log.append(
                f"Starting encryption of folder: {self.encrypt_file_line.text()}..."
            )
            self.encrypt_log.append(
                f"Encrypted files will be saved in: {self.encrypt_file_line.text()}"
            )
            driveCrypto.encrypt(self.encrypt_password.text())
            self.encrypt_log.append(
                f"Encryption of folder {self.encrypt_file_line.text()} completed."
            )
        elif operation == "decrypt":
            self.decrypt_log.append(
                driveCrypto.visualize_directory_structure_as_string()
            )
            self.decrypt_log.append(
                f"Starting decryption of folder: {self.decrypt_file_line.text()}..."
            )
            self.decrypt_log.append(
                f"Decrypted files will be saved in: {self.decrypt_file_line.text()}"
            )
            driveCrypto.decrypt(self.decrypt_password.text())
            self.decrypt_log.append(
                f"Decryption of folder {self.decrypt_file_line.text()} completed."
            )

    def recovery_folder_operation(
        self, driveCrypto: DriveCrypto, old_password, new_password
    ):
        self.encrypt_log.append(
            f"Old password for {self.recovery_drive_line.text()} is: {old_password}"
        )
        self.encrypt_log.append(driveCrypto.visualize_directory_structure_as_string())
        self.encrypt_log.append(
            f"Starting recovery of folder: {self.recovery_drive_line.text()}..."
        )
        driveCrypto.decrypt(self.new_password.text())
        self.encrypt_log.append(
            f"Decryption of folder {self.recovery_drive_line.text()} completed."
        )
        self.encrypt_log.append(
            f"New password for {self.recovery_drive_line.text()} is: {new_password}"
        )
        self.encrypt_log.append(
            f"Re-encryption of folder {self.recovery_drive_line.text()} completed."
        )
        driveCrypto.encrypt(new_password)
        self.encrypt_log.append(
            f"Re-encryption of folder {self.recovery_drive_line.text()} completed."
        )

    def save_recovery_stuff(self, operation):
        if operation == "decrypt":
            return

        password = self.encrypt_password.text()
        password_recovery = PasswordRecovery(self.encrypt_file_line.text(), password)
        if self.seed_phrase_radio_btn.isChecked():
            password_recovery.setup_key_recovery(
                "seed_phrase", self.seed_phrase_text.toPlainText()
            )
        elif self.security_questions_radio_btn.isChecked():

            if self.question1.currentText() == self.question2.currentText():
                raise Exception("Please don't select same questions!")

            if self.answer1.text() == "" or self.answer2.text() == "":
                raise Exception("Please don't leave answers empty")

            questions = {
                "question1": hashlib.sha256(
                    self.question1.currentText().encode()
                ).hexdigest(),
                "question2": hashlib.sha256(
                    self.question2.currentText().encode()
                ).hexdigest(),
            }
            recovery_key = self.answer1.text() + ";" + self.answer2.text()
            password_recovery.setup_key_recovery(
                "security_questions", recovery_key, questions
            )
        elif self.hardware_token_radio_btn.isChecked():
            password_recovery.setup_key_recovery(
                "hardware_token", self.hardware_token_seed_phrase
            )

        password_recovery.encrypt_recovery_key()
        self.encrypt_log.append("Key recovery information has been saved successfully.")
        self.encrypt_log.append(
            f"Recovery information for {self.encrypt_file_line.text()} has been saved."
        )

    def recover_key(self):

        if self.new_password.text() != self.confirm_new_password.text():
            raise ValueError("Passwords do not match")
        if not self.new_password.text():
            raise ValueError("Password cannot be empty")

        password_recovery = PasswordRecovery(
            self.recovery_drive_line.text(), self.new_password.text()
        )
        if self.recovery_seed_phrase_radio_btn.isChecked():
            seed_phrase = self.recovery_seed_phrase_text.toPlainText().strip()
            if not seed_phrase:
                raise ValueError("Seed phrase cannot be empty")

            password_recovery.setup_key_recovery("seed_phrase", seed_phrase)
        elif self.recovery_security_questions_radio_btn.isChecked():
            questions = {
                "question1": hashlib.sha256(
                    self.recovery_question1.text().encode()
                ).hexdigest(),
                "question2": hashlib.sha256(
                    self.recovery_question2.text().encode()
                ).hexdigest(),
            }
            recovery_key = (
                self.recovery_answer1.text() + ";" + self.recovery_answer2.text()
            )
            password_recovery.setup_key_recovery(
                "security_questions", recovery_key, questions
            )

        elif self.recovery_hardware_token_radio_btn.isChecked():
            password_recovery.setup_key_recovery(
                "hardware_token", self.recovery_hardware_token_seed_phrases.popitem()[1], self.recovery_hardware_token_seed_phrases 
            )

        old_password = None
        try:
            old_password = password_recovery.decrypt_recovery_key()
            password_recovery.encrypt_recovery_key()
        except Exception as e:
            self.show_error(f"Failed  key: {str(e)}")
            return

        # show in log that new password is set
        self.encrypt_log.append(
            f"Old password for {self.recovery_drive_line.text()} is: {old_password}"
        )
        self.encrypt_log.append(
            f"New password for {self.recovery_drive_line.text()} is: {self.new_password.text()}"
        )

        if self.encrypt_type == "folder":
            driveCrypto = DriveCrypto((self.recovery_drive_line.text()), True)

            self.recovery_folder_operation(driveCrypto)
            return
        else:
            file_path = self.recovery_drive_line.text()
            new_password = self.new_password.text()
            output_path = self.recovery_drive_line.text()[:-4]

            self.worker = CryptoWorker("decrypt", file_path, output_path, old_password)
            self.worker.set_delete_original(True)
            self.encrypt_log.append(f"Starting encryption of {file_path}...")

            self.setup_worker_connections("decrypt")
            self.worker.start()

            self.worker.wait()

            file_path, output_path = output_path, file_path

            self.worker = CryptoWorker("encrypt", file_path, output_path, new_password)
            self.worker.set_delete_original(True)
            self.encrypt_log.append(f"Starting decryption of {file_path}...")

            self.setup_worker_connections("encrypt")
            self.worker.start()

    def start_operation(self, operation):

        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Warning", "Another operation is in progress")
            return

        if self.encrypt_type is None:
            QMessageBox.information(
                self, "Info", "Please select a file or folder to encrypt"
            )
            return

        try:
            if self.recovery_section.isVisible() and (
                self.seed_phrase_radio_btn.isChecked()
                or self.security_questions_radio_btn.isChecked()
                or self.hardware_token_radio_btn.isChecked()
            ):
                self.save_recovery_stuff(operation)

            if self.encrypt_type == "folder":
                driveCrypto = None

                if operation == "encrypt":
                    driveCrypto = DriveCrypto(
                        self.encrypt_file_line.text(),
                        self.delete_original_checkbox.isChecked(),
                    )
                elif operation == "decrypt":
                    driveCrypto = DriveCrypto(
                        self.decrypt_file_line.text(),
                        self.delete_original_checkbox_decrypt.isChecked(),
                    )

                if not driveCrypto:
                    raise ValueError("Please select a folder to encrypt/decrypt")

                self.folder_operation(driveCrypto, operation)
                return

            if operation == "encrypt":
                file_path = self.encrypt_file_line.text()
                password = self.encrypt_password.text()
                confirm = self.encrypt_confirm.text()

                output_path = self.encrypt_file_line.text() + ".enc"

                if not file_path:
                    raise ValueError("Please select a file to encrypt")
                # if not output_path:
                #     raise ValueError("Please select output path")
                if password != confirm:
                    raise ValueError("Passwords do not match")
                if not password:
                    raise ValueError("Password cannot be empty")

                self.worker = CryptoWorker(operation, file_path, output_path, password)
                self.worker.set_delete_original(
                    self.delete_original_checkbox.isChecked()
                )
                self.encrypt_log.append(f"Starting encryption of {file_path}...")

            elif operation == "decrypt":
                file_path = self.decrypt_file_line.text()
                password = self.decrypt_password.text()

                output_path = self.decrypt_file_line.text()[:-4]

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

    def toggle_recovery_section(self):
        """Toggle visibility of the recovery options section."""
        if self.toggle_recovery_btn.isChecked():
            self.recovery_section.setVisible(True)
            self.toggle_recovery_btn.setText("▲ Hide Key Recovery Options")
        else:
            self.recovery_section.setVisible(False)
            self.toggle_recovery_btn.setText("▼ Set up Key Recovery Options")

    def generate_seed_phrase(self):
        """Generate a random seed phrase."""

        self.seed_phrase_text.setPlainText(generate_seed_phrase(256, "en"))
        QMessageBox.information(
            self,
            "Seed Phrase",
            "Write this down and store it securely!\n"
            "It cannot be recovered if lost.",
        )

    def register_hardware_token(self):
        """Handle hardware token registration."""

        if not self.hardware_token_radio_btn.isChecked():
            QMessageBox.warning(
                self,
                "Hardware Token",
                "Select the Hardware Token Option",
            )
            return

        self.hardware_token = HardwareToken()

        try:
            self.hardware_token.connect()
            self.encrypt_log.append(
                f"Success: Connected to {self.hardware_token.token_name}"
            )

            self.encrypt_log.append(
                f"Info: Key has space for {self.hardware_token.get_space()} and {'has space' if self.hardware_token.has_space() else 'is full.'}"
            )

            if not self.hardware_token.has_space():
                QMessageBox.critical(
                    self, "Hardware Token Full", "Can't use this token as it is full."
                )
                raise Exception("Can't use this token as it is full.")

            self.hardware_token_seed_phrase = generate_seed_phrase(256, "en")
            self.encrypt_log.append(
                f"Info: The seed phrase stored in the Hardware Token is:\n {self.hardware_token_seed_phrase}\nYou can keep it if you want to recover using seed phrase."
            )
            self.hardware_token.write_seed_phrase_to_token(
                self.hardware_token_seed_phrase
            )

            QMessageBox.information(
                self,
                "Success",
                f"Seed Phrase Successfully stored in your {self.hardware_token.token_name}",
            )

            self.encrypt_log.append(
                f"Success: Seed Phrase Successfully stored in your {self.hardware_token.token_name}"
            )

        except Exception as e:
            self.encrypt_log.append(f"Error: {e}")
        finally:
            self.hardware_token.disconnect()

    def toggle_decrypt_recovery_section(self):
        """Toggle visibility of the decrypt recovery options section."""
        if self.decrypt_toggle_recovery_btn.isChecked():
            self.decrypt_recovery_section.setVisible(True)
            self.decrypt_toggle_recovery_btn.setText("▲ Hide Recovery Options")
        else:
            self.decrypt_recovery_section.setVisible(False)
            self.decrypt_toggle_recovery_btn.setText("▼ Alternative Recovery Options")

    def verify_hardware_token(self):
        """Handle hardware token verification during decryption."""

        if not self.recovery_hardware_token_radio_btn.isChecked():
            QMessageBox.warning(
                self,
                "Hardware Token",
                "Select the Hardware Token Option",
            )
            return

        self.hardware_token = HardwareToken()

        try:
            self.hardware_token.connect()
            self.encrypt_log.append(
                f"Success: Connected to {self.hardware_token.token_name}"
            )

            self.encrypt_log.append(
                f"Info: Key has space for {self.hardware_token.get_space()} and {'has space' if self.hardware_token.has_space() else 'is full.'}"
            )

            if not self.hardware_token.has_space():
                QMessageBox.warning(
                    self, "Hardware Token Full", "Be carefull."
                )

            self.recovery_hardware_token_seed_phrases = self.hardware_token.get_seed_phrase_from_token()

            if len(self.recovery_hardware_token_seed_phrases) > 0:
                QMessageBox.information(
                    self,
                    "Success",
                    f"Seed Phrases Successfully retrieved from {self.hardware_token.token_name}",
                )

                self.encrypt_log.append(
                    f"Success: Seed Phrases Successfully retrieved from {self.hardware_token.token_name}"
                )
                return
            QMessageBox.warning(
                    self,
                    "Warning",
                    f"No Seed Phrases found on {self.hardware_token.token_name}",
                )

            self.encrypt_log.append(
                f"Success: No Seed Phrases found on {self.hardware_token.token_name}"
            )

        except Exception as e:
            self.encrypt_log.append(f"Error: {e}")

        finally:
            self.hardware_token.disconnect()
