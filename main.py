"""
Main module for the Secure File/Folder/Drive Encryptor/Decryptor application.

This module initializes the PyQt5 application, applies a dark blue theme, 
and launches the main GUI window.

Features:
- Secure encryption and decryption using AES-GCM with unique nonce per chunk.
- Chunk sequence validation for enhanced security.
- Password strength checking to ensure robust protection.
- Progress reporting during encryption/decryption processes.
- Secure file handling to prevent data leaks.
- Graphical User Interface (GUI) for user-friendly interaction.
- Password recovery options including:

Classes:
- MainWindow: The main GUI window of the application (imported from `gui` module).

Functions:
- None

Attributes:
- app (QApplication): The main application instance.
- window (MainWindow): The main GUI window instance.

Usage:
Run this module directly to start the application.
Secure File/Folder/Drive Encryptor/Decryptor
- Uses AES-GCM with unique nonce per chunk
- Includes chunk sequence validation
- Password strength checking
- Progress reporting
- Secure file handling
- Includes a GUI
- Has Password strength checking
- Provides Password Recovery Options:
    - Seed Phrase
    - Security Questions
    - Hardware Token (Pico Key)
"""

import os
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QCoreApplication, Qt
from gui import MainWindow
from qt_material import apply_stylesheet

if __name__ == "__main__":
    QCoreApplication.setAttribute(Qt.AA_DisableWindowContextHelpButton)
    app: QApplication = QApplication(sys.argv)

    apply_stylesheet(app, theme="dark_blue.xml")
    window: MainWindow = MainWindow()
    window.show()
    sys.exit(app.exec_())
