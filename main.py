"""
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
    - Hardware Token
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
