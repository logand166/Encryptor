#!/usr/bin/env python3

"""
Secure File Encryptor/Decryptor
- Uses AES-GCM with unique nonce per chunk
- Includes chunk sequence validation
- Password strength checking
- Progress reporting
- Secure file handling
"""

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QCoreApplication, Qt
from gui import MainWindow
from qt_material import apply_stylesheet

if __name__ == "__main__":
    QCoreApplication.setAttribute(Qt.AA_DisableWindowContextHelpButton)
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme="dark_teal.xml")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
