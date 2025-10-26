"""
DarkCipher GUI (PyQt6)
File: gui_pyqt.py
"""

import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton,
                             QFileDialog, QMessageBox, QRadioButton,
                             QButtonGroup)
from PyQt6.QtCore import Qt

# Add project root to import path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from functions import aes_gcm, key_derivation, utils


class DarkCipherGUI(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkCipher GUI")
        self.resize(700, 500)
        self.opened_file_path = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        # Mode selection
        mode_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        mode_group = QButtonGroup(self)
        mode_group.addButton(self.encrypt_radio)
        mode_group.addButton(self.decrypt_radio)
        mode_layout.addWidget(QLabel("Mode:"))
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        # Input
        input_layout = QHBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text or open a file...")
        input_layout.addWidget(self.input_text)

        file_buttons = QVBoxLayout()
        self.btn_open_file = QPushButton("Open File...")
        self.btn_open_file.clicked.connect(self.open_file)
        self.lbl_opened = QLabel("No file selected")
        file_buttons.addWidget(self.btn_open_file)
        file_buttons.addWidget(self.lbl_opened)
        file_buttons.addStretch()
        input_layout.addLayout(file_buttons)
        layout.addLayout(input_layout, stretch=2)

        # Password
        pw_layout = QHBoxLayout()
        pw_layout.addWidget(QLabel("Password:"))
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.pw_input)
        layout.addLayout(pw_layout)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.btn_run = QPushButton("Run")
        self.btn_run.clicked.connect(self.run_action)
        self.btn_save_output = QPushButton("Save Output...")
        self.btn_save_output.clicked.connect(self.save_output)
        btn_layout.addWidget(self.btn_run)
        btn_layout.addWidget(self.btn_save_output)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Output
        layout.addWidget(QLabel("Output:"))
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Result will appear here...")
        layout.addWidget(self.output_text, stretch=1)

        self.setLayout(layout)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open file")
        if not path:
            return
        self.opened_file_path = path
        self.lbl_opened.setText(os.path.basename(path))
        try:
            data = utils.load_file(path)
            try:
                text = data.decode("utf-8")
                self.input_text.setPlainText(text)
            except UnicodeDecodeError:
                self.input_text.setPlainText(
                    f"<binary file opened: {os.path.basename(path)}>\n")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read file:\n{e}")

    def run_action(self):
        mode_encrypt = self.encrypt_radio.isChecked()
        password = self.pw_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Missing Password",
                                "Please enter a password.")
            return

        try:
            if self.opened_file_path:
                data = utils.load_file(self.opened_file_path)
                self._process_file(data, password, mode_encrypt)
            else:
                text = self.input_text.toPlainText().strip()
                if not text:
                    QMessageBox.warning(self, "No Input",
                                        "Please enter text or open a file.")
                    return
                self._process_text(text, password, mode_encrypt)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _process_file(self, data: bytes, password: str, encrypt: bool):
        if encrypt:
            salt = key_derivation.generate_salt()
            key = key_derivation.derive_key_pbkdf2(password, salt)
            iv, ciphertext = aes_gcm.encrypt(data, key)
            packaged = utils.package(iv, salt, ciphertext)
            self.output_text.setPlainText(packaged)
            QMessageBox.information(self, "Success",
                                    "File encrypted successfully.")
        else:
            try:
                blob = data.decode("utf-8")
                version, iv, salt, ciphertext = utils.unpack(blob)
                key = key_derivation.derive_key_pbkdf2(password, salt)
                plaintext = aes_gcm.decrypt(iv, ciphertext, key)
                try:
                    self.output_text.setPlainText(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    self.output_text.setPlainText("<binary data decrypted>")
                QMessageBox.information(self, "Success",
                                        "File decrypted successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Decryption Failed", str(e))

    def _process_text(self, text: str, password: str, encrypt: bool):
        if encrypt:
            salt = key_derivation.generate_salt()
            key = key_derivation.derive_key_pbkdf2(password, salt)
            iv, ciphertext = aes_gcm.encrypt(text.encode("utf-8"), key)
            packaged = utils.package(iv, salt, ciphertext)
            self.output_text.setPlainText(packaged)
            QMessageBox.information(self, "Success",
                                    "Text encrypted successfully.")
        else:
            try:
                version, iv, salt, ciphertext = utils.unpack(text)
                key = key_derivation.derive_key_pbkdf2(password, salt)
                plaintext = aes_gcm.decrypt(iv, ciphertext, key)
                try:
                    self.output_text.setPlainText(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    self.output_text.setPlainText("<binary data decrypted>")
                QMessageBox.information(self, "Success",
                                        "Text decrypted successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Decryption Failed", str(e))

    def save_output(self):
        output = self.output_text.toPlainText().strip()
        if not output:
            QMessageBox.warning(self, "No Output", "Nothing to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save output")
        if not path:
            return
        try:
            Path(path).write_text(output, encoding="utf-8")
            QMessageBox.information(self, "Saved", f"Output saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", str(e))


def main():
    app = QApplication(sys.argv)
    gui = DarkCipherGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
