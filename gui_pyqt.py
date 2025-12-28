import sys
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton,
                             QFileDialog, QMessageBox, QRadioButton,
                             QButtonGroup)

from crypt_core.aes_gcm import encrypt, decrypt
from crypt_core.key_derivation import (
    derive_key_pbkdf2,
    derive_key_scrypt,
    generate_salt,
)
from crypt_core.utils import (
    package,
    unpack,
    load_file,
    save_file,
    KDF_PBKDF2,
    KDF_SCRYPT,
)


class DarkCipherGUI(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkCipher GUI")
        self.resize(700, 500)
        self.opened_file_path: str | None = None
        self._build_ui()

    # ---------------- UI ---------------- #

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

    # ---------------- Actions ---------------- #

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open file")
        if not path:
            return

        self.opened_file_path = path
        self.lbl_opened.setText(Path(path).name)

        try:
            data = load_file(path)
            try:
                self.input_text.setPlainText(data.decode("utf-8"))
            except UnicodeDecodeError:
                self.input_text.setPlainText(
                    f"<binary file opened: {Path(path).name}>")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def run_action(self):
        password = self.pw_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Missing Password",
                                "Please enter a password.")
            return

        encrypt_mode = self.encrypt_radio.isChecked()
        password_bytes = password.encode()

        try:
            if self.opened_file_path:
                data = load_file(self.opened_file_path)
                self._process_data(data, password_bytes, encrypt_mode)
            else:
                text = self.input_text.toPlainText().strip()
                if not text:
                    QMessageBox.warning(self, "No Input",
                                        "Enter text or open a file.")
                    return
                self._process_data(text.encode(), password_bytes, encrypt_mode)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ---------------- Crypto Logic ---------------- #

    def _derive_key(self, password: bytes, salt: bytes, kdf: int) -> bytes:
        if kdf == KDF_PBKDF2:
            return derive_key_pbkdf2(password, salt)
        elif kdf == KDF_SCRYPT:
            return derive_key_scrypt(password, salt)
        else:
            raise ValueError("Unsupported KDF")

    def _process_data(self, data: bytes, password: bytes, encrypt_mode: bool):
        if encrypt_mode:
            salt = generate_salt()
            kdf_id = KDF_PBKDF2  # GUI uses PBKDF2 by default
            key = self._derive_key(password, salt, kdf_id)

            aad = b"v1" + bytes([kdf_id])
            iv, ciphertext = encrypt(data, key, aad)

            blob = package(iv, salt, ciphertext, kdf_id)
            self.output_text.setPlainText(blob)

            QMessageBox.information(self, "Success", "Encryption successful.")

        else:
            try:
                blob = data.decode("utf-8")
                version, kdf_id, iv, salt, ciphertext = unpack(blob)

                aad = b"v1" + bytes([kdf_id])
                key = self._derive_key(password, salt, kdf_id)

                plaintext = decrypt(iv, ciphertext, key, aad)

                try:
                    self.output_text.setPlainText(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    self.output_text.setPlainText("<binary data decrypted>")

                QMessageBox.information(self, "Success",
                                        "Decryption successful.")

            except Exception as e:
                QMessageBox.critical(self, "Decryption Failed", str(e))

    # ---------------- Save ---------------- #

    def save_output(self):
        output = self.output_text.toPlainText().strip()
        if not output:
            QMessageBox.warning(self, "No Output", "Nothing to save.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save output")
        if not path:
            return

        try:
            save_file(path, output.encode("utf-8"))
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
