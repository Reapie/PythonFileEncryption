# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'filecrypt.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import os
import base64
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Ui_MainWindow(QtWidgets.QMainWindow):

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(397, 227)
        MainWindow.setAutoFillBackground(False)
        MainWindow.setFixedSize(MainWindow.size())
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.btnChooseFile = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseFile.setGeometry(QtCore.QRect(20, 20, 231, 31))
        self.btnChooseFile.setObjectName("btnChooseFile")
        self.txtFilePath = QtWidgets.QTextEdit(self.centralwidget)
        self.txtFilePath.setGeometry(QtCore.QRect(20, 70, 361, 31))
        self.txtFilePath.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.txtFilePath.setAutoFillBackground(True)
        self.txtFilePath.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.txtFilePath.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.txtFilePath.setReadOnly(True)
        self.txtFilePath.setObjectName("txtFilePath")
        self.btnEncrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btnEncrypt.setEnabled(False)
        self.btnEncrypt.setGeometry(QtCore.QRect(20, 170, 171, 31))
        self.btnEncrypt.setObjectName("btnEncrypt")
        self.btnDecrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btnDecrypt.setEnabled(False)
        self.btnDecrypt.setGeometry(QtCore.QRect(210, 170, 171, 31))
        self.btnDecrypt.setObjectName("btnDecrypt")
        self.cbDelete = QtWidgets.QCheckBox(self.centralwidget)
        self.cbDelete.setGeometry(QtCore.QRect(269, 20, 101, 31))
        self.cbDelete.setObjectName("cbDelete")
        self.txtPwd = QtWidgets.QTextEdit(self.centralwidget)
        self.txtPwd.setGeometry(QtCore.QRect(20, 120, 361, 31))
        self.txtPwd.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.txtPwd.setAutoFillBackground(True)
        self.txtPwd.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.txtPwd.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.txtPwd.setReadOnly(False)
        self.txtPwd.setObjectName("txtPwd")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.btnChooseFile.clicked.connect(self.choose_file)
        self.btnEncrypt.clicked.connect(self.encrypt)
        self.btnDecrypt.clicked.connect(self.decrypt)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Python File Cryptograpy"))
        self.btnChooseFile.setText(_translate("MainWindow", "Choose File"))
        self.txtFilePath.setPlaceholderText(_translate("MainWindow", "Filepath"))
        self.btnEncrypt.setText(_translate("MainWindow", "Encrypt"))
        self.btnDecrypt.setText(_translate("MainWindow", "Decrypt"))
        self.cbDelete.setText(_translate("MainWindow", "Delete Input File"))
        self.txtPwd.setPlaceholderText(_translate("MainWindow", "Password"))

    def choose_file(self):
        file = QtWidgets.QFileDialog.getOpenFileName(self, "Choose File")[0]
        self.txtFilePath.setText(file)
        self.btnEncrypt.setEnabled(True)
        if(file.endswith(".cry")):
            self.btnDecrypt.setEnabled(True)
        else:
            self.btnDecrypt.setEnabled(False)

    def success(self, file_in, mode: bool, file_out, deleted: bool):
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle("Success!")
        text = f'"{file_in}" was successfully {"encrypted" if mode else "decrypted"}.\nThe new File is "{file_out}" .'
        if deleted:
            text += "\nThe Input was deleted."
        msg.setText(text)
        msg.setIcon(QtWidgets.QMessageBox.Information)
        x = msg.exec_()

    def invalid_key(self):
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle("Invalid Key!")
        msg.setText("The Password does not match with the one the file was encrypted with!")
        self.txtPwd.clear()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        x = msg.exec_()
    
    def get_key(self):
        password = self.txtPwd.toPlainText()
        password = password.encode()
        salt = b"[R8b\x7f\xd2\xd1s\x975\x17\xd1\xd7\xf3\xdd\xd2"
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512(),
            length = 32,
            salt = salt,
            iterations = 100000,
            backend = default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def encrypt(self):
        input_file = self.txtFilePath.toPlainText()
        output_file = input_file + ".cry"
        with open(input_file, "rb") as f:
            data = f.read()
        fernet = Fernet(self.get_key())
        encrypted = fernet.encrypt(data)
        with open(output_file, "wb") as f:
            f.write(encrypted)
        if self.cbDelete.isChecked():
            os.remove(input_file)
        self.success(input_file, False, output_file, self.cbDelete.isChecked())

    def decrypt(self):
        input_file = self.txtFilePath.toPlainText()
        output_file = input_file[:-4]
        with open(input_file, 'rb') as f:
            data = f.read()
        fernet = Fernet(self.get_key())
        try:
            encrypted = fernet.decrypt(data)
        except:
            self.invalid_key()
            return
        with open(output_file, 'wb') as f:
            f.write(encrypted)
        if self.cbDelete.isChecked():
            os.remove(input_file)
        self.success(input_file, True, output_file, self.cbDelete.isChecked())


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())