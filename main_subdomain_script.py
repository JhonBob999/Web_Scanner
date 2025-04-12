from PyQt5.QtWidgets import QApplication, QMainWindow
from Python_Script.main_window_ui import Ui_MainWindow
from Ui_Logic.subdomain_scanner import SubdomainScanner
from Ui_Logic.dns_scanner import DnsScanner
from Ui_Logic.certificate_scanner import CertificateScanner  # Импортируем класс для окна certificateWindows

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.subdomainButton.clicked.connect(self.open_subdomain_scanner)
        self.ui.dnsButton.clicked.connect(self.open_dns_scanner)
        self.ui.CertificateButton.clicked.connect(self.open_certificate_scanner)  # Подключаем кнопку CertificateButton

    def open_subdomain_scanner(self):
        self.subdomain_window = SubdomainScanner()
        self.subdomain_window.show()

    def open_dns_scanner(self):
        self.dns_window = DnsScanner()
        self.dns_window.show()

    def open_certificate_scanner(self):
        """Открывает окно CertificateScanner."""
        self.certificate_window = CertificateScanner()
        self.certificate_window.show()

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
