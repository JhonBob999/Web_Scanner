from PyQt5.QtWidgets import QDialog, QMessageBox, QFileDialog, QTreeWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor
import os, json, time
from Python_Script.subdomain_Scanner_ui import Ui_Dialog
from Utils.subdomain_utils import validate_inputs, clear_logs, find_and_check_subdomains, generate_random_values, save_logs_to_file, load_json_to_tree, filter_and_structure_logs

class SubdomainScannerWorker(QThread):
    log_signal = pyqtSignal(str, str)  # Для передачи сообщений в логи с цветом
    progress_signal = pyqtSignal(int)  # Для обновления прогресса

    def __init__(self, domain, request_count, timeout, interval, show_requests, output_folder):
        super().__init__()
        self.domain = domain
        self.request_count = request_count
        self.timeout = timeout
        self.interval = interval
        self.show_requests = show_requests
        self.output_folder = output_folder
        self.running = True

    def run(self):
        try:
            for message, color in find_and_check_subdomains(
                self.domain, self.request_count, self.timeout, self.interval, 
                self.show_requests, self.output_folder, 
                progress_callback=self.update_progress
            ):
                if not self.running:
                    break
                self.log_signal.emit(message, color)

        except Exception as e:
            self.log_signal.emit(f"Ошибка: {e}", "red")

    def stop(self):
        """Прерывает выполнение сканирования."""
        self.running = False

    def update_progress(self, progress):
        """Передает прогресс выполнения через сигнал."""
        self.progress_signal.emit(progress)

class SubdomainScanner(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.subdomain_worker = None

        # Связывание кнопок с действиями
        self.ui.pushButtonScan.clicked.connect(self.start_scan)
        self.ui.pushButtonStop.clicked.connect(self.stop_scan)
        self.ui.pushButtonClearLogs.clicked.connect(self.clear_logs)
        self.ui.pushButtonSaveFormat.clicked.connect(self.save_logs)
        self.ui.pushButtonExportJson.clicked.connect(self.load_json_to_tree_widget)

        # Связывание чекбоксов с функцией
        self.ui.checkBoxSneakyAttack.stateChanged.connect(self.apply_attack_settings)
        self.ui.checkBoxModerateAttack.stateChanged.connect(self.apply_attack_settings)
        self.ui.checkBoxAggressiveAttack.stateChanged.connect(self.apply_attack_settings)

    def apply_attack_settings(self):
        """Применяет настройки атаки в зависимости от выбранного чекбокса."""
        try:
            if self.ui.checkBoxSneakyAttack.isChecked():
                values = generate_random_values("sneaky")
            elif self.ui.checkBoxModerateAttack.isChecked():
                values = generate_random_values("moderate")
            elif self.ui.checkBoxAggressiveAttack.isChecked():
                values = generate_random_values("aggressive")
            else:
                return

            # Устанавливаем значения в поля
            self.ui.lineEditRequestCount.setText(str(values["request_count"]))
            self.ui.lineEditTimeout.setText(str(values["timeout"]))
            self.ui.lineEditInterval.setText(str(values["interval"]))
            self.ui.lineEditRequestLimit.setText(str(values["request_limit"]))
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Ошибка применения настроек: {e}")

    def start_scan(self):
        # Получение пользовательских данных
        domain = self.ui.lineEditDomain.text().strip()
        output_folder = self.ui.lineEditFileName.text().strip()
        try:
            request_count = int(self.ui.lineEditRequestCount.text().strip())
            timeout = int(self.ui.lineEditTimeout.text().strip())
            interval = int(self.ui.lineEditInterval.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Параметры должны быть числовыми!")
            return

        show_requests = self.ui.checkBoxShowRequests.isChecked()

        try:
            validate_inputs(domain, request_count, timeout, interval, output_folder)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return

        # Очистка логов и запуск потока поддоменов
        self.ui.plainTextEditLogs.clear()
        self.subdomain_worker = SubdomainScannerWorker(
            domain, request_count, timeout, interval, show_requests, output_folder
        )
        self.subdomain_worker.log_signal.connect(self.update_logs)
        self.subdomain_worker.progress_signal.connect(self.update_progress_bar)
        self.subdomain_worker.start()

    def save_logs(self):
        """Сохраняет логи в структурированном формате."""
        # Получаем имя файла из lineEditFileName
        file_name = self.ui.lineEditFileName.text().strip()
        if not file_name:
           QMessageBox.warning(self, "Ошибка", "Укажите имя файла для сохранения логов.")
           return

        # Получаем данные из plainTextEditLogs
        logs = self.ui.plainTextEditLogs.toPlainText()
        if not logs.strip():
           QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения.")
           return

        # Структурируем данные
        structured_logs = filter_and_structure_logs(logs.splitlines())
        
        # Type format
        format_type = "json"

        try:
            # Сохраняем данные в JSON формате
            save_logs_to_file(structured_logs, file_name, format_type)
            QMessageBox.information(self, "Успех", f"Логи сохранены в файл: {file_name}.{format_type}")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить логи: {e}")


    def stop_scan(self):
        if self.subdomain_worker and self.subdomain_worker.isRunning():
            self.subdomain_worker.stop()
            self.subdomain_worker.wait()
            QMessageBox.information(self, "Информация", "Сканирование остановлено и сохранено.")

    def clear_logs(self):
        clear_logs(self.ui.plainTextEditLogs)

    def update_logs(self, message, color):
        """Обновление логов с цветами."""
        formatted_message = f'<span style="color:{color};">{message}</span><br>'
        self.ui.plainTextEditLogs.append(formatted_message)

    def update_progress_bar(self, progress):
        """Обновление прогресс-бара."""
        self.ui.progressBarScan.setValue(progress)

####### LOAD JSON AND TREE WIDGET VIEW ###############

    def load_json_to_tree_widget(self):
        """Загружает JSON-файл и отображает его в TreeWidget."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Выбрать JSON файл", "", "JSON Files (*.json)")

        if not file_path:
            return

        try:
            tree_data = load_json_to_tree(file_path)
            self.ui.treeWidgetJson.clear()
            self.populate_tree_widget(self.ui.treeWidgetJson, tree_data)
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))

####### FILL TREE WIDGET WITH DATA ###############
    
    def populate_tree_widget(self, tree_widget, data):
        """Заполняет TreeWidget данными с цветами."""
        def add_items(parent_item, children):
            for child in children:
                if isinstance(child, dict):
                    # Создаём узел для текущего элемента
                    item = QTreeWidgetItem([child.get("name", ""), child.get("value", "")])
                    item.setForeground(0, QBrush(QColor("green")))  # Зелёный для других узлов

                    parent_item.addChild(item)
                    # Рекурсивно обрабатываем вложенные узлы
                    if "children" in child and isinstance(child["children"], list):
                        add_items(item, child["children"])

        # Обрабатываем корневые узлы
        for root in data:
            root_item = QTreeWidgetItem([root.get("name", ""), root.get("value", "")])
            root_item.setForeground(0, QBrush(QColor("purple")))  # Фиолетовый для корневого узла
            tree_widget.addTopLevelItem(root_item)
            if "children" in root and isinstance(root["children"], list):
                add_items(root_item, root["children"])



####### NOT USABLE NOT USABLE NOT USABLE ###############

    def export_logs_to_file(self):
        """Экспортирует логи в файл с фиксированным путём."""
        # Получаем данные из plainTextEditLogs
        logs = self.ui.plainTextEditLogs.toPlainText()
        if not logs.strip():
            QMessageBox.warning(self, "Ошибка", "Нет данных для экспорта.")
            return

        # Структурируем данные
        structured_logs = filter_and_structure_logs(logs.splitlines())

        # Устанавливаем фиксированный путь для сохранения файлов
        base_path = "/home/kali/Desktop/Python/Qt5_Designer/Json_Output"
        os.makedirs(base_path, exist_ok=True)

        # Формируем имя файла
        file_name = f"exported_logs_{time.strftime('%Y%m%d_%H%M%S')}.json"
        full_path = os.path.join(base_path, file_name)

        try:
            # Сохраняем данные в JSON формате
            with open(full_path, "w", encoding="utf-8") as file:
                json.dump(structured_logs, file, indent=4, ensure_ascii=False)
            QMessageBox.information(self, "Успех", f"Логи экспортированы в файл: {full_path}")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Ошибка при экспорте логов: {e}")

