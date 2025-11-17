#!/usr/bin/python3
#
# Версия 2.0    27.10.2025
#-----------------------------------------------------------------------------------------------------------------------------

import os, json
from datetime import datetime as dt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QWidget, QFrame, QDialog, QListWidget, QListWidgetItem,
                             QPushButton, QLabel, QSpacerItem, QLineEdit, QComboBox, QSplitter, QTextEdit)
import config_style as cs
import common_func as func


class SelectAction(QWidget):
    """Класс для выбора режима: экспорт/импорт. Номер в стеке 0."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        text1 = "<b><font color='green' size='+2'>Конвертация конфигурации сторонних вендоров<br>в формат UserGate NGFW</font></b>"
        text2 = f"Экспорт конфигурации из конфигурационных файлов <b>Blue Coat</b>, <b>Cisco ASA</b>, <b>Cisco FPR</b>, <b>Check Point</b>, \
<b>Fortigate</b>, <b>Huawei</b>, <b>Kerio</b>, <b>MikroTik</b>, <b>PaloAlto</b> и сохранение её в формате UserGate в каталоге <b>{self.parent.base_ug_path}</b> \
текущей директории. После экспорта вы можете просмотреть результат и изменить содержимое файлов в соответствии с вашими потребностями."
        label1 = QLabel(text1)
        label1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label2 = QLabel(text2)
        label2.setWordWrap(True)
        
        btn_font = QFont("SansSerif", pointSize=9, weight=600)

        self.btn_export = QPushButton("Экспорт конфигурации")
        self.btn_export.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_export.setFont(btn_font)
        self.btn_export.setFixedWidth(230)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.set_export_page)

        btn_exit = QPushButton("Выход")
        btn_exit.setStyleSheet('color: darkred; background: white;')
        btn_exit.setFont(btn_font)
        btn_exit.setFixedWidth(100)
        btn_exit.clicked.connect(self.parent.close)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)

        vbox = QVBoxLayout()
        vbox.addWidget(label1)
        vbox.addSpacerItem(QSpacerItem(5, 10))
        vbox.addWidget(label2)
        vbox.addWidget(self.btn_export, alignment=Qt.AlignmentFlag.AlignHCenter)
        vbox.addSpacerItem(QSpacerItem(5, 4))
        vbox.addWidget(line)
        vbox.addWidget(btn_exit, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.setLayout(vbox)

        self.parent.stacklayout.currentChanged.connect(self.resize_window)

    def resize_window(self, e):
        if e == 0:
            self.parent.resize(200, 227)

    def set_export_page(self):
        """Переходим на страницу экспорта конфигурации. Номер в стеке 1."""
        self.parent.stacklayout.setCurrentIndex(1)

    def enable_buttons(self):
        self.btn_export.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export.setEnabled(True)


class SelectExportMode(QWidget):
    """
    Класс для конвертации выбранного вендора. Номер в стеке 1.
    1. Выбираем вендора, выбираем/создаём каталог с нужной конфигурацией стороннего вендора для экспорта.
    2. Выбираем/создаём каталог куда будем писать конвертированную в формат UG NGFW конфигурацию.
    3. Конвертируем конфигурацию в формат UG NGFW.
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_point = ''
        self.vendor_base_path = ''
        self.vendor_current_path = ''
        self.thread = None
        self.log_list = QTextEdit()
        self.log_list.setReadOnly(True)
        self.log_list.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        
        self.title = QLabel("<b><font color='green' size='+2'>Конвертация сторонней конфигурации в формат UserGate</font></b>")
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title.setFixedHeight(22)

        frame_nodeinfo = QFrame()
        frame_nodeinfo.setFixedHeight(20)
        frame_nodeinfo.setStyleSheet(
            'background-color: #2690c8; '
            'color: white; font-size: 12px; font-weight: bold; '
            'border-radius: 4px; padding: 0px; margin: 0px;'
        )
        self.label_node_name = QLabel()
        self.label_node_name.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.label_version = QLabel()
        self.label_version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_config_directory = QLabel()
        self.label_config_directory.setAlignment(Qt.AlignmentFlag.AlignRight)
        hbox_nodeinfo = QHBoxLayout()
        hbox_nodeinfo.addWidget(self.label_node_name)
        hbox_nodeinfo.addWidget(self.label_version)
        hbox_nodeinfo.addWidget(self.label_config_directory)
        hbox_nodeinfo.setContentsMargins(0, 2, 0, 2)
        frame_nodeinfo.setLayout(hbox_nodeinfo)

        list_item_font = QFont("Serif", pointSize=14, weight=600)
        vendors = [
            'Blue Coat', 'Cisco ASA', 'Cisco FPR', 'Check Point', 'Check Point (old)', 'Fortigate',
            'Huawei', 'Kerio', 'MikroTik', 'PaloAlto']
        self.vendor_list = QListWidget()
        self.vendor_list.setMaximumWidth(180)
        for vendor in vendors:
            new_item = QListWidgetItem()
            new_item.setText(vendor)
            new_item.setForeground(Qt.GlobalColor.darkBlue)
            new_item.setFont(list_item_font)
            self.vendor_list.addItem(new_item)
        self.vendor_list.currentTextChanged.connect(self.get_selected_item)

        splitter = QSplitter()
        splitter.addWidget(self.vendor_list)
        splitter.addWidget(self.log_list)
        hbox_splitter = QHBoxLayout()
        hbox_splitter.addWidget(splitter)

        self.btn1 = QPushButton("Назад")
        self.btn1.setFixedWidth(100)
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2 = QPushButton('Экспорт')
        self.btn2.setFixedWidth(190)
        self.btn2.clicked.connect(self.export_selected_vendor)
        self.btn3 = QPushButton("Сохранить лог")
        self.btn3.setFixedWidth(100)
        self.btn3.clicked.connect(lambda: self._save_logs('export.log'))

        hbox_btn = QHBoxLayout()
        hbox_btn.addWidget(self.btn1)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn2)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn3)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.title)
        vbox.addWidget(frame_nodeinfo)
        vbox.addLayout(hbox_splitter)
        vbox.addSpacerItem(QSpacerItem(1, 3))
        vbox.addLayout(hbox_btn)
        self.setLayout(vbox)

        self.disable_buttons()
        self.parent.stacklayout.currentChanged.connect(self.init_export_widget)


    def disable_buttons(self):
        self.btn1.setStyleSheet('color: gray; background: gainsboro;')
        self.btn1.setEnabled(False)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)


    def enable_buttons(self):
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.setEnabled(True)
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)


    def init_export_widget(self, e):
        """
        При открытии этой вкладки меняем размер окна и активируем кнопки.
        """
        if e == 1:
            self.parent.resize(900, 700)
            self.enable_buttons()
            self.vendor_list.setCurrentRow(1)
            self.vendor_list.setCurrentRow(0)


    def get_selected_item(self, selected_item):
        """
        Получаем выбранный пункт меню и устанавливаем путь к базовому разделу конфигураций вендора.
        """
        self.selected_point = selected_item
        self.vendor_base_path = self.parent.get_vendor_base_path(selected_item)
        self.log_list.clear()
        match self.selected_point:
            case 'Check Point (old)':
                message = f'{"Конвертация конфигурации CheckPoint версии 77.30":>100}'
                self.add_item_log(message, color='BLUE')
                message = (
                    '\n   Для конвертации необходимо с устройства CheckPoint выгрузить файлы "objects_5_0.C"\n'
                    '   и "rulebases_5_0.fws" из /opt/CPsuite-R77/fw1/conf/"hostname" и скопировать их в каталог\n'
                    '   "data_checkpoint_old/<имя_заданное_вами_для_данного_устройства>"\n'
                )
                self.add_item_log(message)
                message = (
                    '   Переносятся настройки:\n'
                    '       1. Списки IP-адресов\n'
                    '       2. Списки групп IP-адресов\n'
                    '       3. Сетевые сервисы\n'
                    '       4. Группы сетевых сервисов\n'
                    '       5. Шлюзы\n'
                    '       6. Статические маршруты\n'
                    '       7. Правила межсетевого экрана\n'
                )
                self.add_item_log(message, color='BLUE')
            case 'Check Point':
                message = f'{"Конвертация конфигурации CheckPoint версии 80.40 и выше":>100}'
                self.add_item_log(message, color='BLUE')
            case _:
                message = f'Конвертация конфигурации {self.selected_point}'
                self.add_item_log(f'{message:>100}', color='BLUE')


    def export_selected_vendor(self):
        """
        Проверяем что выбран вендор. Если выбран, запускаем экспорт выбранного раздела конфигурации.
        """
        if self.vendor_base_path:
            dialog = SelectConfigDirectories(self.parent, self.vendor_base_path, self.selected_point)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.vendor_current_path = dialog.vendor_current_path
                self.label_node_name.setText(f'  IN:  {self.vendor_current_path}')
                self.label_version.setText(f'{self.selected_point}')
                self.label_config_directory.setText(f'OUT:  {self.parent.get_ug_config_path()}   ')
            else:
                return

            self.disable_buttons()
            self.log_list.clear()
            if self.thread is None:
                match self.selected_point:
                    case 'Blue Coat':
                        import export_blue_coat_config as bluecoat
                        self.thread = bluecoat.ConvertBlueCoatConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Cisco ASA':
                        import export_cisco_asa_config as asa
                        self.thread = asa.ConvertCiscoASAConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Cisco FPR':
                        import export_cisco_fpr_config as fpr
                        self.thread = fpr.ConvertCiscoFPRConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Check Point':
                        import export_checkpoint_config as cp
                        err, msg = self._create_checkpoint_datajson()
                        if err:
                            self.add_item_log(msg, color='RED')
                            self.enable_buttons()
                            self.btn3.setStyleSheet('color: darkred; background: white;')
                            self.btn3.setEnabled(True)
                            return
                        self.label_version.setText(f'{self.selected_point} - {msg}')
                        self.thread = cp.ConvertCheckPointConfig(self.vendor_current_path, self.parent.get_ug_config_path(), msg)
                    case 'Check Point (old)':
                        import export_checkpoint_old_config as cp_old
                        self.thread = cp_old.ConvertOldCheckPointConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Fortigate':
                        import export_fortigate_config as fg
                        self.thread = fg.ConvertFortigateConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Huawei':
                        import export_huawei_config as huawei
                        self.thread = huawei.ConvertHuaweiConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Kerio':
                        import export_kerio_config as kerio
                        self.thread = kerio.ConvertKerioConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'MikroTik':
                        import export_mikrotik_config as mikrotik
                        self.thread = mikrotik.ConvertMikrotikConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'PaloAlto':
                        import export_paloalto_config as paloalto
                        self.thread = paloalto.ConvertPaloAltoConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')
        else:
            func.message_inform(self, "Внимание!", "Вы не выбрали раздел для экспорта.")

    def _create_checkpoint_datajson(self):
        """
        Преобразуем файлы конфигурации CheckPoint в читабельный вид и пишем их в каталог data_json
        и переходим на страницу выбора SecureGateway.
        """
        if os.path.exists(os.path.join(self.vendor_current_path, 'index.json')):
            if os.path.exists(os.path.join(self.vendor_current_path, 'config_cp.txt')):
                cp_data_json = os.path.join(self.vendor_current_path, 'data_json')
                err, msg = func.create_dir(cp_data_json)
                if err:
                    return err, data
                files = os.listdir(self.vendor_current_path)
                for file_name in files:
                    if file_name.endswith('.json'):
                        try:
                            with open(os.path.join(self.vendor_current_path, file_name), 'r') as fh:
                                data = json.load(fh)
                            with open(os.path.join(cp_data_json, file_name), 'w') as fh:
                                json.dump(data, fh, indent=4, ensure_ascii=False)
                        except json.decoder.JSONDecodeError as err:
                            return 1, f'Ошибка парсинга файла конфигурации "{file_name}" [{err}].'
                        except UnicodeDecodeError as err:
                            return 1, f'Ошибка файла конфигурации "{file_name}" [{err}].'

                dialog = SelectSecureGateway(self.parent, cp_data_json)
                result = dialog.exec()
                if result == QDialog.DialogCode.Accepted:
                    return 0, dialog.sg_name
                else:
                    return 1, 'Конвертация конфигурации Check Point прервана пользователем.'
            else:
                return 1, f'Не найден файл конфигурации Check Point "config_cp.txt" в каталоге "{self.vendor_current_path}".'
        else:
            return 1, f'Не найдена конфигурация Check Point в каталоге "{self.vendor_current_path}".'


    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.vendor_current_path, f'{today:%Y-%m-%d_%M:%S}-{log_file}')
        text = self.log_list.document().toPlainText()
        with open(path_logfile, 'w') as fh:
            print(text, sep='\n', file=fh)
            fh.write('\n')
        func.message_inform(self, 'Сохранение лога', f'Лог сохранён в файл "{path_logfile}".')


    def run_page_0(self):
        """Возвращаемся на стартовое окно"""
        self.label_node_name.setText('')
        self.label_version.setText('')
        self.label_config_directory.setText('')
        self.log_list.clear()
        self.selected_point = ''
        self.vendor_base_path = ''
        self.vendor_current_path = ''
        self.parent.stacklayout.setCurrentIndex(0)


    def add_item_log(self, message, color='BLACK'):
        """Добавляем запись лога в log_list."""
        self.log_list.setTextColor(QColor(cs.color.get(color, 'RED')))
        self.log_list.append(message)


    def on_step_changed(self, msg):
        color, _, message = msg.partition('|')
        self.log_list.setTextColor(QColor(cs.color.get(color, 'RED')))
        self.log_list.append(message)
        if color in ('iORANGE', 'iGREEN', 'iRED'):
            func.message_inform(self, 'Внимание!', message)


    def on_finished(self):
        self.thread = None
        self.enable_buttons()
        self.btn3.setStyleSheet('color: darkred; background: white;')
        self.btn3.setEnabled(True)
        message = 'Для импорта полученной конфигурации на NGFW, DCFW или МС запустите ug_ngfw_converter.\n'
        self.add_item_log(message, color='LBLUE')


class SelectSecureGateway(QDialog):
    """Для CheckPoint. Диалоговое окно выбора Secure Gateway для конвертации"""
    def __init__(self, parent, cp_data_json):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Выбор Gateways policy package")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        self.setFixedHeight(200)
        self.sg_name = None

        title =QLabel("<b><font color='green'>Выберите Secure Gateway для конвертации.<br>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.sg_list = QListWidget()
        with open(os.path.join(cp_data_json, 'index.json'), 'r') as fh:
            data = json.load(fh)
        for item in data['policyPackages']:
            self.sg_list.addItem(item['packageName'])

        btn_enter = QPushButton("Ввод")
        btn_enter.setStyleSheet('color: forestgreen; background: white;')
        btn_enter.setFixedWidth(80)
        btn_enter.clicked.connect(self._send_accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(btn_enter)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(self.sg_list)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
        self.sg_list.currentTextChanged.connect(self.select_secure_gateway)

    def select_secure_gateway(self, item_name):
        self.sg_name = item_name
        
    def _send_accept(self):
        if self.sg_name:
            self.accept()


class SelectConfigDirectories(QDialog):
    """Диалоговое окно выбора каталога для с экспортируемой конфигурацией"""
    def __init__(self, parent, vendor_path, vendor):
        super().__init__(parent)
        self.main_window = parent
        self.vendor_base_path = vendor_path
        self.vendor_current_path = ''
        self.vendor = vendor
        self.setWindowTitle("Выбор каталогов с конфигурацией")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        with os.scandir(self.vendor_base_path) as fh:
            list_dir = [x.name for x in fh if x.is_dir()]
        self.vendor_directory = QComboBox()
        self.vendor_directory.addItems(sorted(list_dir))
        self.vendor_directory.setEditable(True)
#        self.setFixedHeight(170)
        vendor_text = f"<b><font size='+1' color='green'>Выберите каталог с конфигурацией {self.vendor}.</font></b><br> \
Если каталог не существует, введите имя нового каталога.<br> \
Он будет создан в текущей директории в каталоге<br><b>{self.vendor_base_path}</b>.<br> \
Затем поместите в него конфигурацию {self.vendor}."
        vendor_title = QLabel(vendor_text)
        vendor_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)

        list_ugdir = os.listdir(self.main_window.base_ug_path)
        self.ug_directory = QComboBox()
        self.ug_directory.addItems(sorted(list_ugdir))
        self.ug_directory.setEditable(True)
        ug_text = f"<b><font size='+1' color='green'>Выберите каталог для экспорта конфигурации.</font></b><br> \
Если каталог не существует, введите имя нового каталога.<br>Он будет создан в текущей директории в каталоге <b>{self.main_window.base_ug_path}</b>."
        ug_title = QLabel(ug_text)
        ug_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        btn_enter = QPushButton("Запустить конвертацию")
        btn_enter.setStyleSheet('color: steelblue; background: white;')
        btn_enter.setFixedWidth(180)
        btn_enter.clicked.connect(self._send_accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(btn_enter)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(vendor_title)
        layout.addWidget(self.vendor_directory)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addWidget(line)
        layout.addSpacerItem(QSpacerItem(0, 2))
        layout.addWidget(ug_title)
        layout.addWidget(self.ug_directory)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
    def _send_accept(self):
        if self.vendor_directory.currentText():
            self.vendor_current_path = os.path.join(self.vendor_base_path, self.vendor_directory.currentText())
            err, msg = func.create_dir(self.vendor_current_path, delete='no')
            if err:
                func.message_alert(self, msg, '')
            else:
                if self.ug_directory.currentText():
                    self.main_window.set_ug_config_path(self.ug_directory.currentText())
                    err, msg = func.create_dir(self.main_window.get_ug_config_path(), delete='no')
                    if err:
                        func.message_alert(self, msg, '')
                        self.main_window.del_ug_config_path()
                    else:
                        self.accept()


#---------------------------------------------------------------------------------------------------------------------------------
def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
