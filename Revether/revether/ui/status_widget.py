from functools import partial

from PyQt5.QtCore import Qt, QTimer, QSize, QPoint, QRect
from PyQt5.QtWidgets import QWidget, QLabel, QMenu, QAction, QDialog, QVBoxLayout, QLineEdit, QHBoxLayout, QPushButton
from PyQt5.QtGui import QPainter, QPixmap, QRegion

class SettingsDialog(QDialog):
    def __init__(self, plugin):
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        self._plugin.logger.debug('Showing settings dialog')
        self.setWindowTitle('Settings')
        self.resize(150,100)

        dialog_layout = QVBoxLayout(self)

        # The server address line
        self._server_address_label = QLabel('Server Address:')
        dialog_layout.addWidget(self._server_address_label)
        self._server_address_input_box = QLineEdit()
        self._server_address_input_box.setPlaceholderText('0.0.0.0')
        dialog_layout.addWidget(self._server_address_input_box)

        # The server port line
        self._server_port_label = QLabel('Server Port:')
        dialog_layout.addWidget(self._server_port_label)
        self._server_port_input_box = QLineEdit()
        self._server_port_input_box.setPlaceholderText('12345')
        dialog_layout.addWidget(self._server_port_input_box)

        # Check if the server is already configured
        if self._plugin.config['server_address'] != self._plugin.get_default_config()['server_address']:
            self._server_address_input_box.setText(self._plugin.config['server_address'])
        if self._plugin.config['server_port'] != self._plugin.get_default_config()['server_port']:
            self._server_port_input_box.setText(str(self._plugin.config['server_port']))

        # Add dialog buttons
        bottom_buttons = QWidget(self)
        bottom_layout = QHBoxLayout(bottom_buttons)
        self._save_button = QPushButton('Save')
        self._save_button.clicked.connect(self.accept)
        bottom_layout.addWidget(self._save_button)
        self._cancel_button = QPushButton('Cancel')
        self._cancel_button.clicked.connect(self.reject)
        bottom_layout.addWidget(self._cancel_button)
        dialog_layout.addWidget(bottom_buttons)

    def get_result(self):
        """
            Returns the result of the dialog
        """
        return {
            'server_address': self._server_address_input_box.text(),
            'server_port': int(self._server_port_input_box.text())
        }


class StatusWidget(QWidget):
    """
        This is the widget that will be displayed in the bottom right
        of the ida window and will update the status of connection
    """

    @staticmethod
    def generate_label():
        widget = QLabel()
        widget.setAutoFillBackground(False)
        widget.setAttribute(Qt.WA_PaintOnScreen)
        widget.setAttribute(Qt.WA_TranslucentBackground)
        return widget

    def __init__(self, plugin):
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        self._server_status_widget = self.generate_label()

        # Update the widget every one second
        self._update_timer = QTimer()
        self._update_timer.setInterval(1000)
        self._update_timer.timeout.connect(self.update)

        # Create a custom right-click menu context
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._handle_right_click)

    def _handle_server_save(self, dialog):
        self._plugin.logger.debug('The saved info is: {}'.format(dialog.get_result()))
        self._plugin.config['server_address'] = dialog.get_result()['server_address']
        self._plugin.config['server_port'] = dialog.get_result()['server_port']
        self._plugin.save_config()

    def _handle_right_click(self, point):
        menu = QMenu(self)

        # Connect to configured server
        if not self._plugin.network_manager.connected:
            connect_action = QAction('Connect', menu)
            def connect():
                self._plugin.logger.debug('Connect handler called')
                self._plugin.network_manager.connect(
                    self._plugin.config['server_address'],
                    self._plugin.config['server_port']
                )
                self.update()

            connect_action.triggered.connect(connect)
            menu.addAction(connect_action)
        else:
            disconnect_action = QAction('Disconnect', menu)
            def disconnect():
                self._plugin.logger.debug('Disconnect handler called')
                self._plugin.network_manager.send('disconnecting')
                self._plugin.network_manager.disconnect()
                self.update()

            disconnect_action.triggered.connect(disconnect)
            menu.addAction(disconnect_action)


        menu.addSeparator()

        # Settings button
        settings_action = QAction('Settings', menu)
        def settings():
            self._plugin.logger.debug('Settings handler called')
            dialog = SettingsDialog(self._plugin)
            dialog.accepted.connect(partial(self._handle_server_save, dialog))
            dialog.exec_()

        settings_action.triggered.connect(settings)
        menu.addAction(settings_action)

        menu.exec_(self.mapToGlobal(point))

    def update(self):
        if self._plugin.network_manager.connected:
            color = 'green'
            text = 'Connected'
        else:
            color = 'red'
            text = 'Disconnected'

        self._server_status_widget.setText(
            '<span style="color:{};">{}</span>'.format(color, text)
        )
        self._server_status_widget.adjustSize()

        self.updateGeometry()

    def add_widget(self, ida_window):
        self._plugin.logger.debug('Adding the status bar widget')
        ida_window.statusBar().addPermanentWidget(self)
        self._update_timer.start()
        self._plugin.logger.debug('Started timer')
        self.update()

    def remove_widget(self, ida_window):
        self._plugin.logger.debug('Removing the status bar widget')
        ida_window.statusBar().removeWidget(self)
        self._update_timer.stop()

    # QWidget functions we need to implement:
    def sizeHint(self):
        """
            called on internal qt size calculations
        """
        width = 5 + self._server_status_widget.sizeHint().width()
        return QSize(width, self._server_status_widget.sizeHint().height())

    def paintEvent(self, event):
        """
            Called when the widget is being painted
        """
        pixel_ratio = self.devicePixelRatioF()
        pixmap = QPixmap(self.width() * pixel_ratio, self.height() * pixel_ratio)
        pixmap.setDevicePixelRatio(pixel_ratio)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)

        # The server text region to be drawn
        server_region = QRegion(
            QRect(QPoint(0, 0), self._server_status_widget.sizeHint())
        )
        self._server_status_widget.render(painter, QPoint(0, 0), server_region)

        painter.end()

        painter = QPainter(self)
        painter.drawPixmap(event.rect(), pixmap, pixmap.rect())
        painter.end()
