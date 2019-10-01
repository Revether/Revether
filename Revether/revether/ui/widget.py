from PyQt5.QtCore import Qt, QTimer, QSize, QPoint, QRect
from PyQt5.QtWidgets import QWidget, QLabel
from PyQt5.QtGui import QPainter, QPixmap, QRegion

class StatusWidget(QWidget):
    """
        This is the widget the will be displayed in the bottom right
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

        # Create a custom right-click menu context
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._handle_right_click)

        # Update the widget every one second
        self._update_timer = QTimer()
        self._update_timer.setInterval(1000)
        self._update_timer.timeout.connect(self.update)

    def _handle_right_click(self, point):
        self._plugin.logger.debug('Right clicked on the status widget')

    def upadte(self):
        try:
            if self._plugin.network_manager.conncted:
                color = 'green'
                text = 'Connected'
            else:
                color = 'red'
                text = 'Disconnected'
        except:
            self._plugin.logger.warning('The network manager does not exist')
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
        self.upadte()

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