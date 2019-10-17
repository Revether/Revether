from PyQt5.QtWidgets import qApp, QMainWindow

from ui.save import SaveMenuAction, SaveMenuActionHandler
from status_widget import StatusWidget


class Ui(object):
    def __init__(self, plugin):
        plugin.logger.debug('Initating the plugin UI')

        # we need to find the ida main window in order to add
        # widgets to it
        for widget in qApp.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                self._window = widget
                break

        self._status_widget = StatusWidget(plugin)
        self._status_widget.add_widget(self._window)

        self._save_action_handler = SaveMenuActionHandler(plugin)
        self._save_action = SaveMenuAction(plugin, self._save_action_handler)
        self._save_action.install()

    def update_all(self):
        self._status_widget.update()
        self._save_action_handler.update()
