import ida_kernwin
import ida_loader
import io
import hashlib
import os

from functools import partial
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QProgressDialog, QMessageBox

from ..utils.unicoder import Unicoder
from ..net.packets import RequestType


class SaveMenuAction(object):
    def __init__(self, plugin, handler):
        self._plugin = plugin
        self._menu = 'File/Save'
        self._text = 'Save file to server'
        self._tooltip = 'Uploads an IDB to the server'
        self._action_name = 'revether:save'
        self._handler = handler

    def install(self):
        action_descriptor = ida_kernwin.action_desc_t(
            self._action_name,
            self._text,
            self._handler,
            None,
            self._tooltip,
            -1,  # This is for icon, maybe later we'll have one
        )

        # Register the action in the ida kernel
        if not ida_kernwin.register_action(action_descriptor):
            raise RuntimeError('Failed to register the save to server action')

        # Attach the action to the wanted menu
        if not ida_kernwin.attach_action_to_menu(self._menu, self._action_name, ida_kernwin.SETMENU_APP):
            raise RuntimeError('Failed to intall the save to menu action')

        return True

    def uninstall(self):
        if not ida_kernwin.detach_action_from_menu(self._menu, self._action_name):
            self._plugin.logger.error('Failed to detach action save to server from menu')
            return False

        if not ida_kernwin.unregister_action(self._action_name):
            self._plugin.logger.error('Failed to unregister action save to server')
            return False

        return True


class SaveMenuActionHandler(ida_kernwin.action_handler_t):

    CHUNK_SIZE = 16384

    @staticmethod
    def _update_progress(progress, count, total):
        """
            Called when a progress has been made
        """
        progress.setRange(0, total)
        progress.setValue(count)

    def __init__(self, plugin):
        super(SaveMenuActionHandler, self).__init__()
        self._plugin = plugin

    def update(self, context=None):
        """
            Update the status of the action according to if we're connected to a server or not
        """
        if self._plugin.network_manager.connected:
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE

    def activate(self, context):
        """
            Called when the action has been clicked by the user
        """
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        ida_loader.save_database(idb_path, 0)

        with open(idb_path, 'rb') as input_file:
            idb_data = input_file.read()

        # Create the progress bar
        progress_bar = QProgressDialog(
            'Uploading your idb to the server, please wait...',
            'Cancel',
            0,
            1
        )
        progress_bar.setCancelButton(None)  # Remove the cancel button so the user won't be able to cancel
        progress_bar.setModal(True)  # Set this as a modal dialog
        window_flags = progress_bar.windowFlags()  # Disable close button
        progress_bar.setWindowFlags(window_flags & ~Qt.WindowCloseButtonHint)
        progress_bar.setWindowTitle('Upload to server')

        idb_data_len = len(idb_data)
        idb_data_stream = io.BytesIO(idb_data)
        idb_hash = hashlib.sha1(idb_data).digest()
        total_packets = (idb_data_len / self.CHUNK_SIZE)
        total_packets = total_packets + 1 if idb_data_len % self.CHUNK_SIZE != 0 else total_packets  # correction
        # Build the initiation packet here
        self._plugin.network_manager.send_request(
            RequestType.UPLOAD_IDB_START,
            idb_name=Unicoder.decode(os.path.split(idb_path)[-1]),
            idb_hash=idb_hash,
            idb_size=idb_data_len,
        )

        self._plugin.logger.debug('starting to send packets')
        self._plugin.logger.debug('The amount of packets needed to be sent: {}'.format(total_packets))

        def _on_error(progress_bar):
            progress_bar.close()
            success = QMessageBox()
            success.setIcon(QMessageBox.Critical)
            success.setStandardButtons(QMessageBox.Ok)
            success.setText("Could not upload IDB")
            success.setWindowTitle("Upload to server FAILED")
            success.exec_()

        for i in range(total_packets):
            current_pkt_data = idb_data_stream.read(self.CHUNK_SIZE)

            self._plugin.network_manager.send_request(
                RequestType.IDB_CHUNK,
                callback=partial(self._update_progress, progress_bar, i, total_packets),
                err_callback=partial(_on_error, progress_bar),
                data=current_pkt_data,
            )

        self._plugin.logger.debug('finished sending packets')
        self._plugin.logger.debug('sending upload_end')

        def _close_window(progress_bar):
            SaveMenuActionHandler._update_progress(progress_bar, 100, 100)
            progress_bar.close()
            success = QMessageBox()
            success.setIcon(QMessageBox.Information)
            success.setStandardButtons(QMessageBox.Ok)
            success.setText("IDB successfully uploaded!")
            success.setWindowTitle("Upload to server")
            success.exec_()

        self._plugin.network_manager.send_request(
            RequestType.IDB_END,
            callback=partial(_close_window, progress_bar)
        )

        progress_bar.show()
