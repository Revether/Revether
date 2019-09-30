from .logger import initiate_logger

import platform
import logging
import json
import os
from datetime import datetime

import ida_kernwin
import ida_idaapi

class Plugin(ida_idaapi.plugin_t):

    PLUGIN_NAME = 'Revether'
    PLUGIN_VERSION = '0.0.1'
    PLUGIN_AUTHORS = ['Ofek Shiffman', 'Asaf Zoler']

    # These are the things needed by the plugin_t to be initialized
    flags = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = 'A plugin that let\'s you collaborate with others on the same IDB'
    wanted_name = PLUGIN_NAME
    help = ''
    wanted_hotkey = ''

    def __init__(self):
        # This checks if we run from ida qt, which cannot work for this plugin
        if not ida_kernwin.is_idaq():
            raise RuntimeError("IDArling cannot be used in terminal mode")

        self._config = self._get_default_config()
        self._paths = self._get_plugin_paths()
        _current_time = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        _log_file_full_path = os.path.join(self._paths['plugin_log'],
                                           _current_time + '.txt')
        self._logger = initiate_logger(_log_file_full_path, 'RevetherLogger', self._config['logging_level'])

    @property
    def logger(self):
        return self._logger

    @property
    def paths(self):
        return self._paths

    @property
    def config(self):
        return self._config

    def _get_plugin_paths(self):
        if platform.system() == 'Windows':
            plugin_user_root_folder = 'C:\\Revether\\'
        elif platform.system() == 'Linux':
            plugin_user_root_folder = '~\\.Revether\\'

        if not os.path.exists(plugin_user_root_folder):
            os.makedirs(plugin_user_root_folder)

        if not os.path.exists(plugin_user_root_folder + 'idbs\\'):
            os.makedirs(plugin_user_root_folder + 'idbs\\')

        if not os.path.exists(plugin_user_root_folder + 'logs\\'):
            os.makedirs(plugin_user_root_folder + 'logs\\')

        return {
            'plugin_root': plugin_user_root_folder,
            'plugin_log': plugin_user_root_folder + 'logs\\',
            'plugin_idbs': plugin_user_root_folder + 'idbs\\',
        }

    def _get_default_config(self):
        return {
            'logging_level': logging.INFO,
        }

    def _print_banner(self):
        banner = '~ {} - {} - By {} ~'.format(self.PLUGIN_NAME,
                                              'v' + self.PLUGIN_VERSION,
                                              ' & '.join(self.PLUGIN_AUTHORS))
        self._logger.info('~' * len(banner))
        self._logger.info(banner)
        self._logger.info('~' * len(banner))

    def init(self):
        """
            This function is called when ida loads the plugin.
            Here we should initate all the modules
        """
        # Lots of inits will be here

        self._print_banner()
        self._logger.info('Plugin intialized successfully')
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _):
        """
            This function is called when IDA is running this plugin as a script.
            In this case we just want to not let ida do so
        """
        ida_kernwin.error('This plugin cannot be run as a script')
        return False

    def term(self):
        """
            This function is called on termination of the plugin.
            Here we should terminate all the modules
        """
        pass
