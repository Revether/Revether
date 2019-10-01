from .logger import initiate_logger
from .ui.ui import Ui

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

        # We need this config incase the loading of the config from the
        # configurations file down in the init function will fail
        # also for iniating the basic logger for this :)
        self._config = self.get_default_config()
        _current_time = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        _log_file_full_path = os.path.join(self.get_plugin_folder()['logs'],
                                           _current_time + '.txt')
        self._logger = initiate_logger(_log_file_full_path, 'RevetherLogger', self._config['logging_level'])
        self._ui = Ui(self)

    @property
    def logger(self):
        return self._logger

    @property
    def config(self):
        return self._config

    @staticmethod
    def get_plugin_folder():
        """
            Returns a dict with all the relevant paths for the plugin
            You can access them using the values root, logs or idbs
        """
        # TODO: Change this to appdate in default and make this configurable
        if platform.system() == 'Windows':
            plugin_user_root_folder = os.path.join('C:', os.sep, 'Revether')
        elif platform.system() == 'Linux':
            plugin_user_root_folder = os.path.join('~', 'Revether')

        if not os.path.exists(plugin_user_root_folder):
            os.makedirs(plugin_user_root_folder)

        if not os.path.exists(os.path.join(plugin_user_root_folder, 'idbs')):
            os.makedirs(os.path.join(plugin_user_root_folder, 'idbs'))

        if not os.path.exists(os.path.join(plugin_user_root_folder, 'logs')):
            os.makedirs(os.path.join(plugin_user_root_folder, 'logs'))

        return {
            'root': plugin_user_root_folder,
            'logs': os.path.join(plugin_user_root_folder, 'logs'),
            'idbs': os.path.join(plugin_user_root_folder, 'idbs'),
        }

    @staticmethod
    def get_config_file_path():
        """
            Returns the path to the config file
        """
        return os.path.join(Plugin.get_plugin_folder()['root'], 'config.json')

    @staticmethod
    def get_default_config():
        """
            Returns the default config for initializations
        """
        return {
            'logging_level': logging.INFO,
            'server_address': '0.0.0.0',
            'server_port': '12345',
        }

    def _print_banner(self):
        banner = '~ {} - {} - By {} ~'.format(self.PLUGIN_NAME,
                                              'v' + self.PLUGIN_VERSION,
                                              ' & '.join(self.PLUGIN_AUTHORS))
        self._logger.info('~' * len(banner))
        self._logger.info(banner)
        self._logger.info('~' * len(banner))

    def _generate_config_if_not_existent(self, cfg_file):
        with open(cfg_file, 'wb') as f:
            pretty_config = json.dumps(self.get_default_config(),
                                       indent=4, separators=(',', ': '))
            f.write(pretty_config)
        self._logger.info('Created log file: {}'.format(cfg_file))

    def load_config(self):
        cfg_file = self.get_config_file_path()
        if not os.path.isfile(cfg_file):
            self._generate_config_if_not_existent(cfg_file)

        with open(cfg_file, 'rb') as f:
            try:
                self._config.update(json.loads(f.read()))
            except ValueError:
                self._logger.warning('Was not able to load the config file')
                return
            self._logger.setLevel(self._config['logging_level'])

    def save_config(self):
        cfg_file = self.get_config_file_path()

        with open(cfg_file, 'wb') as f:
            pretty_config = json.dumps(self.config,
                                       indent=4, separators=(',', ': '))
            f.write(pretty_config)

    def init(self):
        """
            This function is called when ida loads the plugin.
            Here we should initate all the modules
        """
        # Lots of inits will be here
        try:
            self.load_config()
            self._ui.update_all()
        except Exception as e:
            self._logger.error('Failed to initazlie the plugin')
            self._logger.exception(e)
            return ida_idaapi.PLUGIN_SKIP

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
