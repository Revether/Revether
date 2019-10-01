from idb_hooks import *

import logging

class Core(object):
    def __init__(self, plugin):
        super(Core, self).__init__()
        self._plugin = plugin

    def install_hooks(self):
        self._idb_hooks = IDBHooks(self._plugin.network_manager)

        self._plugin.logger.debug('Installing hooks')
        self._idb_hooks.hook()

    def uninstall_hooks(self):
        self._plugin.logger.debug('Uninstalling hooks')
        self._idb_hooks.unhook()