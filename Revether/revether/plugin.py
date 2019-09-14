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

    def init(self):
        """
            This function is called when ida loads the plugin.
            Here we should initate all the modules
        """
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
