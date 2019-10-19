import os
import json
import getpass

DEFAULT_REVETHER_CONFIG_FILE_PATH = "/home/{}/.config/Revether/".format(getpass.getuser())
DEFAULT_REVETHER_CONFIG_FILE_NAME = "config.json"

CONFIG_FILE_PATH = os.path.join(DEFAULT_REVETHER_CONFIG_FILE_PATH, DEFAULT_REVETHER_CONFIG_FILE_NAME)


class Configuration(object):
    REQUIRED_CONFIGS = [
        'idbs_path',
    ]

    DEFAULT_CONFIG = {
        'idbs_path': os.path.join(DEFAULT_REVETHER_CONFIG_FILE_PATH, 'idbs'),
        'events_path': os.path.join(DEFAULT_REVETHER_CONFIG_FILE_PATH, 'events'),
    }

    configuration = None
    path = None

    @staticmethod
    def init(path=CONFIG_FILE_PATH):
        if not os.path.isfile(path) and path != CONFIG_FILE_PATH:
            raise ValueError("Configuration file {0} does not exist".format(path))

        if not os.path.isfile(path):
            try:
                os.makedirs(DEFAULT_REVETHER_CONFIG_FILE_PATH)
                os.makedirs(Configuration.DEFAULT_CONFIG['idbs_path'])
                os.makedirs(Configuration.DEFAULT_CONFIG['events_path'])
            finally:
                with open(CONFIG_FILE_PATH, 'w') as f:
                    json.dump(Configuration.DEFAULT_CONFIG, f)

        Configuration.path = path
        with open(path, 'r') as f:
            Configuration.configuration = json.load(f)

        for required_config in Configuration.REQUIRED_CONFIGS:
            if required_config not in Configuration.configuration:
                raise ValueError("{} is a required configuration, not in config.json file".format(required_config))

    @staticmethod
    def get_idbs_dir():
        return Configuration.configuration['idbs_path']

    @staticmethod
    def get_events(idb_name):
        return Configuration.configuration['events_path']

    @staticmethod
    def get(key):
        return Configuration.configuration.get(key)

    @staticmethod
    def set(key, value, flush=True):
        Configuration.configuration[key] = value

        if flush:
            with open(Configuration.path, 'w') as f:
                json.dump(Configuration.configuration, f)
