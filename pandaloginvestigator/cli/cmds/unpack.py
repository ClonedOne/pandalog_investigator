from pandaloginvestigator.core import log_unpacker
import logging


logger = logging.getLogger(__name__)


def unpack_command(app, max_num=None):
    dir_pandalogs_path = app.config.get('pandaloginvestigator', 'dir_pandalogs_path')
    dir_panda_path = app.config.get('pandaloginvestigator', 'dir_panda_path')
    dir_unpacked_path = app.config.get('pandaloginvestigator', 'dir_unpacked_path')
    logger.debug('Unpack command with parameters: {}, {}, {}, {}'.format(
                  dir_pandalogs_path, dir_panda_path, dir_unpacked_path, str(max_num)))
    log_unpacker.unpack_logs(dir_pandalogs_path, dir_panda_path, dir_unpacked_path, max_num)
