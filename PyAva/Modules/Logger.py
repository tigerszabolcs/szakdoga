import logging
import os
import datetime

def configure_logger():
    log_folder = os.path.join('..', 'logs')
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    current_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_filename = os.path.join(log_folder, f'log_{current_time}.log')

    logging.basicConfig(
        filename=log_filename,
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    _logger = logging.getLogger(__name__)
    return _logger


logger = configure_logger()