from nicegui import ui
from UI.ui_main import mainUI
import os
import datetime
import logging

def start(window_size = (640, 1024)):
    configure_logger()
    main = mainUI()
    ui.run(window_size=window_size, reload=False) # native = True: it opens in a native window instaed of a webbrowser

def configure_logger():
    log_folder = os.path.join('..', 'logs')
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    current_time = datetime.datetime.now().strftime('%Y-%m-%d')
    log_filename = os.path.join(log_folder, f'log_{current_time}.log')

    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

if __name__ in {"__main__", "__mp_main__"}:
    try: 
        start()
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)