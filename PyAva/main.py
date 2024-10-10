from nicegui import ui
from UI.ui_main import mainUI


def start(is_windowed = True, window_size = (1280, 1024)):
    mainUI()
    ui.run(window_size=window_size) # native = True: it opens in a native window instaed of a webbrowser

if __name__ in {"__main__", "__mp_main__"}:
    start()