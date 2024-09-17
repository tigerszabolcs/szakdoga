from nicegui import ui
from UI.ui_main import setup_ui


def start(is_windowed = True):
    setup_ui()
    ui.run(native= is_windowed) # native = True: it opens in a native window instaed of a webbrowser

if __name__ in {"__main__", "__mp_main__"}:
    start()