import os
import logging
from nicegui import ui
from PyAva.UI.ui_scan import scanUI
from PyAva.UI.ui_init import initUI
from PyAva.UI.ui_result import resultsUI

logger = logging.getLogger(__name__)

class mainUI():

    _instance = None

    tab_names = {
        'A': 'Settings',
        'B': 'Scan',
        'C': 'Results'
    }

    def __init__(self):
        self.ui_settings = initUI()
        self.ui_scan = scanUI()
        self.ui_results = resultsUI()
        self.tabs = self.create_tabs()
        self.populate_tabs()
        self.set_footer()

    def create_tabs(self) -> ui.tabs:
        with ui.header().classes(replace='row items-center w-full') as header: # blue header line
            with ui.tabs().classes('w-full') as tabs:
                ui.tab(self.tab_names['A'], icon="build").classes('flex-1')
                ui.tab(self.tab_names['B'], icon="track_changes").classes('flex-1')
                ui.tab(self.tab_names['C'], icon='description').classes('flex-1')
        return tabs

    def set_footer(self):
        with ui.footer(value=True).classes('w-full') as footer:
            ui.label('PyAva - Network Scan Automation Tool').props('text-center text-sm text-gray-500')

    def populate_tabs(self):
        # This is for the already created tabs
        with ui.tab_panels(self.tabs, value=self.tab_names['A']).classes('w-full'):
            with ui.tab_panel(self.tab_names['A']).classes('p-4 w-full'):
                self.ui_settings.create_layout()
            with ui.tab_panel(self.tab_names['B']).classes('p-4 w-full'):
                self.ui_scan.create_layout()
            with ui.tab_panel(self.tab_names['C']).classes('p-4 w-full'):
                self.ui_results.create_layout()