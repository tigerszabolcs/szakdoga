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
        with ui.header().classes(replace='row items-center') as header: # blue header line 
            with ui.tabs() as tabs:
                ui.tab(self.tab_names['A'])
                ui.tab(self.tab_names['B'])
                ui.tab(self.tab_names['C'])
        return tabs
        
        # with ui.left_drawer().classes('bg-blue-100') as left_drawer:
        #     ui.label('Side menu')
    def set_footer(self):    
        with ui.footer(value=True) as footer:
            ui.label('Footer')
        
        # with ui.page_sticky(position='bottom-right', x_offset=20, y_offset=20): # position of the button
        #     ui.button(on_click=footer.toggle, icon='contact_support').props('fab') # button to toggle footer
    def populate_tabs(self):
        # This is for the already created tabs
        with ui.tab_panels(self.tabs, value='A').classes('w-full'):
            with ui.tab_panel(self.tab_names['A']):
                self.ui_settings.create_layout()
            with ui.tab_panel(self.tab_names['B']):
                self.ui_scan.create_layout()
            with ui.tab_panel(self.tab_names['C']):
                self.ui_results.create_layout()
