from nicegui import ui
from UI.ui_init import initUI

class mainUI():
    tab_names = {
        'A': 'Initial setup',
        'B': 'Scan',
        'C': 'Results'
    }
    ui_init = initUI()
    def __init__(self):
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
                self.ui_init.create_layout()
            with ui.tab_panel(self.tab_names['B']):
                ui.label('Content of B')
            with ui.tab_panel(self.tab_names['C']):
                ui.label('Content of C')
                
def setup_ui():
    mainUI()
