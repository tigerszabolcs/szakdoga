from nicegui import ui
from PyAva.Modules.Database  import Database
import re
import logging

logger = logging.getLogger(__name__)
class initUI():
    first_init = True

    def __init__(self):
        self.db = Database()
        self.script_name = None
        self.scan_arguments = None
        self.ip_range_input = None
        self.scan_type = None
        self.card_container = None
        self.scanner_data: list[dict] = []
        self.script_data = {}
        self.reset_script_db()
        self.load_settings_from_db()
        self.first_init = False

    def create_layout(self):
        with ui.grid():
            with ui.row():
                with ui.column():
                    ui.label('Initial setup')
                    with ui.expansion('Nmap Scanner'):
                        self.create_nmap_input()
                    with ui.expansion('OpenVAS Scanner'):
                        self.create_openvas_input()
                    with ui.expansion('Nmap Scripts'):
                        self.create_nmap_scripts_input()
                    with ui.expansion('Actions'):
                        ui.button('Clear all scanners', on_click=self.clear_scanner_data)
                with ui.column().style('position: absolute; right:0;top:0; width: 50%;border-left: 3px solid #ccc;') as self.card_container:
                    ui.label('Scanners List')
                    self.update_scanner_cards()  # Initialize scanner cards at the start of this with statement

    def load_settings_from_db(self):
        scanner_data = self.db.get_scanner_data()
        for data in scanner_data:
            scan_type, ip_range, scan_arguments = data[1:]
            self.scanner_data.append({
                "ip_range": ip_range,
                "scan_type": scan_type,
                "scan_arguments": scan_arguments.split(' ')
            })
        if self.card_container is not None:
            self.update_scanner_cards()
        #TODO: El lehessen menteni majd több scan configot is, ezeket egy ID-vel kellene jelölni.
    
    def reset_script_db(self):
        self.script_data = {'script': None,
                            'enabled': 0}
        if self.db.get_script_data() is None:
            self.db.insert_script_data(self.script_data['script'], self.script_data['enabled'])
        else:
            self.db.update_script_data(self.script_data['script'], self.script_data['enabled'])


        
    def get_settings(self) -> dict:
        nmap_data = self.scanner_data
        script_data = self.script_data
        return {'nmap': nmap_data,
                'script': script_data}
        
    def create_nmap_input(self):
        nmap_ip_range_input = ui.input('Enter the target IP address',
                                       validation=lambda value: 'Invalid IP address!'
                                       if not (self.is_valid_ip(value))
                                       else None
                                       )
        ui.label('Enter scan arguments')
        _scan_arguments = ui.input('Enter scan arguments', value='-sV')
        ui.button('Add Nmap Scanner', on_click=lambda: self.on_add_nmap_click('nmap',nmap_ip_range_input.value, _scan_arguments.value))

    def create_openvas_input(self):
        self.ip_range_input = ui.input('Enter the target IP address',
                                       validation=lambda value: 'Invalid IP address!'
                                       if not (self.is_valid_ip(value))
                                       else None
                                       )
        ui.label('Enter scan arguments')
        ui.button('Add OpenVAS Scanner', on_click=self.on_add_openvas_click)
        
    def on_add_openvas_click(self):
        print('OpenVAS clicked with ip range:', self.get_ip_range())
        pass
            # self.on_add_click('openvas')
    
    def create_nmap_scripts_input(self):
        switch = ui.switch('Scan with scripts', on_change=lambda: self.on_switch_scripts_change(switch, script))
        with ui.column().bind_visibility_from(switch, 'value'):
            ui.label('Select Nmap script')
            script = ui.select(['vulners.nse', 'vulscan.nse'], value='vulners.nse', on_change=lambda: self.on_script_select_change(script.value))

    def on_script_select_change(self, value):
        self.script_data['script'] = value

    def on_xml_file_upload(self, file):
        # Handle the uploaded XML file
        print(f'Uploaded file: {file.name}')
            
    
    def on_switch_scripts_change(self,switch_input, script_input, ip_range='127.0.0.1'):
        self.script_name = script_input.value
        print('Nmap scripts clicked with ip range:', self.get_ip_range())
        logger.info(f'Scripts enabled: {switch_input.value}')
        if switch_input.value:
            script_name = self.script_name.split('.')[0]
            script_dict = {'script': script_name,
                           'enabled':switch_input.value}
            if not self.is_nmap_present():
                ui.notify('Nmap scanner is not added', title='Warning', duration=3000)
                logger.warning('Nmap scanner is not added')
                switch_input.value = False
            else:
                self.script_data = script_dict
                self.db.update_script_data(script_dict['script'], script_dict['enabled'])
                self.update_scanner_cards()
        else:
            # Remove the script scanner from the list
            self.reset_script_db()
            self.update_scanner_cards()
            ui.notify('Scripts are disabled', title='Warning', duration=3000)
            logger.warning('Scripts are disabled')
            
    def is_nmap_present(self):
        for scanner in self.scanner_data:
            if scanner['scan_type'] == 'nmap':
                return True
        return False
    
    def on_add_nmap_click(self, scan_type, ip_range, scan_arguments):
        logger.info(f'Nmap scanner added with IP range: {ip_range} and arguments: {scan_arguments}')
        if scan_arguments is None:
            argument_list = []
        else:
            argument_list = self.split_arguments(scan_arguments)
        _scanner_dict = {"ip_range": ip_range,
                         "scan_type": scan_type,
                         "scan_arguments": argument_list}
        self.scanner_data.append(_scanner_dict)
        self.db.insert_scanner_data(scan_type, ip_range, scan_arguments)
        print(f"Added scanner: {self.scanner_data}")
        self.update_scanner_cards()

    def remove_scanner(self, index):
        # Remove scanner by index and refresh the cards
        if 0 <= index < len(self.scanner_data):
            del self.scanner_data[index]
            self.db.delete_by_id(index+1, 'scanner_data')
            logger.info(f"Removed scanner at index {index}: {self.scanner_data}")
            print(f"Removed scanner at index {index}: {self.scanner_data}")
            self.update_scanner_cards()

    def update_scanner_cards(self):
        # Clear all existing cards and repopulate with current scanner data
        self.card_container.clear()
        logger.info(f"Updating scanner cards: {self.scanner_data}")
        print(f"Updating scanner cards: {self.scanner_data}")
        for index, scanner in enumerate(self.scanner_data):
            with self.card_container:
                with ui.card():
                    ui.label(f"Scanner: {scanner['ip_range']} | Type: {scanner['scan_type']} | Arguments: {scanner['scan_arguments']}")
                    ui.button('x', on_click=lambda idx=index: self.remove_scanner(idx))
        if self.script_data['enabled']:
            with self.card_container:
                ui.label('Scripts are enabled').style('color: red')

    def clear_scanner_data(self):
        self.clear_input()
        self.scanner_data.clear()
        self.reset_script_db()
        logger.info("Cleared all scanner data")
        print("Cleared all scanner data")
        self.update_scanner_cards()

    def clear_input(self):
        self.ip_range_input.value = ''
        self.scan_arguments.value = ''
        self.scan_type.value = 'nmap'
        logger.info("Cleared input fields")
        print("Cleared input fields")

    def get_ip_range(self):
        return self.ip_range_input.value

    def get_scan_arguments(self):
        if self.scan_arguments.value == '':
            return None
        else:
            return self.scan_arguments.value

    def is_valid_ip(self, ip, is_type_return=False):
        re_dict = {}
        ipv4_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
        cidr_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]?\d)$'
        partial_range_pattern = r'^((25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\.){3}(25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))-(25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))$'
        range_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}-(\d+)\.((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){3}$'
        if re.match(ipv4_pattern, ip):
            re_dict = {'val': True,
                       'type:': 'ipv4'}
            return True
        elif re.match(cidr_pattern, ip):
            re_dict = {'val': True,
                       'type:': 'cidr'}
            return True
        elif re.match(range_pattern, ip):
            re_dict = {'val': True,
                       'type:': 'range'}
            return True
        elif re.match(partial_range_pattern, ip):
            re_dict = {'val': True,
                       'type:': 'partial_range'}
            return True
        else:
            re_dict = {'val': False,
                       'type:': None}
        return re_dict if is_type_return else re_dict['val']

    def get_scan_type(self):
        return self.scan_type.value

    def split_arguments(self, arguments):
        return arguments.split(' ')