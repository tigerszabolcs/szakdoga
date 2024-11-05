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
        self.set_script_data()
        self.load_settings_from_db()
        self.first_init = False

    def create_layout(self):
        with ui.splitter().style('padding: 10px') as splt:
            with splt.before:#.style('padding-right: 10px; box-sizing: border-box;'):
                with ui.column():
                    ui.label('Initial setup')
                    with ui.expansion('Nmap Scanner'):
                        self.create_nmap_input()
                    with ui.expansion('Nmap Scripts'):
                        self.create_nmap_scripts_input()
                    with ui.expansion('OpenVAS Scanner'):
                        self.create_openvas_input()
                    with ui.expansion("Cron Schedule"):
                        self.create_schedule_input()
                    with ui.expansion('Misc Settings'):
                        with ui.expansion('OpenVAS Credentials'):
                            self.create_credentials_input()
                        ui.button('Clear all scanners', on_click=self.clear_scanner_data)
                        ui.button('Clear database', on_click=self.db.clear_data)
            with splt.after:#.style('padding-left: 10px; box-sizing: border-box; border-left: 3px solid #ccc;'):
                ui.label('Scanners: ')
                with ui.column().style('padding: 10px') as self.card_container:
                    self.update_scanner_cards()
    
    def create_schedule_input(self):
        cron_input = ui.input('Set a new Cron expression')
        ui.button('Save Schedule',
                  on_click=lambda: self.save_schedule(cron_input.value))
        existing_schedules = self.db.get_all_cron_schedules()
        if existing_schedules:
            ui.label('Or select an existing schedule:').style('border-top: 1px solid #ccc; padding-top: 5px; margin-top: 5px;')
            schedule_dropdown = ui.select([s for s in existing_schedules])
            ui.button('Set as Schedule', on_click=lambda: self.set_valid_schedule(schedule_dropdown.value))
    
    def create_credentials_input(self):
        existing_credentials = self.db.get_all_credentials()
        ui.label('Select existing credentials:')
        with ui.row():
            self.credentials_dropdown = ui.select(
                [cred['username'] for cred in existing_credentials],
                on_change=lambda: self.on_credentials_select_change(self.credentials_dropdown.value)
            )
            ui.button('Delete Selected Item', on_click=self.on_delete_credentials_click)
        ui.label('Or add new credentials:')
        self.username_input = ui.input('Username')
        self.password_input = ui.input('Password', password=True, password_toggle_button=True)
        ui.button('Save Credentials', on_click=lambda: self.on_save_credentials_click(self.username_input.value, self.password_input.value))

    def on_credentials_select_change(self, value):
        # Update the database to set the selected credentials as the current ones
        self.db.set_current_credentials(value)
        self.update_credentials_dropdown()
        ui.notify(f'Selected credentials: {value}', title='Info', duration=1000)
        logger.info(f'Selected credentials: {value}')

    def on_delete_credentials_click(self):
        if self.credentials_dropdown.value:
            self.db.delete_credentials(self.credentials_dropdown.value)
            self.update_credentials_dropdown()
            logger.info(f'Deleted credentials: {self.credentials_dropdown.value}')
        else:
            ui.notify('Please select a credential to delete', title='Warning', duration=1000)
    def on_save_credentials_click(self, username, password):
        if username and password:
            # Save new credentials to the database
            self.db.save_openvas_credentials(username, password)
            self.update_credentials_dropdown()
            self.username_input.clear()
            self.password_input.clear()
            logger.info(f'New credentials saved: {username}')
        else:
            ui.notify('Please enter both username and password', title='Warning', duration=3000)
    
    def update_credentials_dropdown(self):
        self.credentials_dropdown.options = [cred['username'] for cred in self.db.get_all_credentials()]
        self.credentials_dropdown.update()
        
    def save_schedule(self, cron_expression):
        self.db.insert_cron_schedule(cron_expression)
        ui.notify('Schedule saved successfully')

    def set_valid_schedule(self, cron_expression):
        self.db.insert_cron_schedule(cron_expression, new=False)
        ui.notify('Valid schedule updated successfully')
        
    def load_settings_from_db(self):
        scanner_data = self.db.get_scanner_data()
        for data in scanner_data:
            scanner_id, scan_type, ip_range, scan_arguments = data
            if scan_arguments is None:
                scan_arguments = None
            else:
                scan_arguments = scan_arguments.split(' ')
            self.scanner_data.append({
                "id": scanner_id,
                "ip_range": ip_range,
                "scan_type": scan_type,
                "scan_arguments": scan_arguments
            })
        print(f"Loaded scanner data: {self.scanner_data}")
        if self.card_container is not None:
            self.update_scanner_cards()
    
    def reset_script_db(self):
        logger.info("resetting script data in db")
        self.script_data = {'script': None,
                            'enabled': 0}
        if self.db.get_script_data() is None:
            self.db.insert_script_data(self.script_data['script'], self.script_data['enabled'])
        else:
            self.db.update_script_data(self.script_data['script'], self.script_data['enabled'])
            
    def set_script_data(self):
        script_data = self.db.get_script_data()
        if script_data is not None:
            self.script_data = {'script': script_data[1],
                                'enabled': script_data[2]}

    def get_settings(self) -> dict:
        scanner_data = self.scanner_data
        script_data = self.script_data
        #split into openvas and nmap:
        nmap_data = []
        openvas_data = []
        for scanner in scanner_data:
            if scanner['scan_type'] == 'nmap':
                nmap_data.append(scanner)
            elif scanner['scan_type'] == 'openvas':
                openvas_data.append(scanner)
        return {'nmap': nmap_data,
                'script': script_data,
                'openvas': openvas_data}
        
    def create_nmap_input(self):
        nmap_ip_range_input = ui.input('Enter the target IP address',
                                       validation=lambda value: 'Invalid IP address!'
                                       if not (self.is_valid_ip(value))
                                       else None)
        ui.separator()
        _scan_arguments = ui.input('Enter arguments [optional]', value='')
        _arg = _scan_arguments.value
        if _arg == '':
            _arg = None
        ui.button('Add Nmap Scanner', on_click=lambda: self.on_add_nmap_click('nmap',nmap_ip_range_input.value, _arg))

    def create_openvas_input(self):
        ip_range_input = ui.input('Enter the target IP address',
                                       validation=lambda value: 'Invalid IP address!'
                                       if not (self.is_valid_ip(value, exclude='cidr'))
                                       else None
                                       )
        ui.button('Add OpenVAS Scanner',on_click=lambda: self.on_add_openvas_click('openvas', ip_range_input.value))

    def on_add_openvas_click(self, scan_type, ip_range):
        logger.info(f'OpenVAS scanner added with IP range: {ip_range}')
        _scanner_dict = {"ip_range": ip_range,
                         "scan_type": scan_type,
                         "scan_arguments": None}
        self.db.insert_scanner_data(scan_type,ip_range, None)
        _scanner_dict['id'] = self.db.get_last_inserted_id()  # Get the last inserted ID
        self.scanner_data.append(_scanner_dict)
        print(f"Added scanner: {self.scanner_data}")
        self.update_scanner_cards()
    
    def create_nmap_scripts_input(self):
        script_enabled = True if self.script_data['enabled'] == 1 else False
        switch = ui.switch('Scan with scripts', on_change=lambda: self.on_switch_scripts_change(switch, script))
        switch.value = script_enabled
        with ui.column().bind_visibility_from(switch, 'value'):
            ui.label('Select Nmap script')
            script = ui.select(['vulners.nse', 'vulscan/.nse'], value='vulners.nse', on_change=lambda: self.on_script_select_change(script.value))

    def on_script_select_change(self, value):
        self.script_data['script'] = value

    def on_xml_file_upload(self, file):
        # Handle the uploaded XML file
        print(f'Uploaded file: {file.name}')
    
    def on_switch_scripts_change(self,switch_input, script_input):
        self.script_name = script_input.value
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
            argument_list = None
        else:
            argument_list = self.split_arguments(scan_arguments)
        _scanner_dict = {"ip_range": ip_range,
                         "scan_type": scan_type,
                         "scan_arguments": argument_list}
        self.db.insert_scanner_data(scan_type, ip_range, scan_arguments)
        _scanner_dict['id'] = self.db.get_last_inserted_id()  # Get the last inserted ID
        self.scanner_data.append(_scanner_dict)
        print(f"Added scanner: {self.scanner_data}")
        self.update_scanner_cards()

    def remove_scanner(self, index):
        # Remove scanner by index and refresh the cards
        if 0 <= index < len(self.scanner_data):
            scanner_id = self.scanner_data[index]['id']
            del self.scanner_data[index]
            self.db.delete_by_id(scanner_id, 'scanner_data')
            logger.info(f"Removed scanner at index {scanner_id}: {self.scanner_data}")
            print(f"Removed scanner at index {scanner_id}: {self.scanner_data}")
            self.update_scanner_cards()

    def update_scanner_cards(self):
        # Clear all existing cards and repopulate with current scanner data
        self.card_container.clear()
        logger.info(f"Updating scanner cards: {self.scanner_data}")
        for index, scanner in enumerate(self.scanner_data):
            print(scanner, index)
            with self.card_container:
                with ui.card():
                    _args = scanner['scan_arguments']
                    if _args is None or _args == 'None':
                        label_text = f"Hosts: {scanner['ip_range']} \n| Type: {scanner['scan_type']}"
                    else:
                        label_text = f"Hosts: {scanner['ip_range']} | Type: {scanner['scan_type']} | Arguments: {_args}"
                    ui.label(label_text)
                    ui.button('x', on_click=lambda idx=index: self.remove_scanner(idx))
        if self.script_data['enabled']:
            with self.card_container:
                with ui.card().style('background-color: #ff7033;'):
                    ui.label(f"Script: {self.script_data['script']} is enabled")

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

    def is_valid_ip(self, ip, exclude=None):
        ipv4_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
        cidr_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]?\d)$'
        partial_range_pattern = r'^((25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\.){3}(25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))-(25[0-5]|(2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))$'
        range_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}-(\d+)\.((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){3}$'
        if re.match(ipv4_pattern, ip) and exclude != 'ipv4':
            return True
        elif re.match(cidr_pattern, ip) and exclude != 'cidr':
            return True
        elif re.match(range_pattern, ip) and exclude != 'range':
            return True
        elif re.match(partial_range_pattern, ip) and exclude != 'partial_range':
            return True
        else:
           return False
    def get_scan_type(self):
        return self.scan_type.value

    def split_arguments(self, arguments):
        return arguments.split(' ')