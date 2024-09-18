import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from nicegui import ui
from PyAva.Modules.scanner import Scanner
import re

class initUI():

    def __init__(self):
        self.ip_range_input = None
        self.scan_type = None
        self.scanner = None
        
    def create_layout(self):
        with ui.grid():
            with ui.row():
                with ui.column():
                    ui.label('Initial setup')
                    self.ip_range_input = ui.input('Enter the target IP address',
                                                   validation= lambda value: 'Invalid IP adress!' 
                                                   if not(self.is_valid_ip(value)) 
                                                   else None
                                                   )
                    ui.label('Select the type of scan you want to perform')
                    self.scan_type = ui.select(value='nmap', options=['nmap', 'openvas'])
                    with ui.row().style('position: absolute; bottom: 0; right: 0;'):
                        ui.button('Start scan', on_click=self.on_scan_click)
    
    def get_ip_range(self):
        return self.ip_range_input.value
    
    def is_valid_ip(self, ip, is_type_return=False):
        ipv4_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
        cidr_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]?\d)$'
        range_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}-(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){3}$'

        if re.match(ipv4_pattern, ip):
            if is_type_return:
                return {'val': True,
                        'type:' : 'ipv4'}
            else:
                return True
        elif re.match(cidr_pattern, ip):
            if is_type_return:
                return {'val': True,
                        'type:' : 'cidr'}
            else:
                return True
        elif re.match(range_pattern, ip):
            if is_type_return:
                return {'val': True,
                        'type:' : 'range'}
            else:
                return True
        else:
            if is_type_return:
                return {'val': False,
                        'type:' : None}
            else:
                return False
    
    def get_scan_type(self):
        return self.scan_type.value

    def on_scan_click(self):
        ip_range = self.get_ip_range()
        scan_type = self.get_scan_type()
        self.scanner = Scanner(scan_type)
        self.scanner.do_scan(ip_range, ['-sV']) #TODO: Add a way to choose the arguments
        ui.notify(f'IP Range: {ip_range}, Scan Type: {scan_type}')
        #TODO: Add a way to show the progress of the scan
        #TODO: TEST THE SCANNER