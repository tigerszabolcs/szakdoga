import os
import sys
from nicegui import ui
from xml.etree import ElementTree as ET
from PyAva.Modules.nmapScanner import Scanner as NmapScanner
from PyAva.Modules.ovasScanner import OpenVASScanner
from PyAva.Modules.ScriptsScanner import ScriptsScanner as ScriptsScanner
import asyncio

class scanUI():

    def __init__(self, settings):
        print("ui_scan created")
        self.settings = settings
        self.log_label = None
        self.nmap_scanner_dicts: list[dict] = []
        self.scan_results:list = []

    def create_layout(self):
        with ui.grid():
            with ui.column():
                with ui.row():
                    ui.button('Start scan', on_click=self.on_scan_click)
                    ui.button('Stop scan', on_click=self.on_stop_click)
                with ui.card().style('width: calc(100vh - 50px); height: calc(100vh - 50px);'):
                    self.log_label = ui.label().style('white-space: pre-wrap;')
                #TODO: Display the added scanners

    def start_status_check(self):
        asyncio.create_task(self.check_scanner_status())
    
    def on_stop_click(self):
        for _scn in self.nmap_scanner_dicts:
            if not _scn['scan_completed']:
                _scn['scanner'].stop()
                _id = _scn['id']
                self.console_log(f'Scan {_id} stopped')
            
    def console_log(self, text):
        self.log_label.text += '> ' + text + '\n'
        
    def is_script_scan(self, scanner_dict):
        for scn in scanner_dict:
            if scn['scan_type'] == 'nmap_scripts':
                return True
        return False

    def on_scan_click(self):
        self.create_scanner_dict()
        print(self.nmap_scanner_dicts)  # Debug print
        for s_dict in self.nmap_scanner_dicts:
            if s_dict['scan_type'] == 'nmap':
                _scn = s_dict['scanner']
                _scn.do_scan(s_dict['ip_range'], s_dict['scan_arguments'])
                _scn_args = s_dict['scan_arguments']
                self.console_log(f'Starting scan {_scn.id} with arguments: {_scn_args}')
        self.start_status_check()

    def parse_nmap_scan_results(self, filename):
        # Parse the XML file
        tree = ET.parse(filename)
        root = tree.getroot()

        # Dictionary to store the IP addresses and their open ports
        ip_open_ports = {}

        # Loop through each result in the XML file
        for result in root.findall('Result'):
            # Parse the <scan> element, which contains scan details
            scan = result.find('scan')
            if scan is not None:
                # Loop through each host found in the <scan> element
                for ip, details in eval(scan.text).items():
                    open_ports = []
                    # Extract open ports from the 'tcp' section if it exists
                    if 'tcp' in details:
                        for port, port_details in details['tcp'].items():
                            if port_details['state'] == 'open':
                                open_ports.append(port)

                    # Add IP address and its open ports to the dictionary
                    if open_ports:
                        ip_open_ports[ip] = open_ports
        print("ip and open ports are: ",ip_open_ports)
        return ip_open_ports

    def start_script_scan(self, id_list):
        for _id in id_list:
            self.console_log(f'Parsing scan results for scan {_id}')
            filename = os.path.join('..', 'data', 'scanresults', f'scan_{_id}.xml')
            ip_range = self.parse_nmap_scan_results(filename)
            ports = []
            port_str = ''
            #TODO: Add the ip_range and port to the scipt scanner and start it,
            _script_name = self.settings.script_name
            if _script_name is None:
                self.console_log('No script selected')
                return
            else:     
                _scn = ScriptsScanner()
                _scn.do_scan(ip_range,['-sV', f'--script {_script_name}', f'-p {port_str}'])
                self.console_log(f'Starting script scan {_scn.id} with script: {_script_name} on ip(s): {ip_range} and port(s): {port_str}')
                 
    def create_scanner_dict(self):
        self.remove_completed_scanners()
        scanner_data = sorted(self.settings.scanner_data, key=lambda x: x['scan_type'] != 'nmap')
        for scanner in scanner_data:
            _ip_range = scanner['ip_range']
            _scan_type = scanner['scan_type']
            _argument_list = scanner['scan_arguments']
            _scanner = None
            if _scan_type == 'nmap':
                _scanner = NmapScanner()
            elif _scan_type == 'openvas':
                _scanner = OpenVASScanner()
            elif _scan_type == 'nmap_scripts':
                _script_name = scanner['script']
                _ip_range = None
                _scanner = ScriptsScanner(script_name=_script_name) #The last argument is the script name
            _id = _scanner.id
            if _scanner is not None:
                self.nmap_scanner_dicts.append({
                    'id': _id,
                    'scanner': _scanner,
                    'ip_range': _ip_range,
                    'scan_type': _scan_type,
                    'scan_arguments': _argument_list,
                    'scan_completed': False
                })
            else:
                self.console_log(f'Invalid scan type: {_scan_type}')
                raise ValueError(f'Invalid scan type: {_scan_type}')
            
    def remove_completed_scanners(self):
        for item in self.nmap_scanner_dicts:
            if item['scan_completed']:
                self.nmap_scanner_dicts.remove(item)

    async def check_scanner_status(self):
        id_list = []
        while True:
            all_finished = True
            for _scn in self.nmap_scanner_dicts:
                if _scn['scanner'].is_scanning():
                    all_finished = False
                elif not _scn['scan_completed']:
                    _scn['scan_completed'] = True 
                    _id = _scn['id']
                    id_list.append(_id)
                    _ip_range = _scn['ip_range']
                    self.console_log(f'Scan {_id} on ip(s): {_ip_range} completed')
            if all_finished:
                self.console_log('All scans completed')
                if self.is_script_scan(self.nmap_scanner_dicts):
                    self.start_script_scan(id_list)
                break
            await asyncio.sleep(1)
        #INFO: Add a way to choose the arguments
        #TODO: több scan-t is le lehessen futtatni egyszerre
        #TODO: Add a way to show the progress of the scan
        #TODO: Add a way to display the results of the scan
        #TODO: Ütemezni lehessen a scannereket pl.: cron, vagy pl nmap lefutása után futtasa az openvas scannt a megkapott ip-ken