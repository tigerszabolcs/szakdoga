import os
import datetime
import logging
import time
from nicegui import ui
from xml.etree import ElementTree as ET
from PyAva.Modules.nmapScanner import Scanner as NmapScanner
from PyAva.Modules.ovasScanner import OpenVASScanner
from PyAva.Modules.ScriptsScanner import ScriptsScanner as ScriptsScanner
from PyAva.Modules.Database import Database
import asyncio
import schedule
from croniter import croniter
import threading

logger = logging.getLogger(__name__)
class scanUI():

    def __init__(self):
        # self.settings = settings
        self.console_log_element = None
        self.countdown_label = None
        self.log_label = None
        self.nmap_scanner_dicts: list[dict] = []
        self.openvas_scanner_dicts: list[dict] = []
        self.scan_results:list = []
        self.script_data = {}
        self.db = Database()

    def create_layout(self):
        with ui.grid():
            with ui.column():
                with ui.row():
                    ui.button('Start scan', on_click=self.on_scan_click)
                    ui.button('Start Scheduled scans', on_click=self.on_sch_click)
                    ui.button('Stop Scheduled scans', on_click=self.on_stop_sch_click)
                    self.countdown_label = ui.label('Next scan in: --:--:--')
                # with ui.card().style('width: calc(100vh - 50px); height: calc(100vh - 50px);'):
                #     self.log_label = ui.label().style('white-space: pre-wrap;')
                self.console_log_element = ui.log(max_lines=30).classes('w-full h-20')

                with ui.card().style('width: 100%; margin-top: 20px;'):
                    ui.label('Current Cron Schedule')
                    schedule_data = self.db.get_valid_cron_schedule()
                    if schedule_data:
                        cron_expression = schedule_data[0]
                        next_run_times = self.get_next_run_times(cron_expression)
                        for run_time in next_run_times:
                            ui.label(run_time.strftime('%Y-%m-%d %H:%M:%S'))
                    else:
                        ui.label('No valid cron schedule found')

    def get_next_run_times(self, cron_expression, num_times=5):
        base_time = datetime.datetime.now()
        _iter = croniter(cron_expression, base_time)
        return [_iter.get_next(datetime.datetime) for _ in range(num_times)]

    async  def update_countdown(self, next_run_time):
        while True:
            now = datetime.datetime.now()
            remaining_time = next_run_time - now
            if remaining_time.total_seconds() <= 0:
                self.countdown_label.set_text('Next scan in: --:--:--')
                break
            hours, remainder = divmod(remaining_time.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.countdown_label.set_text(f'Next scan in: {int(hours):02}:{int(minutes):02}:{int(seconds):02}')
            await asyncio.sleep(1)
    
    def on_stop_sch_click(self):
        schedule.clear()
        ui.notify('Scheduled scans stopped. Next scan won\'t start')

    
    def on_sch_click(self):
        self.start_scheduled_scanning()
        ui.notify('Scheduled scans started')


    def start_scheduled_scanning(self):
        schedule_data = self.db.get_valid_cron_schedule()
        if schedule_data:
            cron_expression = schedule_data[0]
            base_time = datetime.datetime.now()
            _iter = croniter(cron_expression, base_time)
            next_run = _iter.get_next(datetime.datetime)
            schedule.every().day.at(next_run.strftime("%H:%M:%S")).do(self.schedule_next_run, _iter)
            asyncio.create_task(self.update_countdown(next_run))
        asyncio.create_task(self.run_scheduler())

    def schedule_next_run(self, _iter):
        next_run = _iter.get_next(datetime.datetime)
        schedule.every().day.at(next_run.strftime("%H:%M:%S")).do(self.schedule_next_run, _iter)
        asyncio.create_task(self.update_countdown(next_run))
        self.on_scan_click()

    async def run_scheduler(self):
        while True:
            schedule.run_pending()
            await asyncio.sleep(1)
         
    def console_log(self, text):
        logger.log(logging.INFO, text)
        _text = '> ' + text
        self.console_log_element.push(_text)

    def on_scan_click(self):
        self.db=Database()
        self.load_settings_from_db()
        for s_dict in self.nmap_scanner_dicts:
            if s_dict['scan_type'] == 'nmap':
                print("Starting nmap scan")
                _scn = s_dict['scanner']
                _scn.do_scan(s_dict['ip_range'], s_dict['scan_arguments'])
                _scn_args = s_dict['scan_arguments']
                self.console_log(f'Starting scan {_scn.id} with arguments: {_scn_args}')
        for s_dict in self.openvas_scanner_dicts:
            if s_dict['scan_type'] == 'openvas':
                print("Starting OpenVAS scan")
                _scn = s_dict['scanner']
                _scn.do_scan(s_dict['ip_range'])
                self.console_log(f'Starting OpenVAS scan {_scn.id}')
        asyncio.create_task(self.check_scanner_status())
        logger.log(logging.INFO, 'Starting nmap scan')
            
    def parse_nmap_scan_results(self, filename):
        print("Parsing nmap scan results")
        logger.log(logging.INFO, f'Parsing nmap scan results from {filename}')
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
        # result:  {'127.0.0.1': [443, 445, 5000, 7000, 8000, 8080]}
        print("ip and open ports are: ",ip_open_ports)
        logger.log(logging.INFO, f'Parsed nmap scan results: {ip_open_ports}')
        return ip_open_ports

    # async def start_script_scan(self, id_list, _script_name):
    #     for _id in id_list:
    #         self.console_log(f'Parsing scan results for scan {_id}')
    #         filename = os.path.join('..', 'data', 'scanresults', f'scan_{_id}.xml')
    #         ip_and_port = self.parse_nmap_scan_results(filename)
    #         ip_range = ', '.join(ip_and_port.keys())
    #         ports = set()
    #         for port_list in ip_and_port.values():
    #             ports.update(port_list)
    #         port_str = ','.join(map(str, ports))
    #         _scn = ScriptsScanner()
    #         self.console_log(f'Starting script scan {_scn.id} with script: {_script_name} on ip(s): {ip_range} and port(s): {port_str}')
    #         await _scn.do_scan(ip_range, ['-sV', f'--script {_script_name}', f'-p{port_str}'])
    #         return _scn.id
    async def start_script_scan(self, id_list, _script_name):
        for _id in id_list:
            self.console_log(f'Parsing scan results for scan {_id}')
            filename = os.path.join('..', 'data', 'scanresults', f'scan_{_id}.xml')
            ip_and_port = self.parse_nmap_scan_results(filename)
            _scn = ScriptsScanner()
            for ip, ports in ip_and_port.items():
                port_str = ','.join(map(str, ports))
                self.console_log(f'Starting script scan {_scn.id} with script: {_script_name} on ip: {ip} and ports: {port_str}')
                await _scn.do_scan(ip, ['-sV', f'--script {_script_name}', f'-p{port_str}'])
            # Write the results of these separate scans into one single XML file
            combined_results_filename = os.path.join('..', 'data', 'scanresults', f'scan_{_scn.id}.xml')
            _scn.write_results_to_file(combined_results_filename)

            return _scn.id
                 
    def create_scanner_dict(self):
        self.remove_completed_scanners()
        settings = self.settings.get_settings()
        scanner_data = settings['nmap']
        self.script_data = settings['script']
        for scanner in scanner_data:
            _ip_range = scanner['ip_range']
            _scan_type = scanner['scan_type']
            _argument_list = scanner['scan_arguments']
            _scanner = None
            if _scan_type == 'nmap':
                _scanner = NmapScanner()
            elif _scan_type == 'openvas':
                _scanner = OpenVASScanner()
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

    def load_settings_from_db(self):
        logger.info('Loading settings from database')
        print("Loading settings from database")
        self.nmap_scanner_dicts.clear()
        self.openvas_scanner_dicts.clear()
        scanner_data = self.db.get_scanner_data()
        _username, _password = self.db.get_current_credentials()
        for data in scanner_data:
            scan_type, ip_range, scan_arguments = data[1:]
            _scanner = None
            if scan_type == 'nmap':
                _scanner = NmapScanner()
            elif scan_type == 'openvas':
                _scanner = OpenVASScanner(username=_username, password=_password)
            _id = _scanner.id if _scanner else None
            if _scanner is not None:
                if scan_type == 'nmap':
                    self.nmap_scanner_dicts.append({
                        'id': _id,
                        'scanner': _scanner,
                        'ip_range': ip_range,
                        'scan_type': scan_type,
                        'scan_arguments': scan_arguments.split(' ') if scan_arguments else None,
                        'scan_completed': False
                    })
                elif scan_type == 'openvas':
                    self.openvas_scanner_dicts.append({
                        'id': _id,
                        'scanner': _scanner,
                        'ip_range': ip_range,
                        'scan_type': scan_type,
                        'scan_completed': False
                    })
            else:
                self.console_log(f'Invalid scan type: {scan_type}')
                raise ValueError(f'Invalid scan type: {scan_type}')
        print("nmap scanner dicts: ", self.nmap_scanner_dicts)
        print("Setting ScriptsScanner data")
        script_data = self.db.get_script_data()
        print("script data is: ", script_data)
        if script_data:
            script_name, enabled = script_data[1:]
            self.script_data = {'script': script_name, 'enabled': bool(enabled)}

    def remove_completed_scanners(self):
        logger.info('Checking for completed scanners')
        for item in self.nmap_scanner_dicts:
            if item['scan_completed']:
                self.nmap_scanner_dicts.remove(item)
                logger.info(f'Removed scanner: {item}')
        for item in self.openvas_scanner_dicts:
            if item['scan_completed']:
                self.openvas_scanner_dicts.remove(item)
                logger.info(f'Removed scanner: {item}')
                
    async def wait_for_file(self, filename):
        while not os.path.exists(filename):
            await asyncio.sleep(1)

    async def check_scanner_status(self):
        print("Checking scanner status")
        id_list = {'nmap': [],
                        'script': [],
                        'openvas': []}
        tick = False
        while True:
            all_finished = True
            for _scn in self.nmap_scanner_dicts:
                if _scn['scanner'].is_scanning():
                    all_finished = False
                elif not _scn['scan_completed']:
                    _scn['scan_completed'] = True
                    _id = _scn['id']
                    id_list['nmap'].append(_id)
                    _ip_range = _scn['ip_range']
                    self.console_log(f'Scan {_id} on ip(s): {_ip_range} completed')
            for _scn in self.openvas_scanner_dicts:
                status, progress, scanning = _scn['scanner'].is_scanning()
                if scanning:
                    all_finished = False
                    tick = not tick
                    if tick:
                        self.console_log(f'OpenVAS scan {_scn["id"]} : {status} ({progress}%)')
                elif not _scn['scan_completed']:
                    _scn['scan_completed'] = True
                    _id = _scn['id']
                    _scn['scanner'].save_report()
                    id_list['openvas'].append(_id)
                    self.console_log(f'OpenVAS scan {_id} : {status}')
            if all_finished:
                print("All nmap scans completed, script data: ", self.script_data)
                self.console_log('Nmap scans completed')
                if self.script_data['enabled'] and self.script_data != {}:
                    filename = os.path.join('..', 'data', 'scanresults', f'scan_{_id}.xml')
                    await self.wait_for_file(filename)
                    script_id = await self.start_script_scan(id_list['nmap'], self.script_data['script'])
                    id_list['script'].append(script_id)
                    self.console_log('Script scans completed')
                _dtime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.db.insert_result_data(str(_dtime), str(id_list['nmap']), str(id_list['script']), str(id_list['openvas']))
                self.console_log(f'All scans completed at {_dtime}')
                break
            await asyncio.sleep(10)