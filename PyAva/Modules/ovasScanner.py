import ssl
import logging
from lxml import etree
from xml.etree import ElementTree as ET
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from PyAva.Modules.BaseScanner import BaseScanner
import time

logger = logging.getLogger(__name__)

class OpenVASScanner(Gmp, BaseScanner):

    HOST: str = '127.0.0.1'
    PORT: int = 9390
    USERNAME: str = None
    PASSWORD: str = None

    def __init__(self, username= None, password= None):
        self.id = self.generate_uid()
        self.task_name = f'task_{str(self.id)}'
        self.target_name = f"target_{str(self.id)}"
        self.USERNAME = username
        self.PASSWORD = password
        target_hosts = ["192.168.1.1"]  # Replace with your target's IP address] or hostname
        # scan_config_name = "Full and fast"  # Replace with the name of your scan config
        report_format_name = "XML" 
        try:
            logger.info("Connecting to OpenVAS")
            self.connection = TLSConnection(hostname=self.HOST, port=self.PORT)
            super().__init__(connection=self.connection)
            # Set the transform here
            try:
                self._gmp = self.determine_supported_gmp()
                self.authenticate()
            except Exception as e:
                self._gmp = None
                print(f"An error occurred: while trying to connect:  {e}")
                logger.error(f"An error occurred: {e}")
            logger.info(f"Version: {self.version_check()}")
        except Exception as e:
            print(f"An error occurred: {e}")
            logger.error(f"An error occurred: {e}")

    def parse_generic_response(self, response):
        response_xml = etree.fromstring(response)
        response_dict = {}
        self.recursive_parse(response_xml, response_dict)
        return response_dict
    
    def authenticate(self):
        if not self._gmp.is_authenticated() and self.USERNAME is not None and self.PASSWORD is not None:
            self._gmp.authenticate(username=self.USERNAME, password=self.PASSWORD)
        else:
            raise Exception("Failed to authenticate: No credentials provided")
    def recursive_parse(self, element, response_dict, parent_key=""):
        for child in element:
            key = f"{parent_key}/{child.tag}" if parent_key else child.tag
            if len(child):
                self.recursive_parse(child, response_dict, key)
            else:
                response_dict[key] = child.text

    def set_credentials(self, _usr, _psw):
        self.USERNAME = _usr
        self.PASSWORD = _psw
        self.authenticate()
        
    def set_hosts(self, host, port = 9390):
        self.HOST = host
        self.PORT = 9390

    def target_scan(self):
        targetsXmlList = self._gmp.get_targets(filter_string="rows=1000")  # Get all targets from OpenVAS
        return targetsXmlList
    
    def get_scan_configs(self):
        str_response = self._gmp.get_scan_configs()
        scan_configs = ET.fromstring(str_response)
        print(scan_configs)
        return scan_configs

    def version_check(self):
        if self._gmp is None:
            return "Error: No connection to OpenVAS"
        response = self._gmp.get_version()
        return response

    def create_target(self, name, hosts, port_list_id):
        str_response = self._gmp.create_target(name=name, hosts=hosts, port_list_id=port_list_id)
        # Parse the response XML to get the target ID
        print(str_response)
        if str_response is None:
            raise Exception("Failed to create target: No response")
        response = ET.fromstring(str_response)
        status = response.get('status')
        status_text = response.get('status_text')
        if status == '400' and status_text == "Target exists already":
            targets = self._gmp.get_targets(filter_string=f"name={name}")
            targets_xml = ET.fromstring(targets)
            print("targets: ",targets_xml)
            for target in targets_xml.findall('.//target'):
                if target.find('name').text == name:
                    return target.get('id')
        elif status != '201' or status != '200':
            raise Exception(f"Failed to create target: {status_text}")
        target_id = response.get('id')
        if target_id is None:
            raise Exception("Failed to create target: No target ID in response")
        return target_id

    def get_port_list_id(self, name = 'All IANA assigned TCP'):
        str_response = self._gmp.get_port_lists(filter_string=f"name={name}")
        print(str_response)
        response = ET.fromstring(str_response)
        port_lists = response.findall('.//port_list')
        for port_list in port_lists:
            if port_list.find('name').text == name:
                port_list_id = port_list.get('id')
                return port_list_id
        raise Exception(f"Port list '{name}' not found")

    def get_scan_config_id(self, name='Base'):
        str_response = self._gmp.get_scan_configs()#filter_string=f"name={name}")
        print("scan configs: ",str_response)
        response = ET.fromstring(str_response)
        scan_configs = response.findall('.//config')
        for config in scan_configs:
            if config.find('name').text == name:
                scan_config_id = config.get('id')
                print("scan config id: ",scan_config_id, "config name: ",name)
                return scan_config_id
        raise Exception(f"Scan config '{name}' not found")
        #config names: 'Full and fast', 'Base', 'Discovery'

    def create_task(self, name, target_id, scan_config_id):
        scanners = self.get_scanners()
        scanner_id = None
        for scanner in scanners:
            if scanner['name'] == 'OpenVAS Default':
                scanner_id = scanner['id']
                break
        str_response = self._gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id)
        print(str_response)
        response = ET.fromstring(str_response)
        status = response.get('status')
        status_text = response.get('status_text')
        if status != '201':
            raise Exception(f"Failed to create task: {status_text}")
        task_id = response.get('id')
        if task_id is None:
            raise Exception("Failed to create task: No task ID in response")
        return task_id
    
    def get_tasks(self):
        str_response = self._gmp.get_tasks()
        response = ET.fromstring(str_response)
        tasks = response.findall('.//task')
        task_list = []
        for task in tasks:
            task_info = {
                'id': task.get('id'),
                'name': task.find('name').text,
                'status': task.find('status').text
            }
            task_list.append(task_info)
        return task_list

    def get_scanners(self):
        str_response = self._gmp.get_scanners()
        response = ET.fromstring(str_response)
        scanners = response.findall('.//scanner')
        scanner_list = []
        for scanner in scanners:
            scanner_info = {
                'id': scanner.get('id'),
                'name': scanner.find('name').text,
                'host': scanner.find('host').text,
                'port': scanner.find('port').text
            }
            scanner_list.append(scanner_info)
        return scanner_list

    def start_task(self, task_id):
       str_response = self._gmp.start_task(task_id)
       response = ET.fromstring(str_response)
       status = response.get('status')
       status_text = response.get('status_text')
       if status != '202':
           raise Exception(f"Failed to start task: {status_text}")
       report_id = response.find('.//report_id').text
       if report_id is None:
           raise Exception("Failed to start task: No report ID in response")
       return report_id

    def get_task_status(self, task_id):
        str_response = self._gmp.get_task(task_id=task_id)
        response = ET.fromstring(str_response)
        status = response.find('.//status').text
        progress_element = response.find('.//progress')
        progress = progress_element.text if progress_element is not None else '0'
        return status, progress

    def get_report_format_id(self, name):
        str_response = self._gmp.get_report_formats()
        print('report_formats',str_response)
        response = ET.fromstring(str_response)
        report_formats = response.findall('.//report_format')
        for report_format in report_formats:
            if report_format.find('name').text == name:
                report_format_id = report_format.get('id')
                return report_format_id

    def get_report(self, report_id, report_format_id):
        response = self._gmp.get_report(report_id=report_id, report_format_id=report_format_id)
        return response

if __name__ == '__main__':
    Gmp = OpenVASScanner(username='admin',password= 'admin')
    target_name = "MyTarget"
    target_hosts = ["192.168.1.1"]  # Replace with your target's IP address] or hostname
    # scan_config_name = "Full and fast"  # Replace with the name of your scan config
    task_name = "MyTask"
    report_format_name = "XML"  # You can choose "XML", "HTML", "PDF", etc.
    port_list_name = "All TCP and Nmap Top 100 UDP"  # Default port list name
    
    # Get port list ID
    port_list_id = Gmp.get_port_list_id()
    print(f"Port list ID: {port_list_id}")

    # Create target
    target_id = Gmp.create_target(target_name, target_hosts, port_list_id)
    print(f"Created target with ID: {target_id}")

    # Get scan config ID
    scan_config_id = Gmp.get_scan_config_id()
    print(f"Scan config ID: {scan_config_id}")

    # Create task
    task_id = Gmp.create_task(task_name, target_id, scan_config_id)
    print(f"Created task with ID: {task_id}")
    time.sleep(1)

    # Start task
    report_id = Gmp.start_task(task_id)
    print(f"Started task, report ID: {report_id}")
    time.sleep(1)

    # Monitor task status
    status = ''
    while status != 'Done':
        status, progress = Gmp.get_task_status(task_id)
        print(f"Task status: {status}, progress: {progress}%")
        if status == 'Done':
            break
        elif status == 'Stopped':
            print("Task was stopped.")
            break
        elif status == 'Error':
            print("An error occurred during the scan.")
            break
        time.sleep(10)  # Wait for 10 seconds before checking again

    # Get report format ID
    report_format_id = Gmp.get_report_format_id(report_format_name)
    print(f"Report format ID: {report_format_id}")

    # Get report
    report = Gmp.get_report(report_id, report_format_id)
    print(report)
    # Save report to file
    if report is None:
        raise Exception("Failed to retrieve report content")
    with open(f'scan.{report_format_name.lower()}', 'w') as f:
        f.write(report)
    print(f"Report saved to report.{report_format_name.lower()}")