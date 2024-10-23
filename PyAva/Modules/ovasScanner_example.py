import ssl
import logging
from lxml import etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
import time

logger = logging.getLogger(__name__)

class OpenVASScanner(Gmp):

    HOST: str = '127.0.0.1'
    PORT: int = 9390
    USERNAME: str = 'admin'
    PASSWORD: str = 'admin'

    def __init__(self):
        try:
            logger.info("Connecting to OpenVAS")
            self.connection = TLSConnection(hostname=self.HOST, port=self.PORT)
            super().__init__(connection=self.connection)
            # Set the transform here
            try:
                self._gmp = self.determine_supported_gmp()
            except Exception as e:
                self._gmp = None
                print(f"An error occurred: while trying to connect:  {e}")
                logger.error(f"An error occurred: {e}")
            logger.info(f"Version: {self.version_check()}")
            if not self._gmp.is_authenticated():
                ret = self._gmp.authenticate(username=self.USERNAME, password=self.PASSWORD)
        except Exception as e:
            print(f"An error occurred: {e}")
            logger.error(f"An error occurred: {e}")

    def parse_generic_response(self, response):
        response_xml = etree.fromstring(response)
        response_dict = {}
        self.recursive_parse(response_xml, response_dict)
        return response_dict

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

    def target_scan(self):
        targetsXmlList = self._gmp.get_targets(filter_string="rows=1000")  # Get all targets from OpenVAS
        return targetsXmlList

    def version_check(self):
        if self._gmp is None:
            return "Error: No connection to OpenVAS"
        response = self._gmp.get_version()
        return response

    def create_target(self, name, hosts, port_list_id):
        response = self._gmp.create_target(name=name, hosts=hosts, port_list_id=port_list_id)
        # Parse the response XML to get the target ID
        if response is None:
            raise Exception("Failed to create target: No response")
        status = response.get('status')
        status_text = response.get('status_text')
        if status != '201':
            raise Exception(f"Failed to create target: {status_text}")
        target_id = response.get('id')
        if target_id is None:
            raise Exception("Failed to create target: No target ID in response")
        return target_id

    def get_port_list_id(self, name):
        response = self._gmp.get_port_lists(filter_string=f"name={name}")
        port_lists = response.findall('.//port_list')
        for port_list in port_lists:
            if port_list.find('name').text == name:
                port_list_id = port_list.get('id')
                return port_list_id
        raise Exception(f"Port list '{name}' not found")

    def get_scan_config_id(self, name):
        response = self._gmp.get_scan_configs(filter_string=f"name={name}")
        scan_configs = response.findall('.//config')
        for config in scan_configs:
            if config.find('name').text == name:
                scan_config_id = config.get('id')
                return scan_config_id
        raise Exception(f"Scan config '{name}' not found")

    def create_task(self, name, target_id, scan_config_id):
        response = self._gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id)
        if response is None:
            raise Exception("Failed to create task: No response")
        status = response.get('status')
        status_text = response.get('status_text')
        if status != '201':
            raise Exception(f"Failed to create task: {status_text}")
        task_id = response.get('id')
        if task_id is None:
            raise Exception("Failed to create task: No task ID in response")
        return task_id

    def start_task(self, task_id):
        response = self._gmp.start_task(task_id)
        if response is None:
            raise Exception("Failed to start task: No response")
        status = response.get('status')
        status_text = response.get('status_text')
        if status != '202':
            raise Exception(f"Failed to start task: {status_text}")
        report_id = response.find('.//report_id').text
        if report_id is None:
            raise Exception("Failed to start task: No report ID in response")
        return report_id

    def get_task_status(self, task_id):
        response = self._gmp.get_task(task_id=task_id)
        status = response.find('.//status').text
        progress_element = response.find('.//progress')
        progress = progress_element.text if progress_element is not None else '0'
        return status, progress

    def get_report_format_id(self, name):
        response = self._gmp.get_report_formats()
        report_formats = response.findall('.//report_format')
        for report_format in report_formats:
            if report_format.find('name').text == name:
                report_format_id = report_format.get('id')
                return report_format_id
        raise Exception(f"Report format '{name}' not found")

    def get_report(self, report_id, report_format_id):
        response = self._gmp.get_report(report_id=report_id, report_format_id=report_format_id)
        return response

if __name__ == '__main__':
    Gmp = OpenVASScanner()
    target_name = "MyTarget"
    target_hosts = "192.168.1.1"  # Replace with your target's IP address or hostname
    scan_config_name = "Full and fast"  # Replace with the name of your scan config
    task_name = "MyTask"
    report_format_name = "HTML"  # You can choose "XML", "HTML", "PDF", etc.
    port_list_name = "All TCP and Nmap Top 100 UDP"  # Default port list name

    # Get port list ID
    try:
        port_list_id = Gmp.get_port_list_id(port_list_name)
        print(f"Port list ID: {port_list_id}")
    except Exception as e:
        print(e)
        exit(1)

    # Create target
    try:
        target_id = Gmp.create_target(target_name, target_hosts, port_list_id)
        print(f"Created target with ID: {target_id}")
    except Exception as e:
        print(e)
        exit(1)

    # Get scan config ID
    try:
        scan_config_id = Gmp.get_scan_config_id(scan_config_name)
        print(f"Scan config ID: {scan_config_id}")
    except Exception as e:
        print(e)
        exit(1)

    # Create task
    try:
        task_id = Gmp.create_task(task_name, target_id, scan_config_id)
        print(f"Created task with ID: {task_id}")
    except Exception as e:
        print(e)
        exit(1)

    # Start task
    try:
        report_id = Gmp.start_task(task_id)
        print(f"Started task, report ID: {report_id}")
    except Exception as e:
        print(e)
        exit(1)

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
    try:
        report_format_id = Gmp.get_report_format_id(report_format_name)
        print(f"Report format ID: {report_format_id}")
    except Exception as e:
        print(e)
        exit(1)

    # Get report
    try:
        report = Gmp.get_report(report_id, report_format_id)
        # Save report to file
        report_content = report.find('.//report').text  # Extract the report content
        if report_content is None:
            raise Exception("Failed to retrieve report content")
        with open(f'report.{report_format_name.lower()}', 'w') as f:
            f.write(report_content)
        print(f"Report saved to report.{report_format_name.lower()}")
    except Exception as e:
        print(e)
        exit(1)
