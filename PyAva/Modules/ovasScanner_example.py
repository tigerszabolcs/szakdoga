import ssl
import logging
import time
from lxml import etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

logger = logging.getLogger(__name__)


class OpenVASScanner(Gmp):
    HOST: str = '127.0.0.1'
    PORT: int = 9390
    USERNAME: str = 'admin'
    PASSWORD: str = 'admin'
    PORT_LIST_ID: str = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'  # Example for 'All TCP' port list

    def __init__(self):
        try:
            logger.info("Connecting to OpenVAS")
            self.connection = TLSConnection(hostname=self.HOST, port=self.PORT)
            super().__init__(connection=self.connection, transform=EtreeCheckCommandTransform())
            self.connect()

            logger.info("Authenticating...")
            self._gmp = self.determine_supported_gmp()
            logger.info(f"Version: {self.version_check()}")

            if not self._gmp.is_authenticated():
                ret = self._gmp.authenticate(username=self.USERNAME, password=self.PASSWORD)
                if ret is None:
                    logger.info("Successfully authenticated.")
                else:
                    raise Exception("Authentication failed.")
        except ssl.SSLError as e:
            logger.error(f"SSL error: {e}")
            raise
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            raise

    def set_credentials(self, _usr, _psw):
        """Set the credentials for authentication."""
        self.USERNAME = _usr
        self.PASSWORD = _psw

    def version_check(self):
        """Check GMP version."""
        response = self._gmp.get_version()
        version = response.find('version').text  # Extract version from XML response
        return version

    def get_port_lists(self):
        """Retrieve available port lists."""
        logger.info("Retrieving available port lists")
        response = self._gmp.get_port_lists()
        port_lists = response.xpath('.//port_list')
        for port_list in port_lists:
            name = port_list.find('name').text
            port_list_id = port_list.get('id')
            logger.info(f"Port list: {name}, ID: {port_list_id}")

    def create_target(self, target_name, hosts):
        """Create a new scan target."""
        logger.info(f"Creating target: {target_name} with hosts: {hosts}")
        response = self._gmp.create_target(
            name=target_name,
            hosts=hosts,
            port_list_id=self.PORT_LIST_ID  # Use the specified port list ID
        )
        target_id = response.xpath('.//target/@id')[0]  # Get the target ID from XML response
        return target_id

    def create_task(self, task_name, target_id, config_id):
        """Create a task for scanning the target."""
        logger.info(f"Creating task: {task_name} for target ID: {target_id}")
        response = self._gmp.create_task(name=task_name, target_id=target_id, config_id=config_id)
        task_id = response.xpath('.//task/@id')[0]  # Get the task ID from XML response
        return task_id

    def start_task(self, task_id):
        """Start the task and run the scan."""
        logger.info(f"Starting task with ID: {task_id}")
        self._gmp.start_task(task_id)

    def is_task_finished(self, task_id):
        """Check if the task is finished."""
        logger.info(f"Checking task status for task ID: {task_id}")
        response = self._gmp.get_task(task_id=task_id)
        status = response.find('.//status').text
        progress = response.find('.//progress').text
        return status == "Done", progress

    def get_report(self, task_id):
        """Retrieve the report from a finished task."""
        logger.info(f"Retrieving report for task ID: {task_id}")
        task_response = self._gmp.get_task(task_id=task_id)
        report_id = task_response.xpath('.//last_report/report/@id')[0]
        report_response = self._gmp.get_report(report_id=report_id)
        return report_response

    def save_report(self, report_xml, filename):
        """Save the report to an XML file."""
        logger.info(f"Saving report to {filename}")
        with open(filename, 'wb') as f:
            f.write(etree.tostring(report_xml, pretty_print=True))

    def target_scan(self, target_name, hosts, task_name, config_id):
        """Run the entire scan process: create target, run task, check status, and save report."""
        try:
            # Create target
            target_id = self.create_target(target_name, hosts)
            # Create task
            task_id = self.create_task(task_name, target_id, config_id)
            # Start task (scan)
            self.start_task(task_id)

            # Wait for the task to complete
            while True:
                finished, progress = self.is_task_finished(task_id)
                logger.info(f"Scan progress: {progress}%")
                if finished:
                    logger.info(f"Scan for task {task_id} completed")
                    break
                time.sleep(10)  # Wait before checking again

            # Retrieve and save the report
            report_xml = self.get_report(task_id)
            self.save_report(report_xml, f"{task_name}_report.xml")
            logger.info(f"Report saved for task {task_id}")
        except Exception as e:
            logger.error(f"An error occurred during the scan process: {e}")
            raise

scanner = OpenVASScanner()
scanner.set_credentials('admin ', 'admin')
target_name = "Test Target"
hosts = "192.168.1.1"
task_name = "Test Scan"
config_id = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast config ID

scanner.target_scan(target_name, hosts, task_name, config_id)
