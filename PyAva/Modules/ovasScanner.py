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

    from lxml import etree

    def parse_generic_response(self, response):
        response_xml = etree.fromstring(response)
        response_dict = {}
        self.recursive_parse(response_xml, response_dict)
        return response_dict

    def recursive_parse(self, element, response_dict, parent_key=""):
        for child in element:
            key = f"{parent_key}/{child.tag}" if parent_key else child.tag
            if len(child):
                self.recursive_parse(child, key)
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

if __name__ == '__main__':
    Gmp = OpenVASScanner()
    print(Gmp.version_check())
    response = '<get_version_response status="200" status_text="OK"><version>21.4</version></get_version_response>'
    parsed_response = Gmp.parse_generic_response(response)
    print(parsed_response)
