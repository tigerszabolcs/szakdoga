import ssl
import logging
from gvm.connections import  TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from PyAva.Modules.BaseScanner import BaseScanner

logger = logging.getLogger(__name__)
class OpenVASScanner(Gmp):

    HOST: str = '127.0.0.1'
    PORT: int = 9390
    USERNAME: str = 'admin'
    PASSWORD: str = 'admin'

    def __init__(self):
        # try:
        self.connection = TLSConnection(hostname=self.HOST, port=self.PORT)
        super().__init__(connection=self.connection)
        self._gmp = self.determine_supported_gmp()
        print(self.version_check())
        if not self._gmp.is_authenticated():
            ret = self._gmp.authenticate(username=self.USERNAME, password=self.PASSWORD)

        # self.transform = EtreeCheckCommandTransform()
        # except ssl.SSLError as e:
        #     print(f"SSL error: {e}")
        # except Exception as e:
        #     print(f"An error occurred: {e}")

    def target_scan(self):
        targetsXmlList = self._gmp.get_targets(filter_string="rows=1000") # Get all targets from OpenVAS
        return targetsXmlList

    def version_check(self):
        response = self._gmp.get_version()
        return response

if __name__ in {"__main__", "__mp_main__"}:
    scanner = OpenVASScanner()
    print(scanner.target_scan())
    