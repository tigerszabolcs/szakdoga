# PyAva/Modules/scanner_openvas.py
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from PyAva.Modules.BaseScanner import BaseScanner

class OpenVASScanner(BaseScanner): #!!!!TODO: Heavily modify this!!!!
    
    HOST: str = '127.0.0.1'
    PORT: int = 443
    USERNAME: str = 'admin'
    PASSWORD: str = 'admin'
    UNIX_SOCKET_PATH = '/var/run/gvmd.sock'
    
    def __init__(self):
        super().__init__()
        self.connection = self.connect()
        self.transform = EtreeCheckCommandTransform()
        self.gmp = Gmp(connection=self.connection, transform=self.transform)
        print(self.version_check())
        self.gmp.authenticate('admin', 'admin_password')  # Replace with actual credentials
        
        
    def connect(self):
        # unix_con = UnixSocketConnection(path=self.UNIX_SOCKET_PATH)
        tls_con = TLSConnection(hostname=self.HOST, port=self.PORT)
        return tls_con
    
    def version_check(self):
        with Gmp(connection=self.connection, transform=self.transform) as gmp:
            gmp.authenticate(self.USERNAME, self.PASSWORD)
            response = gmp.get_version()
        return response

if __name__ in {"__main__", "__mp_main__"}:
    scanner = OpenVASScanner()
    # def start_scan(self, target, scan_config):
    #     response = self.gmp.create_target(name='Target', hosts=target)
    #     target_id = response.get('id')
    #     response = self.gmp.create_task(name='Scan', config_id=scan_config, target_id=target_id)
    #     task_id = response.get('id')
    #     self.gmp.start_task(task_id)
    #     return task_id
    # 
    # def stop(self, task_id):
    #     self.gmp.stop_task(task_id)
    # 
    # def is_scanning(self, task_id):
    #     response = self.gmp.get_task(task_id)
    #     status = response.find('status').text
    #     return status == 'Running'
    # 
    # def get_results(self, task_id):
    #     response = self.gmp.get_results(task_id=task_id)
    #     return response