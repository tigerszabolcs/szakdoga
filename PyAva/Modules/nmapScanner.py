# PyAva/Modules/nmapScanner.py
import platform
from time import sleep
import os
import nmap
import subprocess
from PyAva.Modules.BaseScanner import BaseScanner

class Scanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.is_async = False
        self.scn = nmap.PortScannerAsync()
        self.is_async = True
                

    def do_scan(self, ip_range, arguments: list):
        self.scan_completed = False
        joined_arguments = self.join_arguments(arguments)
        if self.is_async:
            self.scn.scan(hosts=ip_range, arguments=joined_arguments, callback=self.scan_callback)

    def scan_callback(self, host, scan_result):
        self.save_scan_result(host, scan_result)  
        print(f"Host: {host} scanned: {scan_result['scan']}")

    def is_scanning(self):
        return self.scn.still_scanning()

    def stop(self):
        if self.is_async:
            self.scn.stop()

    def join_arguments(self, arguments: list) -> str:
        # for val in arguments:
        #     if val.startswith('-'):
        #         arguments.remove(val) <- removed, because there is no need for it
        return_str = ' '.join([f'{val}' for val in arguments])
        print(return_str)
        return return_str
    
    
if __name__ in {"__main__", "__mp_main__"}:
    scanner = Scanner()
    print(scanner.find_nmap_location())