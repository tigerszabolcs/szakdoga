import nmap


class Scanner():
    
    def __init__(self, what):
        self.is_async = False
        if what == 'nmap':
            self.scanner = nmap.PortScanner()
        elif what == 'openvas':
            pass #TODO: Implement openvas scanner
        elif what == 'nmapasync':
            self.scanner = nmap.PortScannerAsync()
            self.is_async = True
        else:
            self.scanner = None
        
    def do_scan(self, ip_range, arguments: list) -> dict:
        arguments = self.join_arguments(arguments)
        scan_result = self.scanner.scan(hosts=ip_range, arguments=arguments)
        with open('scan.xml', 'w') as file:
            file.write(self.scanner.get_nmap_last_output())
        return scan_result
    
    def is_async(self):
        return self.is_async
    
    def join_arguments(self, arguments: list) -> str:
        if '-oX' in arguments:
            arguments.remove('-oX')
        return_str = ' '.join([f'-{val}' for val in arguments])
        return_str += ' -oX -'
        return return_str
