from xml.etree import ElementTree as ET
import os
from nicegui import ui
import json
import logging
import ast
from PyAva.Modules.Database import Database
import matplotlib.pyplot as plt
import io
import base64
import pdfkit  # Make sure to install pdfkit
import tempfile
from icecream import ic
from collections import defaultdict
import re

logger = logging.getLogger(__name__)
SCAN_DIR = "../data/scanresults/"


class resultsUI:
    def __init__(self):
        self.db = Database()
        self.current_results = {}  # To store results for PDF export
        self.chart_image_base64 = ''  # To store chart image data for PDF export
        self.results_container = None

    def parse_nmap_scan(self, nmap_scan_id):
        logger.info(f"Processing nmap scan: {nmap_scan_id}")
        filepath = os.path.join(SCAN_DIR, f'scan_{nmap_scan_id}.xml')
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return {}

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        nmap_results = {}
        # Loop through each result in the ScanResults element
        for result in root.findall('Result'):
            ip_element = result.find('nmap')
            scan_element = result.find('scan')

            if ip_element is None or scan_element is None:
                logger.error("Missing 'nmap' or 'scan' element in a 'Result' node.")
                continue

            ip = ip_element.text.strip() if ip_element.text else ''
            scan_text = scan_element.text.strip() if scan_element.text else '{}'

            if scan_text:
                try:
                    # Safely evaluate the string to a Python dictionary
                    scan_data = ast.literal_eval(scan_text)
                    nmap_results[ip] = scan_data.get(ip, {})
                except Exception as e:
                    logger.error(f"Error processing scan data for IP {ip}: {e}")
                    nmap_results[ip] = {}
            else:
                logger.warning(f"No scan data found for IP {ip}")
                nmap_results[ip] = {}

        return nmap_results

    def parse_ovas_scan(self, ovas_scan_id):
        logger.info(f"Processing nmap scan: {ovas_scan_id}")
        filepath = os.path.join(SCAN_DIR, f'scan_{ovas_scan_id}.xml')
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return {}
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            # logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        # Extract results (vulnerabilities)
        results = root.findall('.//results/result')
        errors = root.findall('.//results/errors')
        vulnerabilities = []
        
        for error in errors:
            err_vuln = {}
            # Get the host address
            host = error.findtext('host', '').strip()
            # Extract the port text, e.g., '80/tcp'
            port_text = error.findtext('port', '').strip()
            if port_text:
                if '/' in port_text:
                    port_number, port_type = port_text.split('/', 1)
                else:
                    port_number = port_text
                    port_type = ''
            else:
                port_number = 'general'
                port_type = 'tcp'
            nvt = error.find('nvt')
            vuln_type = nvt.findtext('type', '') if nvt is not None else ''
            vuln_name = nvt.findtext('name', '').strip()
            severity = error.findtext('severity', '').strip()
            err_vuln['host'] = host
            err_vuln['port_number'] = port_number
            err_vuln['port_type'] = port_type
            err_vuln['type'] = vuln_type
            err_vuln['name'] = vuln_name
            err_vuln['severity'] = severity
            vulnerabilities.append(err_vuln)
            

        for result in results:
            vuln = {}
            # Get the host address
            host = result.findtext('host', '').strip()
            # Extract the port text, e.g., '80/tcp'
            port_text = result.findtext('port', '').strip()
            if port_text:
                if '/' in port_text:
                    port_number, port_type = port_text.split('/', 1)
                else:
                    port_number = port_text
                    port_type = ''
            else:
                port_number = 'general'
                port_type = 'tcp'

            # Get the type (nvt or cve)
            nvt = result.find('nvt')
            vuln_type = nvt.findtext('type', '') if nvt is not None else ''
            vuln_name = result.findtext('name', '').strip()
            severity = result.findtext('severity', '').strip()
            if nvt is not None:
                cvss_base = nvt.findtext('cvss_base', '').strip()
                cvss_score = nvt.findtext('.//severities/severity/score', '').strip()
            tags = nvt.findtext('tags', '') if nvt is not None else ''
            description = result.findtext('description', '').strip()
            cves = []
            if nvt is not None:
                # Extract from <cve> elements
                cve_elements = nvt.findall('cve')
                for cve_elem in cve_elements:
                    cve_id = cve_elem.text.strip()
                    if cve_id:
                        cves.append(cve_id)
                # Extract from tags
                if tags:
                    cve_matches = re.findall(r'cve=(CVE-\d{4}-\d+)', tags, re.IGNORECASE)
                    cves.extend(cve_matches)

            vuln['host'] = host
            vuln['port_number'] = port_number
            vuln['port_type'] = port_type
            vuln['type'] = vuln_type
            vuln['name'] = vuln_name
            vuln['severity'] = severity
            vuln['cvss_base'] = cvss_base
            vuln['cvss_score'] = cvss_score
            vuln['tags'] = tags
            vuln['description'] = description
            vuln['cves'] = cves or None  # Set to None if no CVEs found

            vulnerabilities.append(vuln)

        # Organize vulnerabilities by host and port
        host_data = defaultdict(lambda: defaultdict(list))

        for vuln in vulnerabilities:
            host = vuln['host']
            port_number = vuln['port_number']
            host_data[host][port_number].append(vuln)

        # Convert defaultdict to regular dict
        report_data = {host: dict(ports) for host, ports in host_data.items()}

        return report_data

    def parse_script_scan(self, script_scan_id):
        logger.info(f"Processing script scan: {script_scan_id}")
        filepath = os.path.join(SCAN_DIR, f'scan_{script_scan_id}.xml')
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return {}

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        script_results = {}

        for result in root.findall('Result'):
            ip_element = result.find('IP')
            state_element = result.find('State')
            protocols_element = result.find('Protocols')

            if ip_element is None or state_element is None or protocols_element is None:
                logger.error("Missing elements in a 'Result' node.")
                continue

            ip = ip_element.text.strip()
            state = state_element.text.strip()
            protocols_text = protocols_element.text.strip()

            try:
                protocols_text = protocols_text.replace("'", '"')
                protocols = json.loads(protocols_text)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON for IP {ip}: {e}")
                continue
            extracted_data = self.extract_protocol_info(protocols)
            script_results[ip] = {'state': state, 'protocols': extracted_data}

        return script_results

    def merge_results(self, nmap_results, script_results, ovas_results):
        merged_results = {}

        for ip, nmap_data in nmap_results.items():
            merged_results[ip] = {'nmap': nmap_data, 'script': script_results.get(ip, {}), 'ovas': ovas_results.get(ip, {})}

        for ip, script_data in script_results.items():
            if ip not in merged_results:
                merged_results[ip] = {'nmap': {}, 'script': script_data, 'ovas': ovas_results.get(ip, {})}
        
        for ip, ovas_data in ovas_results.items():
            if ip not in merged_results:
                merged_results[ip] = {'nmap': {}, 'script': {}, 'ovas': ovas_data}
                
        return merged_results

    def get_scan_ids(self, date):
        result = self.db.get_results_by_date(date)
        if result:
            nmap_scan_id_str, script_scan_id_str, ovas_scan_id_str = result[0]
            nmap_scan_id = nmap_scan_id_str.strip("[]'\"") if nmap_scan_id_str else None
            script_scan_id = script_scan_id_str.strip("[]'\"") if script_scan_id_str else None
            ovas_scan_id = ovas_scan_id_str.strip("[]'\"") if ovas_scan_id_str else None
            ic(nmap_scan_id, script_scan_id, ovas_scan_id)
            return nmap_scan_id, script_scan_id, ovas_scan_id
        else:
            return None, None
        
    def display_ovas(self, ovas_data):
        if ovas_data:
            for port_number, vulns in ovas_data.items():
                with ui.expansion(f"Port: {port_number}"):
                    for vuln in vulns:
                        with ui.card().classes('w-full'):
                            ui.label(f"Vulnerability Name: {vuln['name']}")
                            ui.label(f"Severity: {vuln['severity']}")
                            ui.label(f"CVSS Score: {vuln['cvss_score']}")
                            ui.label(f"CVSS Base: {vuln['cvss_base']}")
                            ui.label(f"Tags: {vuln['tags']}")
                            with ui.expansion("Description"):
                                ui.label(f"{vuln['description']}")
                            if vuln['cves']:
                                with ui.expansion("CVEs"):
                                    for cve in vuln['cves']:
                                        ui.label(f"{cve}")
                            else:
                                ui.label("No CVEs found.")
        else:
            ui.label("No Vulnerabilities found with openVAS.")
        pass
    
    def display_script(self, script_data):
        if script_data:
            # Display script scan results
            ui.label(f"State: {script_data.get('state', '')}")
            protocols = script_data.get('protocols', {})
            if protocols:
                for port_data in protocols:
                    port_number = port_data.get('port', '')
                    port_state = port_data.get('state', '')
                    fingerprint_strings = port_data.get('fingerprint_strings', [])
                    if port_state == 'closed' or not fingerprint_strings:
                        ui.label(f"\tPort: {port_number} : {port_state}.")
                    else:
                        with ui.expansion(f"Port: {port_number}"):
                            ui.label(f"State: {port_state}")
                            if fingerprint_strings:
                                ui.label("More Info:")
                                ui.label(fingerprint_strings)
                            else:
                                ui.label("No more info available.")
        else:
            ui.label("No Script data available.")
        pass
    
    def display_nmap(self, nmap_data, tcp_ports):
        if nmap_data:
            # Display general host info
            status = nmap_data.get('status', {})
            state = status.get('state', 'unknown')
            reason = status.get('reason', '')
            ic(status, state, reason)
            ui.label(f"Host Status: {state} ({reason})")
            # Display open ports and their details
            if tcp_ports:
                ui.label("Open TCP Ports:")
                # Prepare columns and rows for the table
                columns = [
                    {'name': 'port', 'label': 'Port', 'field': 'port', 'align': 'center'},
                    {'name': 'state', 'label': 'State', 'field': 'state', 'align': 'center'},
                    {'name': 'service', 'label': 'Service', 'field': 'service', 'align': 'center'},
                    {'name': 'product', 'label': 'Product', 'field': 'product', 'align': 'center'},
                    {'name': 'version', 'label': 'Version', 'field': 'version', 'align': 'center'},
                    {'name': 'extrainfo', 'label': 'Extra Info', 'field': 'extrainfo', 'align': 'center'},
                ]
                rows = []
                for port, port_data in tcp_ports.items():
                    port_state = port_data.get('state', '')
                    service = port_data.get('name', '')
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    extrainfo = port_data.get('extrainfo', '')
                    row = {
                        'port': str(port),
                        'state': port_state if port_state else '[unknown]',
                        'service': service if service else '[unknown]',
                        'product': product if product else '[unknown]',
                        'version': version if version else '[unknown]',
                        'extrainfo': extrainfo if extrainfo else '[unknown]',
                    }
                    # ic(rows, columns)
                    rows.append(row)
                ui.table(rows=rows, columns=columns).classes('w-full')
            else:
                ui.label("No open TCP ports found.")
        else:
            ui.label("No Nmap data available.")
        pass

    def display_results(self, results):
        with ui.column() as self.results_container:
            self.current_results = results  # Store results for PDF export
            ip_list = []
            open_port_counts = []
            for ip, data in results.items():
                if not data['nmap'] and not data['script'] and not data['ovas']:
                    continue  # Skip if both nmap and script results are empty, and ovas too
                nmap_data = data.get('nmap', {})
                script_data = data.get('script', {})
                ovas_data = data.get('ovas', {})
                tcp_ports = nmap_data.get('tcp', {})
                # Count open ports
                open_ports = [port for port, port_data in tcp_ports.items() if port_data.get('state') == 'open']
                open_port_counts.append(len(open_ports))
                ip_list.append(ip)
                # Populate the cards by ip
                with ui.card():
                    ui.label(f'IP: {ip}')
                    with ui.column():
                        with ui.expansion('Nmap Results'):
                            self.display_nmap(nmap_data, tcp_ports)
                        ui.separator()
                        with ui.expansion('Script Scan Results'):
                            self.display_script(script_data)
                        ui.separator()
                        with ui.expansion('OpenVAS Results'):
                            self.display_ovas(ovas_data)
            # Create a graphic using matplotlib
            if ip_list and open_port_counts:
                plt.figure(figsize=(10, 6))
                plt.bar(ip_list, open_port_counts, color='blue')
                plt.xlabel('IP Address')
                plt.ylabel('Number of Open Ports')
                plt.title('Open Ports per Host')
                plt.xticks(rotation=90)
                plt.tight_layout()
                # Save the plot to a BytesIO object
                buf = io.BytesIO()
                plt.savefig(buf, format='png')
                plt.close()
                buf.seek(0)
                # Encode the image to base64 to display in NiceGUI
                img_base64 = base64.b64encode(buf.read()).decode('utf-8')
                self.chart_image_base64 = img_base64  # Store image data for PDF export
                with ui.card().tight():
                    ui.label("Open Ports per Host")
                    ui.image(f'data:image/png;base64,{img_base64}')
            
            # Add a button to export to PDF
            ui.button('Export to PDF', on_click=self.export_to_pdf)

    def extract_protocol_info(self, protocol):
        protocol = protocol[0]
        extracted_info = []
        protocol_name = protocol.get('name')
        for port in protocol.get('ports', []):
            port_number = port.get('number')
            port_state = port.get('state')
            script_info = port.get('script', '')

            if isinstance(script_info, dict):
                fingerprint_strings = script_info.get('fingerprint-strings', '')
            else:
                fingerprint_strings = ''

            extracted_info.append({
                'protocol': protocol_name,
                'port': port_number,
                'state': port_state,
                'fingerprint_strings': fingerprint_strings
            })
        ic(extracted_info)
        return extracted_info

    def export_to_pdf(self):
        # Generate HTML content
        html_content = '<html><head><meta charset="UTF-8"></head><body>'
        html_content += '<h1>Scan Results Report</h1>'
        for ip, data in self.current_results.items():
            if not data['nmap'] and not data['script'] and not data['ovas']:
                continue
            html_content += f'<h2>IP: {ip}</h2>'
            # Nmap data
            nmap_data = data.get('nmap', {})
            if nmap_data:
                status = nmap_data.get('status', {})
                state = status.get('state', 'unknown')
                reason = status.get('reason', '')
                html_content += f"<p>Host Status: {state} ({reason})</p>"
                tcp_ports = nmap_data.get('tcp', {})
                if tcp_ports:
                    html_content += "<h3>Open TCP Ports:</h3>"
                    html_content += '<table border="1" cellpadding="5" cellspacing="0"><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Extra Info</th></tr>'
                    for port, port_data in tcp_ports.items():
                        port_state = port_data.get('state', '')
                        service = port_data.get('name', '')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        extrainfo = port_data.get('extrainfo', '')
                        html_content += f'<tr><td>{port}</td><td>{port_state}</td><td>{service}</td><td>{product}</td><td>{version}</td><td>{extrainfo}</td></tr>'
                    html_content += '</table>'
                else:
                    html_content += "<p>No open TCP ports found.</p>"
            else:
                html_content += "<p>No Nmap data available.</p>"

            # Script data
            script_data = data.get('script', {})
            if script_data:
                html_content += "<h3>Script Scan Results:</h3>"
                html_content += f"<p>State: {script_data.get('state', '')}</p>"
                protocols = script_data.get('protocols', {})
                if protocols:
                    protocols_formatted = json.dumps(protocols, indent=2).replace('\n', '<br>').replace(' ', '&nbsp;')
                    html_content += f"<pre>{protocols_formatted}</pre>"
            else:
                html_content += "<p>No Script data available.</p>"

            # OpenVAS data
            ovas_data = data.get('ovas', {})
            if ovas_data:
                html_content += "<h3>OpenVAS Results:</h3>"
                for port_number, vulns in ovas_data.items():
                    html_content += f"<h4>Port: {port_number}</h4>"
                    for vuln in vulns:
                        html_content += f"<p>Vulnerability Name: {vuln['name']}</p>"
                        html_content += f"<p>Severity: {vuln['severity']}</p>"
                        html_content += f"<p>CVSS Score: {vuln['cvss_score']}</p>"
                        html_content += f"<p>CVSS Base: {vuln['cvss_base']}</p>"
                        html_content += f"<p>Tags: {vuln['tags']}</p>"
                        html_content += f"<p>Description: {vuln['description']}</p>"
                        if vuln['cves']:
                            html_content += "<p>CVEs:</p><ul>"
                            for cve in vuln['cves']:
                                html_content += f"<li>{cve}</li>"
                            html_content += "</ul>"
                        else:
                            html_content += "<p>No CVEs found.</p>"
            else:
                html_content += "<p>No OpenVAS data available.</p>"

        # Add the chart image
        if self.chart_image_base64:
            html_content += '<h2>Open Ports per Host</h2>'
            html_content += f'<img src="data:image/png;base64,{self.chart_image_base64}" />'

        html_content += '</body></html>'

        # Convert HTML to PDF
        try:
            # Use a temporary file
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
                pdf_file_path = tmp_file.name
                pdfkit.from_string(html_content, pdf_file_path)

            # Provide a download link
            with ui.dialog() as dialog:
                with ui.card():
                    ui.label('PDF Report is ready for download.')
                    ui.button('Download', on_click=lambda: ui.download(pdf_file_path, 'scan_results_report.pdf'))
                    ui.button('Close', on_click=dialog.close)
            dialog.open()
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            ui.notify('Failed to generate PDF report.', level='error')
    
    # def export_to_pdf(self):
    #     # Generate HTML content
    #     html_content = '<html><head><meta charset="UTF-8"></head><body>'
    #     html_content += '<h1>Scan Results Report</h1>'
    #     for ip, data in self.current_results.items():
    #         if not data['nmap'] and not data['script']:
    #             continue
    #         html_content += f'<h2>IP: {ip}</h2>'
    #         nmap_data = data.get('nmap', {})
    #         if nmap_data:
    #             status = nmap_data.get('status', {})
    #             state = status.get('state', 'unknown')
    #             reason = status.get('reason', '')
    #             html_content += f"<p>Host Status: {state} ({reason})</p>"
    #             tcp_ports = nmap_data.get('tcp', {})
    #             if tcp_ports:
    #                 html_content += "<h3>Open TCP Ports:</h3>"
    #                 html_content += '<table border="1" cellpadding="5" cellspacing="0"><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Extra Info</th></tr>'
    #                 for port, port_data in tcp_ports.items():
    #                     port_state = port_data.get('state', '')
    #                     service = port_data.get('name', '')
    #                     product = port_data.get('product', '')
    #                     version = port_data.get('version', '')
    #                     extrainfo = port_data.get('extrainfo', '')
    #                     html_content += f'<tr><td>{port}</td><td>{port_state}</td><td>{service}</td><td>{product}</td><td>{version}</td><td>{extrainfo}</td></tr>'
    #                 html_content += '</table>'
    #             else:
    #                 html_content += "<p>No open TCP ports found.</p>"
    #         else:
    #             html_content += "<p>No Nmap data available.</p>"
    # 
    #         script_data = data.get('script', {})
    #         if script_data:
    #             html_content += "<h3>Script Scan Results:</h3>"
    #             html_content += f"<p>State: {script_data.get('state', '')}</p>"
    #             protocols = script_data.get('protocols', {})
    #             if protocols:
    #                 protocols_formatted = json.dumps(protocols, indent=2).replace('\n', '<br>').replace(' ', '&nbsp;')
    #                 html_content += f"<pre>{protocols_formatted}</pre>"
    #         else:
    #             html_content += "<p>No Script data available.</p>"
    # 
    #     # Add the chart image
    #     if self.chart_image_base64:
    #         html_content += '<h2>Open Ports per Host</h2>'
    #         html_content += f'<img src="data:image/png;base64,{self.chart_image_base64}" />'
    # 
    #     html_content += '</body></html>'
    # 
    #     # Convert HTML to PDF
    #     try:
    #         # Use a temporary file
    #         with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
    #             pdf_file_path = tmp_file.name
    #             pdfkit.from_string(html_content, pdf_file_path)
    # 
    #         # Provide a download link
    #         with ui.dialog() as dialog:
    #             with ui.card():
    #                 ui.label('PDF Report is ready for download.')
    #                 ui.button('Download', on_click=lambda: ui.download(pdf_file_path, 'scan_results_report.pdf'))
    #                 ui.button('Close', on_click=dialog.close)
    #         dialog.open()
    #     except Exception as e:
    #         logger.error(f"Error generating PDF: {e}")
    #         ui.notify('Failed to generate PDF report.', level='error')

    def create_layout(self):
        dates = self.db.get_scan_dates()
        with ui.column():
            with ui.row():
                date_dropdown = ui.select([d for d in dates], label='Select a scan date:')
                ui.button( on_click=lambda: self.update_layout(date_dropdown), icon='autorenew').style('background: none')
            ui.button('Load Results', on_click=lambda: self.load_result(date_dropdown.value))
        
    def update_layout(self, date_dropdown):
        dates = self.db.get_scan_dates()
        date_dropdown.options = [d for d in dates]
        date_dropdown.update()
        
    def load_result(self, value):
        if self.results_container is not None:
            self.results_container.clear()
        selected_date = value
        nmap_scan_id, script_scan_id, ovas_scan_id = self.get_scan_ids(selected_date)
        # ic(nmap_scan_id, script_scan_id, ovas_scan_id)
        nmap_results = self.parse_nmap_scan(nmap_scan_id) if nmap_scan_id else {}
        script_results = self.parse_script_scan(script_scan_id) if script_scan_id else {}
        ovas_results = self.parse_ovas_scan(ovas_scan_id) if ovas_scan_id else {}
        ic(ovas_results)
        if nmap_results or script_results or ovas_results:
            merged_results = self.merge_results(nmap_results, script_results, ovas_results)
            self.display_results(merged_results)
        else:
            ui.notify('No scan data available for the selected date', level='error')


if __name__ == '__main__':

    def parse_ovas_scan():
        try:
            tree = ET.parse("../../data/scanresults/scan_TEST.xml")
            root = tree.getroot()
        except ET.ParseError as e:
            # logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        # Extract results (vulnerabilities)
        results = root.findall('.//results/result')
        vulnerabilities = []

        for result in results:
            vuln = {}
            # Get the host address
            host = result.findtext('host', '').strip()
            # Extract the port text, e.g., '80/tcp'
            port_text = result.findtext('port', '').strip()
            port_number = ''
            port_type = ''
            if port_text:
                if '/' in port_text:
                    port_number, port_type = port_text.split('/', 1)
                else:
                    port_number = port_text
                    port_type = ''
            else:
                port_number = 'general'
                port_type = 'tcp'

            # Get the type (nvt or cve)
            nvt = result.find('nvt')
            vuln_type = nvt.findtext('type', '') if nvt is not None else ''
            vuln_name = result.findtext('name', '').strip()
            severity = result.findtext('severity', '').strip()
            cvss_base = ''
            cvss_score = ''
            if nvt is not None:
                cvss_base = nvt.findtext('cvss_base', '').strip()
                cvss_score = nvt.findtext('.//severities/severity/score', '').strip()
            tags = nvt.findtext('tags', '') if nvt is not None else ''
            description = result.findtext('description', '').strip()

            # Extract potential CVEs from <cve> elements or tags
            cves = []
            if nvt is not None:
                # Extract from <cve> elements
                cve_elements = nvt.findall('cve')
                for cve_elem in cve_elements:
                    cve_id = cve_elem.text.strip()
                    if cve_id:
                        cves.append(cve_id)
                # Extract from tags
                if tags:
                    cve_matches = re.findall(r'cve=(CVE-\d{4}-\d+)', tags, re.IGNORECASE)
                    cves.extend(cve_matches)

            vuln['host'] = host
            vuln['port_number'] = port_number
            vuln['port_type'] = port_type
            vuln['type'] = vuln_type
            vuln['name'] = vuln_name
            vuln['severity'] = severity
            vuln['cvss_base'] = cvss_base
            vuln['cvss_score'] = cvss_score
            vuln['tags'] = tags
            vuln['description'] = description
            vuln['cves'] = cves or None  # Set to None if no CVEs found

            vulnerabilities.append(vuln)

        # Organize vulnerabilities by host and port
        host_data = defaultdict(lambda: defaultdict(list))

        for vuln in vulnerabilities:
            host = vuln['host']
            port_number = vuln['port_number']
            host_data[host][port_number].append(vuln)

        # Convert defaultdict to regular dict
        report_data = {host: dict(ports) for host, ports in host_data.items()}

        return report_data