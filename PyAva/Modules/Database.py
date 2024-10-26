import sqlite3
import logging

logger = logging.getLogger(__name__)
class Database:
    def __init__(self, db_name='../data/settings.db'):
        self.db_name = db_name
        self.connection = sqlite3.connect(db_name)
        self.create_table()
        
    def get_connection(self):
        return self.connection
    

    def create_table(self):
        try:
            logger.info("creating DBs")
            with self.connection:
                self.connection.execute('''
                    CREATE TABLE IF NOT EXISTS scanner_data (
                        id INTEGER PRIMARY KEY,
                        scan_type TEXT,
                        ip_range TEXT,
                        scan_arguments TEXT
                    )
                ''')
                logger.info("scanner_data created")
                self.connection.execute('''
                    CREATE TABLE IF NOT EXISTS script_data (
                        id INTEGER PRIMARY KEY,
                        script_name TEXT,
                        enabled INTEGER
                    )
                ''')
                logger.info("script_data created")
                self.connection.execute('''
                    CREATE TABLE IF NOT EXISTS results (
                        id INTEGER PRIMARY KEY,
                        scan_date TEXT,
                        nmap_scan_id TEXT,
                        script_scan_id TEXT,
                        ovas_scan_id TEXT
                    )
                    ''')
                logger.info("results data created")
                self.connection.execute('''CREATE TABLE IF NOT EXISTS cron_schedules (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        cron_expression TEXT,
                                        valid BOOLEAN DEFAULT FALSE
                                    )''')
                logger.info("cron_schedules table created")
                self.connection.execute('''
                    CREATE TABLE IF NOT EXISTS openvas_credentials (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT,
                        is_set BOOLEAN DEFAULT FALSE
                    )
                ''')
                logger.info("openvas_credentials table created")
        except sqlite3.Error as e:
            logger.error(f"Error creating table: {e}")

    def save_openvas_credentials(self, username, password):
        try:
            with self.connection:
                query = "INSERT INTO openvas_credentials (username, password, is_set) VALUES (?, ?, ?)"
                self.connection.execute(query, (username, password, 1))
                logger.info("OpenVAS credentials saved to the database")
        except sqlite3.Error as e:
            logger.error(f"Error saving OpenVAS credentials: {e}")

    def get_all_credentials(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT username FROM openvas_credentials')
                return [{'username': row[0]} for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting credentials: {e}")
            return []

    def set_current_credentials(self, username):
        try:
            with self.connection:
                # Set all credentials to not set
                self.connection.execute('UPDATE openvas_credentials SET is_set = FALSE')
                # Set the selected credentials to set
                self.connection.execute('UPDATE openvas_credentials SET is_set = TRUE WHERE username = ?', (username,))
                logger.info(f"Set credentials for {username} as current")
        except sqlite3.Error as e:
            logger.error(f"Error setting current credentials: {e}")
            
    def delete_credentials(self, username):
        try:
            with self.connection:
                self.connection.execute('DELETE FROM openvas_credentials WHERE username = ?', (username,))
                logger.info(f"Deleted credentials for {username}")
        except sqlite3.Error as e:
            logger.error(f"Error deleting credentials: {e}")
            
    def get_current_credentials(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT username FROM openvas_credentials WHERE is_set = TRUE')
                return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error getting current credentials: {e}")
            return None

    def insert_scanner_data(self, scan_type, ip_range, scan_arguments):
        try:
            with self.connection:
                print("Inserting scanner data")
                logger.info(f"nmap data inserted into scanner_data table: {scan_type}; {ip_range}; {scan_arguments}")
                self.connection.execute('''
                    INSERT INTO scanner_data (scan_type, ip_range, scan_arguments)
                    VALUES (?, ?, ?)
                ''', (scan_type, ip_range, scan_arguments))
        except sqlite3.Error as e:
            logger.error(f"Error inserting scanner data: {e}")

    def get_scanner_data(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT * FROM scanner_data')
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error getting scanner data: {e}")
            return None

    def delete_by_id(self, id, what):
        """"Deletes data from the given table, by ID.
        id should correspond to idx+1 on the given array
        what is either scanner_data or script_data"""
        try: 
            with self.connection:
                self.connection.execute(f'DELETE FROM {what} WHERE id = ?', (id,))
                logger.info(f"Line deleted from {what} with id {id}")
        except sqlite3.Error as e:
            logger.error(f"Error deleting data: {e}")
    
    def insert_script_data(self, script_name, enabled):
        try:
            with self.connection:
                self.connection.execute('''
                    INSERT INTO script_data (script_name, enabled)
                    VALUES (?, ?)
                ''', (script_name, enabled))
        except sqlite3.Error as e:
            logger.error(f"Error inserting script data: {e}")

    def get_script_data(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT * FROM script_data')
                return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error getting script data: {e}")
            return None

    def update_script_data(self, script_name, enabled, id=1):
        try:
            with self.connection:
                self.connection.execute('''
                    UPDATE script_data
                    SET script_name = ?, enabled = ?
                    WHERE id = ?
                ''', (script_name, enabled, id))
        except sqlite3.Error as e:
            logger.error(f"Error updating script data: {e}")
            
    def insert_result_data(self, scan_date, nmap_scan_id, script_scan_id):
        try:
            with self.connection:
                self.connection.execute('''
                    INSERT INTO results (scan_date, nmap_scan_id, script_scan_id)
                    VALUES (?, ?, ?)
                ''', (scan_date, nmap_scan_id, script_scan_id))
        except sqlite3.Error as e:
            logger.error(f"Error inserting result data: {e}")

    def get_scan_times(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT scan_date FROM results')
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting scan times: {e}")
            return None
        
    def get_results_by_date(self, date):
        try:
            with self.connection:
                cursor = self.connection.execute('''SELECT nmap_scan_id, script_scan_id FROM results WHERE scan_date = ?''', (date,))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error getting results by date: {e}")
            return
        
    def get_scan_dates(self):
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT DISTINCT scan_date FROM results')
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting scan dates: {e}")
            return None

    def insert_cron_schedule(self, cron_expression, new = True):
        with self.connection:
            self.invalidate_cron_schedule()
            if new:
                self.connection.execute('INSERT INTO cron_schedules (cron_expression, valid) VALUES (?, TRUE)',
                              (cron_expression,))
            else:
                self.connection.execute('UPDATE cron_schedules SET valid = TRUE WHERE cron_expression = ?', (cron_expression,))

    def invalidate_cron_schedule(self):
        with self.connection:
            self.connection.execute('UPDATE cron_schedules SET valid = FALSE')
            
    def get_all_cron_schedules(self):
        with self.connection:
            cursor = self.connection.execute('SELECT cron_expression FROM cron_schedules')
            return [row[0] for row in cursor.fetchall()]

    def get_valid_cron_schedule(self):
        with self.connection:
            cursor = self.connection.execute('SELECT cron_expression FROM cron_schedules WHERE valid = TRUE')
            row = cursor.fetchone()
            return row if row else None

    def clear_data(self):
        try:
            with self.connection:
                self.connection.execute('DELETE FROM scanner_data')
                self.connection.execute('DELETE FROM script_data')
                self.connection.execute('DELETE FROM results')
                self.connection.execute('DELETE FROM cron_schedules')
                logger.info("database flushed")
        except sqlite3.Error as e:
            logger.error(f"Error clearing data: {e}")