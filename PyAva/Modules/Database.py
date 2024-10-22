import sqlite3
import logging

logger = logging.getLogger(__name__)
class Database:
    def __init__(self, db_name='../data/settings.db'):
        self.connection = sqlite3.connect(db_name)
        self.create_table()
        
    def get_connection(self):
        return self.connection

    def create_table(self):
        try:
            logger.info("creating DB's")
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
                        nmap_scan_id TEXT
                        script_scan_id TEXT
                    )
                    ''')
                logger.info("results data created")
        except sqlite3.Error as e:
            logger.error(f"Error creating table: {e}")

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

    def clear_data(self):
        try:
            with self.connection:
                self.connection.execute('DELETE FROM scanner_data')
                self.connection.execute('DELETE FROM script_data')
                self.connection.execute('DELETE FROM results')
                logger.info("database flushed")
        except sqlite3.Error as e:
            logger.error(f"Error clearing data: {e}")