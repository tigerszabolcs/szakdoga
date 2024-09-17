import sqlite3
from sqlite3 import Error

class SQLiteDB:
    def __init__(self, db_file):
        """Initialize the database connection."""
        self.db_file = db_file
        self.conn = None

    def create_connection(self):
        """Create a database connection."""
        try:
            self.conn = sqlite3.connect(self.db_file)
            print(f"SQLite database connected: {self.db_file}")
        except Error as e:
            print(e)

    def create_table(self, create_table_sql):
        """Create a table from the create_table_sql statement."""
        try:
            c = self.conn.cursor()
            c.execute(create_table_sql)
        except Error as e:
            print(e)

    def insert_data(self, table, data):
        """Insert data into table."""
        placeholders = ', '.join(['?'] * len(data))
        sql = f'INSERT INTO {table} VALUES ({placeholders})'
        cur = self.conn.cursor()
        cur.execute(sql, data)
        self.conn.commit()
        return cur.lastrowid

    def query_data(self, query, params=()):
        """Query data from the table."""
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()

    def update_data(self, sql, params=()):
        """Update data in the table."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()

    def delete_data(self, sql, params=()):
        """Delete data from the table."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()

    def close_connection(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()