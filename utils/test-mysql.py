import mysql.connector
import sys

host = input("MySQL host: ")
user = input("MySQL user: ")
password = input("MySQL password: ")
database = input("Database: ")

try:
    print(f"\nConnecting to MySQL at {host}...")

    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        connection_timeout=5
    )

    if conn.is_connected():
        print("SUCCESS: Connected to MySQL.")
        print(f"SUCCESS: Database '{database}' is accessible.")

    conn.close()
    sys.exit(0)

except mysql.connector.Error as err:
    print(f"FAILED: {err}")
    sys.exit(1)
