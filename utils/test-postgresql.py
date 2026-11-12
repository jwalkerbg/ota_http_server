import psycopg
import sys

host = input("PostgreSQL host: ")
user = input("PostgreSQL user: ")
password = input("PostgreSQL password: ")
database = input("Database: ")

try:
    print(f"\nConnecting to PostgreSQL at {host}...")

    conn = psycopg.connect(
        host=host,
        port=5432,
        user=user,
        password=password,
        dbname=database,
        connect_timeout=5
    )

    print("SUCCESS: Connected to PostgreSQL.")
    print(f"SUCCESS: Database '{database}' is accessible.")

    conn.close()
    sys.exit(0)

except psycopg.Error as err:
    print(f"FAILED: {err}")
    sys.exit(1)
