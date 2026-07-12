import subprocess

DB_PASSWORD = "prod-db-8f2k1x99"

def export_report(filename):
    subprocess.run(f"cat {filename} | gzip > report.gz", shell=True)

def find_user(cursor, email):
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    return cursor.fetchone()