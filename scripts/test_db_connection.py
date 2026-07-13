import os
import sys

import psycopg2
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)

url = os.environ["DATABASE_URL"]
# psycopg2 doesn't parse sqlalchemy URL directly; extract via simple split
# postgresql://user:pass@host:port/db
rest = url.split("://", 1)[1]
auth, hostpart = rest.split("@", 1)
user, password = auth.split(":", 1)
host_port, database = hostpart.split("/", 1)
host, port = host_port.split(":", 1)

try:
    conn = psycopg2.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=port,
        connect_timeout=10,
    )
    cur = conn.cursor()
    cur.execute("SELECT 1")
    print("DB connection OK")
    conn.close()
    sys.exit(0)
except Exception as exc:
    print("DB connection failed:", exc)
    sys.exit(1)
