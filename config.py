import os
from datetime import timedelta

from dotenv import load_dotenv

_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
load_dotenv(os.path.join(_base_dir, ".env"), override=True)

# Some managed providers hand out "postgres://"; SQLAlchemy 2.x needs "postgresql://".
_database_url = os.getenv("DATABASE_URL")
if _database_url and _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)


class Config:
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(weeks=1)
    JWT_TOKEN_LOCATION = ["headers", "query_string"]
    JWT_QUERY_STRING_NAME = "token"

    # Local Ollama for NOVA dashboard analysis / chat
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
