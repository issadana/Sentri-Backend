import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

# Some managed providers (and older DO templates) hand out a "postgres://" URL,
# but SQLAlchemy 2.x only accepts the "postgresql://" scheme. Normalize it so the
# app boots regardless of which form DigitalOcean injects.
_database_url = os.getenv("DATABASE_URL")
if _database_url and _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)


class Config:
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    # Access token lifetime: one week.
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(weeks=1)

    # Accept the JWT from the Authorization header (REST + native WS clients)
    # and from the query string (browser WebSocket clients, which cannot set
    # custom headers on the handshake): wss://host/firewall-logs/ws?token=<JWT>
    JWT_TOKEN_LOCATION = ["headers", "query_string"]
    JWT_QUERY_STRING_NAME = "token"

    # Groq API key for the SSE chatbot (langchain_groq / ChatGroq).
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")