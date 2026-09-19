"""Pytest Configuration and Shared Fixtures"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.session import Base, get_db
from app.main import app

# Test in-memory SQLite engine
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def no_live_twilio(monkeypatch):
    """
    Blank every Twilio setting for every test.

    Settings are read from backend/.env, so a developer with real credentials
    there would otherwise have the suite send genuine WhatsApp messages (the
    audit-chain test posts to /whatsapp/send-passport) and see the
    "not configured" assertions fail. Tests that need credentials set them
    explicitly with monkeypatch.
    """
    from app.config import settings
    for name in (
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_WHATSAPP_FROM",
        "TWILIO_CONTENT_SID",
    ):
        monkeypatch.setattr(settings, name, "")


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables before test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Yield an isolated test session per test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with overridden database dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
