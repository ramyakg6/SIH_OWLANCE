"""Database Engine and Session Configuration"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

Base = declarative_base()


def get_engine():
    """Create SQLAlchemy engine with automatic fallback to SQLite if PostgreSQL is unreachable."""
    database_url = settings.DATABASE_URL
    try:
        if database_url.startswith("postgresql"):
            # Test engine connectivity
            eng = create_engine(
                database_url,
                pool_pre_ping=True,
                connect_args={"connect_timeout": 3},
            )
            # Try a quick connection test
            with eng.connect() as conn:
                logger.info("Connected successfully to PostgreSQL database.")
                return eng
    except Exception as e:
        logger.warning(
            "Could not connect to PostgreSQL database (%s). Falling back to SQLite at %s",
            e,
            settings.SQLITE_FALLBACK_URL,
        )

    # Fallback to SQLite
    sqlite_args = {"check_same_thread": False} if "sqlite" in settings.SQLITE_FALLBACK_URL else {}
    return create_engine(settings.SQLITE_FALLBACK_URL, connect_args=sqlite_args)


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency for yielding database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
