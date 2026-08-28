from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
import os

from models import Base


def get_database_url() -> str:
    """Get database URL from environment or use default"""
    return os.getenv("DATABASE_URL", "sqlite:///./data/threatiq.db")


def create_db_engine():
    """Create SQLAlchemy engine"""
    db_url = get_database_url()
    
    if db_url.startswith("sqlite"):
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=os.getenv("DEBUG", "false").lower() == "true"
        )
    else:
        engine = create_engine(
            db_url,
            echo=os.getenv("DEBUG", "false").lower() == "true"
        )
    
    return engine


engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database - create all tables"""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI routes to get DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()