"""
Database Engine & Session Management
=====================================
SQLite (dev) va PostgreSQL (prod) uchun SQLAlchemy async setup.
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from agent.config import settings


class Base(DeclarativeBase):
    pass


# Async engine yaratish
engine = create_async_engine(
    settings.database_url,
    echo=settings.app_debug,
    future=True,
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def init_db():
    """Barcha jadvallarni yaratadi (birinchi ishga tushirishda)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency injection uchun session generator."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
