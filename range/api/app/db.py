import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Fail loudly if DATABASE_URL isn't set, instead of silently falling back
# to a default that might point somewhere unintended.
DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_async_engine(DATABASE_URL, echo=False)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


async def init_db() -> None:
    """Create tables if they don't exist yet.

    This is a stand-in for real migrations. It's fine while the schema
    is this simple; Alembic (or similar) should replace it once the
    schema needs to evolve safely across environments.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
