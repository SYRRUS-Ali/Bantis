import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Token, UserCreate, UserOut
from app.orm_models import UserORM
from app.security import create_access_token, hash_password, verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, session: AsyncSession = Depends(get_session)) -> UserORM:
    existing = await session.execute(select(UserORM).where(UserORM.username == payload.username))
    if existing.scalar_one_or_none() is not None:
        logger.warning("registration rejected: username taken", extra={"username": payload.username})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered"
        )

    user = UserORM(username=payload.username, hashed_password=hash_password(payload.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)
    logger.info("user registered", extra={"username": user.username, "user_id": user.id})
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> Token:
    result = await session.execute(select(UserORM).where(UserORM.username == form_data.username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        # Audit trail for failed auth attempts — useful for spotting brute-force
        # patterns later without logging the attempted password itself.
        logger.warning("login failed", extra={"username": form_data.username})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(subject=user.username)
    logger.info("login succeeded", extra={"username": user.username, "user_id": user.id})
    return Token(access_token=token)
