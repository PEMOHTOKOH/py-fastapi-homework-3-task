from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import (
    get_jwt_auth_manager,
    get_settings,
    BaseAppSettings
)
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import (
    BaseSecurityError,
    TokenExpiredError,
    InvalidTokenError,
)
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        # 1. Проверяем существование пользователя
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        # 2. Получаем группу USER
        user_group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )

        # 3. Создаем пользователя
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(new_user)
        await db.flush()  # получаем new_user.id без commit

        # 4. Создаем activation token
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        # 5. Сохраняем изменения
        await db.commit()
        await db.refresh(new_user)

        return new_user

    except HTTPException:
        raise

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        activation_token = await db.scalar(
            select(ActivationTokenModel)
            .options(joinedload(ActivationTokenModel.user))
            .where(
                ActivationTokenModel.token == activation_data.token
            )
        )

        if activation_token is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        expires_at = cast(datetime, activation_token.expires_at).replace(
            tzinfo=timezone.utc
        )

        if (
                activation_token.user.email != activation_data.email
                or expires_at < datetime.now(timezone.utc)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user = activation_token.user

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        user.is_active = True

        await db.delete(activation_token)

        await db.commit()

        return MessageResponseSchema(
            message="User account activated successfully."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error.",
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
        request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == request.email)
        )

        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )

            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)

            await db.commit()

        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error.",
        )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password(
        request: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == request.email)
        )

        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        reset_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        if reset_token is None or reset_token.token != request.token:
            if reset_token:
                await db.delete(reset_token)
                await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        expires_at = cast(datetime, reset_token.expires_at).replace(
            tzinfo=timezone.utc
        )

        if expires_at < datetime.now(timezone.utc):
            await db.delete(reset_token)
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = request.password

        await db.delete(reset_token)

        await db.commit()

        return MessageResponseSchema(
            message="Password reset successfully."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.email == user_data.email)
    )

    if user is None or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": user.group.name.value,
        }
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": user.group.name.value,
        }
    )

    db_refresh_token = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )

    try:
        db.add(db_refresh_token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh(
    token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(
            token.refresh_token
        )

    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    existing_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token.refresh_token
        )
    )

    if existing_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = decoded_refresh_token.get("user_id")

    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == user_id)
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": user.group.name.value,
        }
    )

    return TokenRefreshResponseSchema(
        access_token=access_token,
        token_type="bearer",
    )
