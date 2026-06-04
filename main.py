import asyncio
import hashlib
import logging
import hmac
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

import aiosqlite
from aiogram import Bot, Dispatcher, Router
from aiogram.filters import Command, CommandObject
from aiogram.types import Message
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class Settings:
    bot_token: str
    app_secret: str
    db_path: str
    pairing_ttl_seconds: int
    max_package_name: str


def load_settings() -> Settings:
    bot_token = os.getenv("BOT_TOKEN", "").strip()
    app_secret = os.getenv("APP_SECRET", "").strip()

    if not bot_token:
        raise RuntimeError("BOT_TOKEN is required")

    if len(app_secret) < 32:
        raise RuntimeError("APP_SECRET must be at least 32 chars")

    return Settings(
        bot_token=bot_token,
        app_secret=app_secret,
        db_path=os.getenv("DB_PATH", "bridge.db").strip(),
        pairing_ttl_seconds=int(os.getenv("PAIRING_TTL_SECONDS", "600")),
        max_package_name=os.getenv("MAX_PACKAGE_NAME", "ru.oneme.app").strip(),
    )


settings = load_settings()

bot = Bot(token=settings.bot_token)
dispatcher = Dispatcher()
router = Router()


class RegisterDeviceRequest(BaseModel):
    deviceId: str = Field(min_length=8, max_length=128)
    deviceSecret: str = Field(min_length=32, max_length=256)
    pairingCode: str = Field(min_length=6, max_length=16)
    deviceName: Optional[str] = Field(default=None, max_length=128)


class RegisterDeviceResponse(BaseModel):
    ok: bool
    pairingCode: str
    expiresInSeconds: int


class MaxNotificationRequest(BaseModel):
    packageName: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, max_length=4096)
    text: Optional[str] = Field(default=None, max_length=4096)
    bigText: Optional[str] = Field(default=None, max_length=8192)
    subText: Optional[str] = Field(default=None, max_length=4096)
    postTime: int
    notificationKeyHash: str = Field(min_length=16, max_length=256)


class NotificationResponse(BaseModel):
    ok: bool
    status: str


def now_seconds() -> int:
    return int(time.time())


def normalize_pairing_code(code: str) -> str:
    return code.strip().upper().replace(" ", "").replace("-", "")


def hmac_sha256(value: str) -> str:
    return hmac.new(
        settings.app_secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_device_secret(device_secret: str) -> str:
    return hmac_sha256(f"device-secret:{device_secret}")


def hash_pairing_code(pairing_code: str) -> str:
    return hmac_sha256(f"pairing-code:{normalize_pairing_code(pairing_code)}")


def make_event_hash(device_id: str, payload: MaxNotificationRequest) -> str:
    raw = "|".join(
        [
            device_id,
            payload.packageName,
            payload.title or "",
            payload.text or "",
            payload.bigText or "",
            payload.subText or "",
            str(payload.postTime),
            payload.notificationKeyHash,
        ]
    )

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@asynccontextmanager
async def open_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row

    try:
        yield db
    finally:
        await db.close()


async def init_db() -> None:
    async with open_db() as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_secret_hash TEXT NOT NULL,
                device_name TEXT NULL,

                pairing_code_hash TEXT NULL,
                pairing_expires_at INTEGER NULL,

                telegram_chat_id INTEGER NULL,
                linked_at INTEGER NULL,

                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_devices_pairing_code_hash
                ON devices(pairing_code_hash);

            CREATE INDEX IF NOT EXISTS ix_devices_telegram_chat_id
                ON devices(telegram_chat_id);

            CREATE TABLE IF NOT EXISTS notification_events (
                event_hash TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        await db.commit()


async def get_device_by_id(device_id: str) -> Optional[aiosqlite.Row]:
    async with open_db() as db:
        cursor = await db.execute(
            """
            SELECT *
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,),
        )
        return await cursor.fetchone()


async def register_or_refresh_device(request: RegisterDeviceRequest) -> None:
    current_time = now_seconds()
    pairing_code = normalize_pairing_code(request.pairingCode)
    pairing_code_hash = hash_pairing_code(pairing_code)
    device_secret_hash = hash_device_secret(request.deviceSecret)
    expires_at = current_time + settings.pairing_ttl_seconds

    async with open_db() as db:
        cursor = await db.execute(
            """
            SELECT *
            FROM devices
            WHERE device_id = ?
            """,
            (request.deviceId,),
        )
        existing = await cursor.fetchone()

        if existing is not None:
            existing_secret_hash = existing["device_secret_hash"]

            if not hmac.compare_digest(existing_secret_hash, device_secret_hash):
                raise HTTPException(
                    status_code=401,
                    detail="Device secret mismatch",
                )

            await db.execute(
                """
                UPDATE devices
                SET
                    device_name = ?,
                    pairing_code_hash = ?,
                    pairing_expires_at = ?,
                    updated_at = ?
                WHERE device_id = ?
                """,
                (
                    request.deviceName,
                    pairing_code_hash,
                    expires_at,
                    current_time,
                    request.deviceId,
                ),
            )
        else:
            await db.execute(
                """
                INSERT INTO devices (
                    device_id,
                    device_secret_hash,
                    device_name,
                    pairing_code_hash,
                    pairing_expires_at,
                    telegram_chat_id,
                    linked_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    request.deviceId,
                    device_secret_hash,
                    request.deviceName,
                    pairing_code_hash,
                    expires_at,
                    current_time,
                    current_time,
                ),
            )

        await db.commit()


async def find_pending_devices_by_code(pairing_code: str) -> list[aiosqlite.Row]:
    pairing_code_hash = hash_pairing_code(pairing_code)
    current_time = now_seconds()

    async with open_db() as db:
        cursor = await db.execute(
            """
            SELECT *
            FROM devices
            WHERE pairing_code_hash = ?
              AND pairing_expires_at > ?
            LIMIT 2
            """,
            (pairing_code_hash, current_time),
        )
        return await cursor.fetchall()


async def link_device_to_chat(device_id: str, telegram_chat_id: int) -> None:
    current_time = now_seconds()

    async with open_db() as db:
        await db.execute(
            """
            UPDATE devices
            SET
                telegram_chat_id = ?,
                linked_at = ?,
                pairing_code_hash = NULL,
                pairing_expires_at = NULL,
                updated_at = ?
            WHERE device_id = ?
            """,
            (
                telegram_chat_id,
                current_time,
                current_time,
                device_id,
            ),
        )
        await db.commit()


async def unlink_chat_devices(telegram_chat_id: int) -> int:
    current_time = now_seconds()

    async with open_db() as db:
        cursor = await db.execute(
            """
            UPDATE devices
            SET
                telegram_chat_id = NULL,
                linked_at = NULL,
                updated_at = ?
            WHERE telegram_chat_id = ?
            """,
            (
                current_time,
                telegram_chat_id,
            ),
        )
        await db.commit()

        return cursor.rowcount


async def list_chat_devices(telegram_chat_id: int) -> list[aiosqlite.Row]:
    async with open_db() as db:
        cursor = await db.execute(
            """
            SELECT *
            FROM devices
            WHERE telegram_chat_id = ?
            ORDER BY linked_at DESC
            """,
            (telegram_chat_id,),
        )
        return await cursor.fetchall()


async def authenticate_device(
    device_id: Optional[str],
    device_secret: Optional[str],
    require_linked: bool,
) -> aiosqlite.Row:
    if not device_id or not device_secret:
        raise HTTPException(
            status_code=401,
            detail="Missing device auth headers",
        )

    device = await get_device_by_id(device_id)

    if device is None:
        raise HTTPException(
            status_code=401,
            detail="Unknown device",
        )

    actual_hash = hash_device_secret(device_secret)

    if not hmac.compare_digest(device["device_secret_hash"], actual_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid device secret",
        )

    if require_linked and device["telegram_chat_id"] is None:
        raise HTTPException(
            status_code=409,
            detail="Device is not linked to Telegram",
        )

    return device


async def remember_event_once(event_hash: str, device_id: str) -> bool:
    current_time = now_seconds()

    async with open_db() as db:
        try:
            await db.execute(
                """
                INSERT INTO notification_events (
                    event_hash,
                    device_id,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (event_hash, device_id, current_time),
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False


def build_telegram_notification_text(payload: MaxNotificationRequest) -> str:
    sender = payload.title or payload.subText or "Неизвестный отправитель"
    message_text = payload.bigText or payload.text or "Без текста"

    return "\n".join(
        [
            "📩 MAX",
            f"От: {sender}",
            "",
            message_text,
        ]
    )


@router.message(Command("start"))
async def handle_start(message: Message) -> None:
    await message.answer(
        "Это мост MAX → Telegram.\n\n"
        "Открой Android-приложение, возьми код привязки и отправь:\n"
        "/link CODE\n\n"
        "Команды:\n"
        "/devices — список привязанных устройств\n"
        "/unlink — отвязать все устройства от этого чата"
    )


@router.message(Command("link"))
async def handle_link(message: Message, command: CommandObject) -> None:
    raw_code = command.args or ""
    pairing_code = normalize_pairing_code(raw_code)

    if not pairing_code:
        await message.answer("Формат: /link CODE")
        return

    devices = await find_pending_devices_by_code(pairing_code)

    if len(devices) == 0:
        await message.answer(
            "Код не найден или уже истёк. "
            "Сгенерируй новый код в Android-приложении."
        )
        return

    if len(devices) > 1:
        # TODO: Для production лучше хранить server-generated pairingCode
        # с уникальным индексом и делать retry при коллизии.
        await message.answer(
            "Нашлось несколько устройств с таким кодом. "
            "Это редкая коллизия, сгенерируй новый код."
        )
        return

    device = devices[0]
    await link_device_to_chat(device["device_id"], message.chat.id)

    device_name = device["device_name"] or device["device_id"]

    await message.answer(
        "Готово, устройство привязано.\n"
        f"Устройство: {device_name}"
    )


@router.message(Command("devices"))
async def handle_devices(message: Message) -> None:
    devices = await list_chat_devices(message.chat.id)

    if not devices:
        await message.answer("К этому чату пока не привязано ни одного устройства.")
        return

    lines = ["Привязанные устройства:"]

    for index, device in enumerate(devices, start=1):
        device_name = device["device_name"] or device["device_id"]
        linked_at = device["linked_at"] or 0
        lines.append(f"{index}. {device_name}, linked_at={linked_at}")

    await message.answer("\n".join(lines))


@router.message(Command("unlink"))
async def handle_unlink(message: Message) -> None:
    count = await unlink_chat_devices(message.chat.id)
    await message.answer(f"Отвязано устройств: {count}")


dispatcher.include_router(router)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()

    # TODO: Временная защитная мера для polling-режима.
    # Если позже перейдём на Telegram webhook, этот вызов нужно убрать.
    await bot.delete_webhook(drop_pending_updates=True)

    logger.info("Starting Telegram polling...")
    polling_task = asyncio.create_task(dispatcher.start_polling(bot))

    try:
        yield
    finally:
        polling_task.cancel()

        try:
            await polling_task
        except asyncio.CancelledError:
            pass

        await bot.session.close()


app = FastAPI(
    title="MAX to Telegram Bridge",
    lifespan=lifespan,
)


@app.post("/api/devices/register", response_model=RegisterDeviceResponse)
async def register_device(request: RegisterDeviceRequest) -> RegisterDeviceResponse:
    pairing_code = normalize_pairing_code(request.pairingCode)

    await register_or_refresh_device(request)

    return RegisterDeviceResponse(
        ok=True,
        pairingCode=pairing_code,
        expiresInSeconds=settings.pairing_ttl_seconds,
    )


@app.post("/api/notifications/max", response_model=NotificationResponse)
async def receive_max_notification(
    request: MaxNotificationRequest,
    x_device_id: Optional[str] = Header(default=None),
    x_device_secret: Optional[str] = Header(default=None),
) -> NotificationResponse:
    device = await authenticate_device(
        device_id=x_device_id,
        device_secret=x_device_secret,
        require_linked=True,
    )

    if request.packageName != settings.max_package_name:
        return NotificationResponse(
            ok=True,
            status="ignored_package",
        )

    event_hash = make_event_hash(device["device_id"], request)
    is_new_event = await remember_event_once(event_hash, device["device_id"])

    if not is_new_event:
        return NotificationResponse(
            ok=True,
            status="duplicate",
        )

    telegram_chat_id = device["telegram_chat_id"]

    if telegram_chat_id is None:
        raise HTTPException(
            status_code=409,
            detail="Device is not linked",
        )

    await bot.send_message(
        chat_id=telegram_chat_id,
        text=build_telegram_notification_text(request),
    )

    return NotificationResponse(
        ok=True,
        status="sent",
    )


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}