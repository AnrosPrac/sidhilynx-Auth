import os
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not set")

MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "app_db")


client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB_NAME]
