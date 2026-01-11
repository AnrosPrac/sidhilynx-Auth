from datetime import datetime
from database import db


async def get_client_by_id(client_id: str):
    return await db.clients.find_one({"client_id": client_id})

async def revoke_client(client_id: str):
    await db.clients.update_one(
        {"client_id": client_id},
        {"$set": {"status": "revoked"}}
    )


async def is_client_active(client_id: str) -> bool:
    client = await db.clients.find_one(
        {"client_id": client_id},
        {"status": 1}
    )
    return bool(client and client.get("status") == "active")

async def create_client(
    client_id: str,
    user_id: str,
    platform: str,
    app_id: str,
    app_name: str,
    app_version: str,
    ip_address: str,
    public_key: str
):

    now = datetime.utcnow()

    await db.clients.insert_one({
        "client_id": client_id,
        "user_id": user_id,
        "public_key": public_key,

        "platform": platform,
        "app_id": app_id,
        "app_name": app_name,
        "app_version": app_version,

        "ip_first_seen": ip_address,
        "ip_last_seen": ip_address,
        "ip_history": [
            {
                "ip": ip_address,
                "seen_at": now
            }
        ],

        "created_at": now,
        "last_seen_at": now,
        "status": "active"
    })


async def update_client_activity(client_id: str, ip_address: str):
    now = datetime.utcnow()

    await db.clients.update_one(
        {"client_id": client_id},
        {
            "$set": {
                "ip_last_seen": ip_address,
                "last_seen_at": now
            },
            "$push": {
                "ip_history": {
                    "$each": [
                        {
                            "ip": ip_address,
                            "seen_at": now
                        }
                    ],
                    "$slice": -10   # keep last 10 IPs only
                }
            }
        }
    )
