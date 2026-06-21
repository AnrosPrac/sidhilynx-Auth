from datetime import datetime
from database import db
from ustils.geo import lookup_location


async def get_client_by_id(client_id: str):
    """Returns the most recently active account link for this device, if any."""
    return await db.clients.find_one(
        {"client_id": client_id},
        sort=[("last_seen_at", -1)]
    )


async def get_client_link(client_id: str, user_id: str):
    """Returns the link record for this specific device+account pair."""
    return await db.clients.find_one({"client_id": client_id, "user_id": user_id})


async def revoke_client(client_id: str):
    await db.clients.update_many(
        {"client_id": client_id},
        {"$set": {"status": "revoked"}}
    )


async def is_client_active(client_id: str, user_id: str) -> bool:
    client = await db.clients.find_one(
        {"client_id": client_id, "user_id": user_id, "status": "active"},
        {"status": 1}
    )
    return bool(client)


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
    location = lookup_location(ip_address)

    await db.clients.update_one(
        {"client_id": client_id, "user_id": user_id},
        {
            "$set": {
                "client_id": client_id,
                "user_id": user_id,
                "public_key": public_key,

                "platform": platform,
                "app_id": app_id,
                "app_name": app_name,
                "app_version": app_version,

                "ip_first_seen": ip_address,
                "ip_last_seen": ip_address,
                "location_last_seen": location,

                "last_seen_at": now,
                "status": "active"
            },
            "$setOnInsert": {
                "created_at": now
            },
            "$push": {
                "ip_history": {
                    "ip": ip_address,
                    "location": location,
                    "seen_at": now
                }
            }
        },
        upsert=True
    )


async def update_client_activity(client_id: str, ip_address: str, user_id: str):
    now = datetime.utcnow()
    location = lookup_location(ip_address)

    await db.clients.update_one(
        {"client_id": client_id, "user_id": user_id},
        {
            "$set": {
                "ip_last_seen": ip_address,
                "location_last_seen": location,
                "last_seen_at": now
            },
            "$push": {
                "ip_history": {
                    "$each": [
                        {
                            "ip": ip_address,
                            "location": location,
                            "seen_at": now
                        }
                    ],
                    "$slice": -10   # keep last 10 IPs only
                }
            }
        },
        upsert=True
    )
