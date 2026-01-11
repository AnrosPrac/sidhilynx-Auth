from fastapi import APIRouter, HTTPException, Header
from database import db
import os

router = APIRouter(prefix="/admin/clients")


def verify_admin(x_admin_key: str):
    if x_admin_key != os.getenv("ADMIN_API_KEY"):
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/")
async def list_clients(x_admin_key: str = Header(...)):
    verify_admin(x_admin_key)

    clients = []
    async for c in db.clients.find({}, {"_id": 0}):
        clients.append(c)

    return clients


@router.post("/revoke/{client_id}")
async def revoke(client_id: str, x_admin_key: str = Header(...)):
    verify_admin(x_admin_key)

    await db.clients.update_one(
        {"client_id": client_id},
        {"$set": {"status": "revoked"}}
    )

    return {"message": "Client revoked"}
