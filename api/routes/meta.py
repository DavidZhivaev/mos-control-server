from fastapi import APIRouter

from core.role_defs import ROLE_META, ROLE_ORDER

router = APIRouter(prefix="/meta", tags=["meta"])


@router.get("/roles")
def list_roles():
    return [
        {
            "id": rid,
            "code_en": ROLE_META[rid]["code_en"],
            "name_ru": ROLE_META[rid]["name_ru"],
        }
        for rid in ROLE_ORDER
    ]
