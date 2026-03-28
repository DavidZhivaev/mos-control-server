from fastapi import APIRouter, Depends, Request

from core.permissions import require_admin_school_or_above
from models.user import User

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/api-paths")
async def list_api_paths(
    request: Request,
    _: User = Depends(require_admin_school_or_above()),
):
    spec = request.app.openapi()
    paths_out = []
    for path, item in spec.get("paths", {}).items():
        for method, op in item.items():
            if method.upper() not in (
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            ):
                continue
            paths_out.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": op.get("operationId"),
                    "summary": op.get("summary"),
                    "tags": op.get("tags") or [],
                }
            )
    paths_out.sort(key=lambda x: (x["path"], x["method"]))
    return {
        "openapi": spec.get("openapi"),
        "title": spec.get("info", {}).get("title"),
        "paths": paths_out,
        "count": len(paths_out),
    }
