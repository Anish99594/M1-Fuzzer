from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict
from src.utils.scale_codec import encode_data, decode_data
from src.models.scale_enum import ScaleEnum
from src.types.custom_enum import CustomEnum

router = APIRouter()

class ScaleRequest(BaseModel):
    data: Any
    scale_type: ScaleEnum

class ScaleResponse(BaseModel):
    encoded: str
    decoded: Any

@router.post("/scale", response_model=ScaleResponse)
async def process_scale(request: ScaleRequest) -> ScaleResponse:
    try:
        encoded_data = encode_data(request.data, request.scale_type)
        decoded_data = decode_data(encoded_data, request.scale_type)
        return ScaleResponse(encoded=encoded_data, decoded=decoded_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))