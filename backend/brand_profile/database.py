import uuid
from datetime import datetime
from typing import Dict, Any
BRAND_DB: Dict[str, Dict[str, Any]] = {}
ANALYSIS_DB: Dict[str, Dict[str, Any]] = {}

def save_brand_profile(data: dict) -> dict:
    brand_id = f"BRD-{uuid.uuid4().hex[:6].upper()}"
    data["brand_id"] = brand_id
    data["created_at"] = datetime.utcnow().isoformat()
    BRAND_DB[brand_id] = data
    return data

def get_brand_profile(brand_id: str) -> dict | None:
    return BRAND_DB.get(brand_id)

def get_all_brands() -> list:
    return list(BRAND_DB.values())

def save_analysis(data: dict) -> dict:
    analysis_id = data["analysis_id"]
    ANALYSIS_DB[analysis_id] = data
    return data

def get_analysis(analysis_id: str) -> dict | None:
    return ANALYSIS_DB.get(analysis_id)