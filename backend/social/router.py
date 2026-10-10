from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel, Field

from brand_profile import database
from social.social_analysis import (
    AnalysisResult,
    BrandDetails,
    SocialProfile,
    analyse_profiles,
    analyze_profile,
)

router = APIRouter(prefix="/social", tags=["social analysis"])


class BrandReferenceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    official_username: str | None = Field(default=None, min_length=1, max_length=200)
    official_handles: list[str] = Field(default_factory=list, max_length=100)
    official_domain: str | None = Field(default=None, min_length=1, max_length=253)
    official_domains: list[str] = Field(default_factory=list, max_length=20)
    official_website: AnyHttpUrl | None = None
    logo_url: AnyHttpUrl | None = None


class BrandReferenceResponse(BrandReferenceCreate):
    brand_id: str
    created_at: str


class SocialAnalysisRequest(BaseModel):
    brand: BrandDetails
    profiles: list[SocialProfile] = Field(max_length=500)


class AccountAnalysisRequest(SocialProfile):
    brand_id: str | None = Field(default=None, min_length=1, max_length=50)


def _brand_details(data: dict) -> BrandDetails:
    handles = list(data.get("official_handles", []))
    if data.get("official_username"):
        handles.append(data["official_username"])
    domains = list(data.get("official_domains", []))
    if data.get("official_domain"):
        domains.append(data["official_domain"])
    if data.get("official_website"):
        domains.append(data["official_website"])
    return BrandDetails(
        name=data["name"],
        official_handles=sorted(set(handles)),
        official_domains=sorted(set(domains)),
        logo_url=data.get("logo_url"),
    )


@router.post("/brands", response_model=BrandReferenceResponse, status_code=status.HTTP_201_CREATED)
def register_brand(reference: BrandReferenceCreate) -> dict:
    data = reference.model_dump(mode="json")
    data["company_name"] = data["name"]
    data["monitored_domain"] = data.get("official_domain") or ""
    data["official_logo_url"] = data.get("logo_url") or ""
    data["social_accounts"] = [
        {"platform": "unknown", "handle": handle, "profile_url": ""}
        for handle in data["official_handles"]
    ]
    return database.save_brand_profile(data)


@router.get("/brands", response_model=list[BrandReferenceResponse])
def list_brands() -> list[dict]:
    return database.get_all_brands()


@router.post("/analyze", response_model=AnalysisResult, status_code=status.HTTP_201_CREATED)
def analyze_social_account(request: AccountAnalysisRequest) -> AnalysisResult:
    brands = database.get_all_brands()
    if request.brand_id:
        brand_data = database.get_brand_profile(request.brand_id)
        if not brand_data:
            raise HTTPException(status_code=404, detail="Registered brand not found.")
        candidates = [brand_data]
    else:
        candidates = brands
    if not candidates:
        raise HTTPException(status_code=400, detail="Register a brand reference before analysis.")

    profile = SocialProfile.model_validate(request.model_dump(exclude={"brand_id"}))
    analyses = [analyze_profile(_brand_details(candidate), profile) for candidate in candidates]
    result = max(analyses, key=lambda item: item.risk_score)
    database.save_analysis(result.model_dump(mode="json"))
    return result


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
def get_social_analysis(analysis_id: str) -> dict:
    result = database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return result


@router.post("/analyse", response_model=AnalysisResult)
def analyse_social_profiles(request: SocialAnalysisRequest) -> AnalysisResult:
    return analyse_profiles(request.brand, request.profiles)
