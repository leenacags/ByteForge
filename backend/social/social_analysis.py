"""Explainable heuristic detection for suspicious social media profiles."""

from __future__ import annotations

import re
import uuid
from difflib import SequenceMatcher
from enum import Enum
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

try:
    from rapidfuzz import fuzz
except ImportError:  # Keep local development usable before requirements are installed.
    fuzz = None


class RiskType(str, Enum):
    BRAND_IMPERSONATION = "brand_impersonation"
    FAKE_COMPANY_PAGE = "fake_company_page"
    SCAM_PROFILE = "scam_profile"
    BRAND_SIMILARITY = "brand_similarity"


class RiskCategory(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class BrandDetails(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    official_handles: list[str] = Field(default_factory=list, max_length=100)
    official_domains: list[str] = Field(default_factory=list, max_length=20)
    logo_url: str | None = Field(default=None, max_length=2_000)

    @field_validator("official_handles", "official_domains")
    @classmethod
    def validate_non_empty_values(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("reference values must not be empty")
        return values


class SocialProfile(BaseModel):
    platform: str = Field(min_length=1, max_length=50)
    handle: str = Field(min_length=1, max_length=200)
    display_name: str = Field(default="", max_length=200)
    bio: str = Field(default="", max_length=2_000)
    profile_url: str | None = Field(default=None, max_length=2_000)
    website: str | None = Field(default=None, max_length=2_000)
    logo_url: str | None = Field(default=None, max_length=2_000)
    has_verified_badge: bool = False
    logo_match: bool | None = None
    logo_similarity: float | None = Field(default=None, ge=0, le=100)


class Finding(BaseModel):
    profile: str
    risk_type: RiskType
    severity: str
    confidence: float = Field(ge=0, le=1)
    reasons: list[str]


class DetectionSignal(BaseModel):
    code: str
    weight: float = Field(ge=0, le=100)
    explanation: str


class AnalysisResult(BaseModel):
    analysis_id: str | None = None
    profile: SocialProfile | None = None
    matched_brand: BrandDetails | None = None
    risk_score: float = Field(default=0, ge=0, le=100)
    risk_category: RiskCategory = RiskCategory.LOW
    detected_signals: list[DetectionSignal] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    heuristic: bool = True
    findings: list[Finding] = Field(default_factory=list)
    analysed_profiles: int = 0
    summary: dict[str, int] = Field(default_factory=dict)


_SCAM_TERMS = {
    "claim prize", "claim your prize", "giveaway", "guaranteed returns",
    "investment opportunity", "limited time offer", "send crypto",
    "send money", "whatsapp me", "telegram me", "double your money",
    "send your password", "share your password", "verify your account",
    "credential", "seed phrase", "urgent kyc",
}
_AFFILIATION_TERMS = {
    "official", "support", "customer support", "customer care",
    "verification", "verify", "refund", "help desk", "helpdesk",
    "careers", "human resources", "investor relations",
}
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _domain(value: str | None) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.hostname.casefold().removeprefix("www.") if parsed.hostname else ""


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    sequence_score = SequenceMatcher(None, _normalise(left), _normalise(right)).ratio()
    rapidfuzz_score = fuzz.WRatio(left, right) / 100 if fuzz else 0.0
    return max(sequence_score, rapidfuzz_score)


def _is_official(profile: SocialProfile, brand: BrandDetails) -> bool:
    handle = _normalise(profile.handle).removeprefix("at")
    official_handles = {_normalise(item).removeprefix("at") for item in brand.official_handles}
    profile_domain = _domain(profile.website)
    official_domains = {_domain(item) for item in brand.official_domains}
    exact_handle = handle in official_handles
    exact_brand_name = _normalise(profile.display_name) == _normalise(brand.name)
    return exact_handle or bool(
        profile_domain and profile_domain in official_domains and exact_brand_name
    )


def _risk_category(score: float) -> RiskCategory:
    if score >= 85:
        return RiskCategory.CRITICAL
    if score >= 65:
        return RiskCategory.HIGH
    if score >= 35:
        return RiskCategory.MEDIUM
    return RiskCategory.LOW


def analyze_profile(brand: BrandDetails, profile: SocialProfile) -> AnalysisResult:
    """Return explainable heuristic evidence; this is not an ML fraud verdict."""
    if _is_official(profile, brand):
        return AnalysisResult(
            analysis_id=f"ANL-{uuid.uuid4().hex[:10].upper()}",
            profile=profile,
            matched_brand=brand,
            explanations=["The submitted handle or website matches a registered official reference."],
        )

    signals: list[DetectionSignal] = []
    reasons: list[str] = []
    name_score = max(_similarity(profile.handle, brand.name), _similarity(profile.display_name, brand.name))
    official_handle_similarity = max((_similarity(profile.handle, item) for item in brand.official_handles), default=0)
    if max(name_score, official_handle_similarity) >= 0.72:
        score = min(100, round(max(name_score, official_handle_similarity) * 25, 2))
        signals.append(DetectionSignal(
            code="similar_brand_name", weight=score,
            explanation=f"Username or display name is {max(name_score, official_handle_similarity):.0%} similar to the registered brand.",
        ))
        reasons.append("Name similarity is evidence only and does not prove impersonation.")

    text = f"{profile.display_name} {profile.bio}".casefold()
    matched_terms = sorted(term for term in _AFFILIATION_TERMS if term in text)
    if matched_terms:
        signals.append(DetectionSignal(
            code="misleading_affiliation_terms", weight=min(20, len(matched_terms) * 7),
            explanation=f"Description uses affiliation terms: {', '.join(matched_terms)}.",
        ))
        reasons.append("Profile description claims or implies a company relationship.")

    scam_terms = sorted(term for term in _SCAM_TERMS if term in text)
    if scam_terms:
        signals.append(DetectionSignal(
            code="scam_language", weight=min(35, len(scam_terms) * 12),
            explanation=f"Description contains scam indicators: {', '.join(scam_terms)}.",
        ))
        reasons.append("Profile description contains requests or claims commonly associated with scams.")

    profile_domain = _domain(profile.website)
    official_domains = {_domain(item) for item in brand.official_domains}
    if profile_domain and official_domains and profile_domain not in official_domains:
        domain_similarity = max((_similarity(profile_domain, item) for item in official_domains), default=0)
        signals.append(DetectionSignal(
            code="untrusted_or_lookalike_domain", weight=25 if domain_similarity >= 0.7 else 30,
            explanation=f"Website domain '{profile_domain}' does not match an official registered domain.",
        ))
        reasons.append("Website ownership was not verified; the domain differs from the registered reference.")

    logo_similarity = profile.logo_similarity or (100 if profile.logo_match is True else 0)
    if logo_similarity >= 70:
        signals.append(DetectionSignal(
            code="logo_similarity", weight=20,
            explanation=f"Supplied logo evidence has a similarity score of {logo_similarity:.0f}%.",
        ))
        reasons.append("Logo similarity is supplied evidence and is not an ownership verification.")

    if profile.handle.casefold().strip("@") not in {item.casefold().strip("@") for item in brand.official_handles}:
        signals.append(DetectionSignal(
            code="unverified_brand_account", weight=10 if (name_score >= 0.72 or matched_terms) else 0,
            explanation="Submitted account is not one of the registered official handles.",
        ))

    signals = [signal for signal in signals if signal.weight > 0]
    risk_score = min(100, round(sum(signal.weight for signal in signals), 2))
    category = _risk_category(risk_score)
    finding_list: list[Finding] = []
    if risk_score >= 35:
        confidence = min(0.99, risk_score / 100)
        base_reasons = reasons or ["No strong impersonation signal was detected."]
        if scam_terms:
            finding_list.append(Finding(
                profile=profile.handle,
                risk_type=RiskType.SCAM_PROFILE,
                severity=category.value.lower(),
                confidence=confidence,
                reasons=base_reasons,
            ))
        if matched_terms:
            finding_list.append(Finding(
                profile=profile.handle,
                risk_type=RiskType.FAKE_COMPANY_PAGE,
                severity=category.value.lower(),
                confidence=confidence,
                reasons=base_reasons,
            ))
        if name_score >= 0.72 or logo_similarity >= 70:
            finding_list.append(Finding(
                profile=profile.handle,
                risk_type=RiskType.BRAND_SIMILARITY,
                severity=category.value.lower(),
                confidence=confidence,
                reasons=base_reasons,
            ))
        if (name_score >= 0.72 or logo_similarity >= 70) and (
            profile_domain not in official_domains or not profile.has_verified_badge
        ):
            finding_list.append(Finding(
                profile=profile.handle,
                risk_type=RiskType.BRAND_IMPERSONATION,
                severity=category.value.lower(),
                confidence=confidence,
                reasons=base_reasons,
            ))
    return AnalysisResult(
        analysis_id=f"ANL-{uuid.uuid4().hex[:10].upper()}",
        profile=profile,
        matched_brand=brand,
        risk_score=risk_score,
        risk_category=category,
        detected_signals=signals,
        explanations=reasons or ["No strong impersonation signal was detected."],
        findings=finding_list,
        analysed_profiles=1,
        summary={category.value.lower(): 1} if finding_list else {},
    )


def analyse_profiles(brand: BrandDetails, profiles: list[SocialProfile]) -> AnalysisResult:
    """Backward-compatible batch endpoint using the detailed single-profile analyzer."""
    analyses = [analyze_profile(brand, profile) for profile in profiles]
    findings = [finding for result in analyses for finding in result.findings]
    summary = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    findings.sort(key=lambda item: (-_SEVERITY_ORDER[item.severity], -item.confidence, item.profile.casefold()))
    return AnalysisResult(
        matched_brand=brand,
        findings=findings,
        analysed_profiles=len(profiles),
        summary=summary,
        risk_score=max((result.risk_score for result in analyses), default=0),
        risk_category=max((result.risk_category for result in analyses), key=lambda item: list(RiskCategory).index(item), default=RiskCategory.LOW),
        detected_signals=[signal for result in analyses for signal in result.detected_signals],
        explanations=[explanation for result in analyses for explanation in result.explanations],
    )
