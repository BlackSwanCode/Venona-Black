from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

class SearchResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    url: str
    snippet: str
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_html_hash: Optional[str] = None

class IOC(BaseModel):
    value: str
    type: str  # EMAIL, IPV4, DOMAIN, URL, PHONE, HASH_MD5, HASH_SHA256
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    enrichment: Optional[Dict[str, Any]] = None

class Leak(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_value: str
    signature_type: str  # PASSWORD, API_KEY, IBAN, SSN, etc.
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    snippet: str
    source_url: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Case(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    target_scope: str
    status: str = "OPEN"  # OPEN, CLOSED, ARCHIVED
    created_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: Optional[datetime] = None
    investigator: Optional[str] = None

class WatchlistItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    term: str
    type: str  # EMAIL, DOMAIN, KEYWORD
    is_active: bool = True

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    watchlist_term: str
    alert_type: str  # LEAK, NEW_IOC, INFRA_CHANGE
    severity: str
    details: str
    status: str = "NEW"  # NEW, VIEWED, RESOLVED, FALSE_POSITIVE
    triggered_at: datetime = Field(default_factory=datetime.utcnow)

class EnrichmentResult(BaseModel):
    ioc_value: str
    ioc_type: str
    source: str  # cache, live, error
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
