"""Core configuration — hardcoded for development."""
from __future__ import annotations


class Settings:
    supabase_url: str = "https://xbosoldcnfhtshqfvxdn.supabase.co"
    supabase_anon_key: str = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inhib3NvbGRjbmZodHNocWZ2eGRuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM3MjA4NDksImV4cCI6MjA4OTI5Njg0OX0"
        ".GCKcHRFOJA_ok69W5F683gRc0irWNsGQPcmtj04OND4"
    )
    supabase_jwt_secret: str = ""
    supabase_jwks_url: str = "https://xbosoldcnfhtshqfvxdn.supabase.co/auth/v1/.well-known/jwks.json"
    redis_url: str = "redis://redis:6379"
    frontend_url: str = "http://localhost:3000"


settings = Settings()
