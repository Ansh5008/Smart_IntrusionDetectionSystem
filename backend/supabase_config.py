"""Supabase client configuration for Smart-IDS."""
from __future__ import annotations

from supabase import create_client, Client

SUPABASE_URL = "https://xbosoldcnfhtshqfvxdn.supabase.co"
SUPABASE_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inhib3NvbGRjbmZodHNocWZ2eGRuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM3MjA4NDksImV4cCI6MjA4OTI5Njg0OX0"
    ".GCKcHRFOJA_ok69W5F683gRc0irWNsGQPcmtj04OND4"
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
