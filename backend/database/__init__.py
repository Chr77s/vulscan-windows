"""Couche de persistance SQLite (scans, findings, stats)."""
from .db import init_db, save_scan, list_scans, get_scan, delete_scan, diff_scans
__all__ = ["init_db", "save_scan", "list_scans", "get_scan", "delete_scan", "diff_scans"]
