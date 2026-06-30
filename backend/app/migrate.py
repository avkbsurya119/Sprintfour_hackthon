"""
Database migration script: adds new columns for Phase 1 ensemble improvements.

Run this script to update an existing database with the new columns:
- detector_spans.pii_category
- detector_spans.confidence_score
- detector_spans.is_manual
- risk_flags.confidence_score
- risk_flags.is_manual

Usage:
    python -m app.migrate
"""
import sqlite3
from pathlib import Path

# Path to the SQLite database
DB_PATH = Path(__file__).parent.parent / "conseal_review.db"


def migrate():
    """Add new columns to existing tables."""
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        print("Run the seed script first to create the database.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check existing columns in detector_spans
    cursor.execute("PRAGMA table_info(detector_spans)")
    detector_columns = {row[1] for row in cursor.fetchall()}

    # Check existing columns in risk_flags
    cursor.execute("PRAGMA table_info(risk_flags)")
    risk_columns = {row[1] for row in cursor.fetchall()}

    migrations_applied = []

    # Add columns to detector_spans
    if "pii_category" not in detector_columns:
        cursor.execute("ALTER TABLE detector_spans ADD COLUMN pii_category VARCHAR(50)")
        migrations_applied.append("detector_spans.pii_category")

    if "confidence_score" not in detector_columns:
        cursor.execute("ALTER TABLE detector_spans ADD COLUMN confidence_score INTEGER")
        migrations_applied.append("detector_spans.confidence_score")

    if "is_manual" not in detector_columns:
        cursor.execute("ALTER TABLE detector_spans ADD COLUMN is_manual INTEGER DEFAULT 0")
        migrations_applied.append("detector_spans.is_manual")

    # Add columns to risk_flags
    if "confidence_score" not in risk_columns:
        cursor.execute("ALTER TABLE risk_flags ADD COLUMN confidence_score INTEGER")
        migrations_applied.append("risk_flags.confidence_score")

    if "is_manual" not in risk_columns:
        cursor.execute("ALTER TABLE risk_flags ADD COLUMN is_manual INTEGER DEFAULT 0")
        migrations_applied.append("risk_flags.is_manual")

    conn.commit()
    conn.close()

    if migrations_applied:
        print("Migrations applied:")
        for m in migrations_applied:
            print(f"  + {m}")
        print("\nDatabase updated successfully.")
    else:
        print("No migrations needed. Database is up to date.")


if __name__ == "__main__":
    migrate()
