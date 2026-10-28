"""
Configuration de la base de données souveraine (Zero-Knowledge Server Store).
Compatible SQLite (développement local / déploiement léger) et PostgreSQL (production).
Aucune donnée de message ou de fichier en clair n'est jamais persistée dans cette base.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./faso_secur_sovereign.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Fournit une session de base de données par requête FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
