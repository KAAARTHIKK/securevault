"""Shared fixtures for backend tests (doc 07 Section 1.2: moto + a real test DB).

The environment defaults below must be set before backend.app.config is first
imported: the tests run against moto and a throwaway database, so the .env
placeholder checks are relaxed with SECUREVAULT_DEV=1.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

os.environ.setdefault("SECUREVAULT_DEV", "1")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg2://sv:sv@localhost:5432/securevault_test")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("KA_PASSPHRASE", "test-ka-passphrase")
os.environ.setdefault("STORAGE_BACKEND", "moto")
os.environ.setdefault("AWS_REGION", "ap-south-1")
os.environ.setdefault("S3_BUCKET", "securevault-test-bucket")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from backend.app import key_authority, models
from backend.app.auth import hash_password
from backend.app.config import get_settings
from backend.app.db import Base, get_engine, get_sessionmaker
from backend.app.main import app


@pytest.fixture(scope="session", autouse=True)
def _schema():
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="session", autouse=True)
def _ka_keys():
    key_authority.setup_and_save()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Login throttling is process-global, so clear it between tests."""
    from backend.app import ratelimit
    ratelimit.reset()
    yield
    ratelimit.reset()


@pytest.fixture(autouse=True)
def _clean_tables():
    engine = get_engine()
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    yield


@pytest.fixture
def db_session():
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def moto_s3():
    with mock_aws():
        settings = get_settings()
        s3 = boto3.client("s3", region_name=settings.aws_region)
        s3.create_bucket(
            Bucket=settings.s3_bucket,
            CreateBucketConfiguration={"LocationConstraint": settings.aws_region},
        )
        yield s3


def make_user(db_session, username, password, is_admin=False, attributes=None, key_stale=True):
    user = models.User(
        username=username,
        password_hash=hash_password(password),
        is_admin=is_admin,
        key_stale=key_stale,
    )
    db_session.add(user)
    db_session.flush()
    for name in (attributes or []):
        attr = db_session.query(models.Attribute).filter(models.Attribute.name == name).first()
        if attr is None:
            attr = models.Attribute(name=name, current_version=1)
            db_session.add(attr)
            db_session.flush()
        db_session.add(models.UserAttribute(user_id=user.id, attribute_id=attr.id))
    db_session.commit()
    return user


def login(client, username, password):
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]
