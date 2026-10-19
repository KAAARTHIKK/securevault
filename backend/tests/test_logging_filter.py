"""The secret-scrubbing logging filter (doc 08 Phase 4 item 4).

Global rule 1 forbids key material in any log line. These tests check the
backstop that catches an accidental leak: a traceback, a request repr, or
uvicorn's access log printing a pre-signed URL complete with its signature.
"""
import base64
import logging
import os

from backend.app.logging_filter import REDACTED, SecretScrubFilter, install, scrub


def _record(message, *args):
    return logging.LogRecord("t", logging.INFO, __file__, 1, message, args, None)


def test_presigned_url_signature_is_redacted():
    url = ("https://bucket.s3.ap-south-1.amazonaws.com/objects/abc/1.svlt"
           "?X-Amz-Credential=AKIAEXAMPLE%2F20260101%2Fap-south-1%2Fs3%2Faws4_request"
           "&X-Amz-Expires=300&X-Amz-Signature=4f6c9a2b7e1d3c8f5a0b2e4d6c8a1f3b")
    cleaned = scrub(url)
    assert "4f6c9a2b7e1d3c8f5a0b2e4d6c8a1f3b" not in cleaned
    assert "AKIAEXAMPLE" not in cleaned
    assert "X-Amz-Expires=300" in cleaned  # harmless parts survive


def test_bearer_token_and_jwt_are_redacted():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
           ".eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ"
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    assert jwt not in scrub("Authorization: Bearer %s" % jwt)
    assert jwt not in scrub('{"access_token": "%s"}' % jwt)


def test_file_key_is_redacted_in_every_encoding():
    key = os.urandom(32)
    for encoded in (key.hex(), base64.b64encode(key).decode()):
        assert encoded not in scrub("recovered key=%s" % encoded)


def test_key_material_json_fields_are_redacted():
    cleaned = scrub('{"sk": "AAEC", "ct_key": "BBDD", "username": "prof_a"}')
    assert '"sk": "%s"' % REDACTED in cleaned
    assert '"ct_key": "%s"' % REDACTED in cleaned
    assert "prof_a" in cleaned, "non-secret fields must stay readable"


def test_configured_secrets_are_redacted_by_literal():
    secret = "a-very-real-jwt-secret-value-0123456789"
    scrubber = SecretScrubFilter(literals=(secret,))
    record = _record("startup used %s", secret)
    assert scrubber.filter(record) is True
    assert secret not in record.getMessage()


def test_short_literals_are_ignored():
    """A 3-character secret would redact half of every message."""
    scrubber = SecretScrubFilter(literals=("abc",))
    record = _record("abc is everywhere in abcdef")
    scrubber.filter(record)
    assert "abc is everywhere" in record.getMessage()


def test_filter_never_drops_records_and_leaves_clean_lines_alone():
    scrubber = SecretScrubFilter()
    record = _record("GET /api/v1/files 200")
    assert scrubber.filter(record) is True
    assert record.getMessage() == "GET /api/v1/files 200"


def test_install_attaches_to_handlers(caplog):
    install(literals=("another-long-secret-value",))
    logger = logging.getLogger("uvicorn.access")
    assert any(isinstance(f, SecretScrubFilter) for f in logger.filters)
