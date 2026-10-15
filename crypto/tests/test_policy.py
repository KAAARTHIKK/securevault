import pytest

from crypto import policy

KNOWN = {"DEPT_CSE", "DEPT_ECE", "ROLE_FACULTY", "ROLE_HOD", "ROLE_STUDENT"}


def test_valid_policy_passes():
    policy.validate("(DEPT_CSE and ROLE_FACULTY) or ROLE_HOD", KNOWN)


def test_c11_unknown_attribute_rejected():
    with pytest.raises(ValueError):
        policy.validate("DEPT_MATH and ROLE_FACULTY", KNOWN)


def test_c11_injection_like_string_rejected():
    with pytest.raises(ValueError):
        policy.validate("DEPT_CSE; DROP TABLE users;--", KNOWN)


def test_c11_lowercase_attribute_rejected():
    with pytest.raises(ValueError):
        policy.validate("dept_cse and role_faculty", KNOWN)


def test_c11_unbalanced_parens_rejected():
    with pytest.raises(ValueError):
        policy.validate("(DEPT_CSE and ROLE_FACULTY", KNOWN)


def test_c11_dangling_operator_rejected():
    with pytest.raises(ValueError):
        policy.validate("DEPT_CSE and", KNOWN)


def test_versioned_rewrite():
    versions = {"DEPT_CSE": 1, "ROLE_FACULTY": 3, "ROLE_HOD": 1}
    result = policy.to_versioned("(DEPT_CSE and ROLE_FACULTY) or ROLE_HOD", KNOWN, versions)
    assert result == "(DEPT_CSE_V1 and ROLE_FACULTY_V3) or ROLE_HOD_V1"


def test_to_logical_strips_versions():
    assert policy.to_logical("DEPT_CSE_V1 and ROLE_FACULTY_V3") == "DEPT_CSE and ROLE_FACULTY"
    assert policy.to_logical("(DEPT_CSE_V2 and ROLE_FACULTY_V4) or ROLE_HOD_V1") == \
        "(DEPT_CSE and ROLE_FACULTY) or ROLE_HOD"


def test_to_logical_round_trips_through_to_versioned():
    """What the re-key worker does: reduce a file's versioned policy back to
    logical form, then re-apply the current versions."""
    known = {"DEPT_CSE", "ROLE_FACULTY"}
    old = policy.to_versioned("DEPT_CSE and ROLE_FACULTY", known, {"DEPT_CSE": 1, "ROLE_FACULTY": 1})
    logical = policy.to_logical(old)
    new = policy.to_versioned(logical, known, {"DEPT_CSE": 1, "ROLE_FACULTY": 2})
    assert old == "DEPT_CSE_V1 and ROLE_FACULTY_V1"
    assert new == "DEPT_CSE_V1 and ROLE_FACULTY_V2"
