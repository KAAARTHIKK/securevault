"""Create demo attributes and the five seed users (doc 07 Section 3, doc 01 Section 4)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app import models  # noqa: E402
from backend.app.auth import hash_password  # noqa: E402
from backend.app.db import Base, get_engine, get_sessionmaker  # noqa: E402

ATTRIBUTE_UNIVERSE = [
    "DEPT_CSE", "DEPT_ECE", "DEPT_MECH",
    "ROLE_ADMIN", "ROLE_HOD", "ROLE_FACULTY", "ROLE_STUDENT",
    "YEAR_1", "YEAR_2", "YEAR_3", "YEAR_4",
]

SEED_USERS = [
    # admin key holds all attributes, needed to run the re-key worker (doc 02 Section 4.4)
    {"username": "admin", "password": "admin-pass", "is_admin": True, "attributes": ATTRIBUTE_UNIVERSE},
    {"username": "prof_a", "password": "prof-a-pass", "is_admin": False, "attributes": ["DEPT_CSE", "ROLE_FACULTY"]},
    {"username": "prof_b", "password": "prof-b-pass", "is_admin": False, "attributes": ["DEPT_CSE", "ROLE_FACULTY"]},
    {"username": "hod", "password": "hod-pass", "is_admin": False,
     "attributes": ["DEPT_CSE", "ROLE_HOD", "ROLE_FACULTY"]},
    {"username": "student_s", "password": "student-s-pass", "is_admin": False,
     "attributes": ["DEPT_CSE", "ROLE_STUDENT", "YEAR_4"]},
]


def main() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    session = get_sessionmaker()()
    try:
        attrs_by_name = {}
        for name in ATTRIBUTE_UNIVERSE:
            attr = session.query(models.Attribute).filter(models.Attribute.name == name).first()
            if attr is None:
                attr = models.Attribute(name=name, current_version=1)
                session.add(attr)
                session.flush()
            attrs_by_name[name] = attr

        for spec in SEED_USERS:
            if session.query(models.User).filter(models.User.username == spec["username"]).first():
                print("Skipping %s (already exists)" % spec["username"])
                continue
            user = models.User(
                username=spec["username"],
                password_hash=hash_password(spec["password"]),
                is_admin=spec["is_admin"],
                key_stale=True,
            )
            session.add(user)
            session.flush()
            for name in spec["attributes"]:
                session.add(models.UserAttribute(user_id=user.id, attribute_id=attrs_by_name[name].id))
            print("Created user %s (password: %s)" % (spec["username"], spec["password"]))

        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    main()
