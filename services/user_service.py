"""
Dịch vụ truy vấn và tạo tài khoản người dùng - Issue #5.1.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from models.user import User


def create_user(db: Session, username: str, email: str, password: str) -> User:
    """Tạo và lưu một tài khoản mới."""
    user = User(username=username, email=email)
    user.set_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_by_username(db: Session, username: str) -> User | None:
    """Tìm người dùng theo username."""
    return db.query(User).filter(User.username == username).first()


def get_by_id(db: Session, user_id: int) -> User | None:
    """Tìm người dùng theo khóa chính."""
    return db.get(User, user_id)