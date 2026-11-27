"""
Dịch vụ truy vấn và tạo tài khoản người dùng - Issue #5.1.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from models.user import VALID_ROLES, User


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


def list_users(db: Session, limit: int = 200) -> list[User]:
    """Liệt kê danh sách tài khoản người dùng phục vụ quản trị viên."""
    return db.query(User).order_by(User.id.asc()).limit(limit).all()


def update_user_admin(
    db: Session,
    *,
    target_user_id: int,
    actor_user_id: int,
    role: str | None = None,
    is_active: bool | None = None,
) -> User:
    """
    Cập nhật vai trò hoặc trạng thái hoạt động của người dùng (chỉ dành cho Admin).
    Ngăn quản trị viên tự hạ quyền hoặc tự khóa chính tài khoản đang đăng nhập.
    """
    user = db.get(User, target_user_id)
    if user is None:
        raise LookupError("Không tìm thấy người dùng.")

    if role is not None:
        cleaned_role = role.strip().lower()
        if cleaned_role not in VALID_ROLES:
            raise ValueError(f"Vai trò không hợp lệ. Chỉ hỗ trợ: {', '.join(VALID_ROLES)}.")
        if user.id == actor_user_id and cleaned_role != "admin":
            raise ValueError("Quản trị viên không thể tự hạ quyền của chính mình.")
        user.role = cleaned_role

    if is_active is not None:
        if not isinstance(is_active, bool):
            raise ValueError("is_active phải là kiểu boolean.")
        if user.id == actor_user_id and not is_active:
            raise ValueError("Quản trị viên không thể tự vô hiệu hóa tài khoản của chính mình.")
        user.is_active = is_active

    db.commit()
    db.refresh(user)
    return user