from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import UUID, JSON
from datetime import datetime, timezone
from core import db
import uuid


# ---------- User ----------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(225), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    _password_hash = db.Column("password", db.String(255), nullable=False)  # hashed password
    role = db.Column(db.String(20), default="user")
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    sessions = db.relationship("Session", back_populates="user", cascade="all, delete-orphan")
    chats = db.relationship("ChatHistory", back_populates="user", cascade="all, delete-orphan")
    bookmarks = db.relationship("Bookmark", back_populates="user", cascade="all, delete-orphan")
    repositories = db.relationship("Repository", back_populates="user", cascade="all, delete-orphan")

    @property
    def password(self):
        raise AttributeError("Password is write-only.")

    @password.setter
    def password(self, plain_text_password):
        self._password_hash = generate_password_hash(plain_text_password)

    def check_password(self, plain_text_password):
        return check_password_hash(self._password_hash, plain_text_password)

    def to_dict(self, include_email=True):
        data = {
            "id": str(self.id),
            "username": self.username,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_email:
            data["email"] = self.email
        return data


# ---------- Session ----------
class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.Text, unique=True, nullable=False)
    summary = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked = db.Column(db.Boolean, default=False)

    user = db.relationship("User", back_populates="sessions")
    chats = db.relationship("ChatHistory", back_populates="session", cascade="all, delete-orphan")


# ---------- ChatHistory ----------
class ChatHistory(db.Model):
    __tablename__ = "chat_history"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(UUID(as_uuid=True), db.ForeignKey("sessions.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    chat_metadata = db.Column(JSON)

    user = db.relationship("User", back_populates="chats")
    session = db.relationship("Session", back_populates="chats")
    bookmarks = db.relationship("Bookmark", back_populates="chat", cascade="all, delete-orphan")


# ---------- Bookmark ----------
class Bookmark(db.Model):
    __tablename__ = "bookmarks"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    chat_id = db.Column(UUID(as_uuid=True), db.ForeignKey("chat_history.id"), nullable=True)
    repo_id = db.Column(UUID(as_uuid=True), db.ForeignKey("repositories.id"), nullable=True)
    title = db.Column(db.String(150))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", back_populates="bookmarks")
    chat = db.relationship("ChatHistory", back_populates="bookmarks")
    repo = db.relationship("Repository", back_populates="bookmarks")


# ---------- Repository ----------
class Repository(db.Model):
    __tablename__ = "repositories"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    repo_name = db.Column(db.String(150), nullable=False)
    repo_url = db.Column(db.Text, nullable=False)
    visibility = db.Column(db.String(20), default="private")
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", back_populates="repositories")
    files = db.relationship("File", back_populates="repository", cascade="all, delete-orphan")
    bookmarks = db.relationship("Bookmark", back_populates="repo", cascade="all, delete-orphan")


# ---------- File ----------
class File(db.Model):
    __tablename__ = "files"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_id = db.Column(UUID(as_uuid=True), db.ForeignKey("repositories.id"), nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text)
    file_type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    repository = db.relationship("Repository", back_populates="files")
    embeddings = db.relationship("Embedding", back_populates="file", cascade="all, delete-orphan")


# ---------- Embedding ----------
class Embedding(db.Model):
    __tablename__ = "embeddings"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id = db.Column(UUID(as_uuid=True), db.ForeignKey("files.id"), nullable=False)
    chunk_index = db.Column(db.Integer, nullable=False)
    chunk_text = db.Column(db.Text, nullable=False)
    embedding = db.Column(JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    file = db.relationship("File", back_populates="embeddings")

