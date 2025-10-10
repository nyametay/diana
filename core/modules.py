from flask_jwt_extended import create_refresh_token
from sentence_transformers import SentenceTransformer
import numpy as np
from PyPDF2 import PdfReader
import docx
import re
from core.models import *
from core import *


# ---------- Helper functions ----------
def create_session_for_user(user_id):
    refresh = create_refresh_token(identity=user_id)
    expires_at = datetime.now(timezone.utc) + app.config["JWT_REFRESH_TOKEN_EXPIRES"]
    session = Session(user_id=user_id, token=refresh, expires_at=expires_at)
    db.session.add(session)
    db.session.commit()
    return session


def revoke_refresh_token(refresh_token):
    session = Session.query.filter_by(token=refresh_token, revoked=False).first()
    if session:
        session.revoked = True
        db.session.commit()
        return True
    return False


# load once at startup
hf_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

def get_embedding_for_text(text: str):
    """
    Generate an embedding using Hugging Face model (local).
    """
    embedding = hf_model.encode(text, convert_to_numpy=True)
    return embedding.tolist()  # convert numpy -> Python list


def cosine_similarity(a, b):
    a = np.array(a, dtype=np.float32)
    b = np.array(b, dtype=np.float32)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50):
    """
    Split text into chunks with overlap.
    chunk_size and overlap are in words (not tokens).
    """
    words = re.split(r"\s+", text)
    chunks = []
    start = 0
    idx = 0

    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        if chunk.strip():
            chunks.append((idx, chunk))  # return (index, text)
            idx += 1
        start += chunk_size - overlap

    return chunks

ALLOWED_EXTENSIONS = {"txt", "md", "py", "pdf", "docx"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_content(file_type, file) -> str:
    """
    Extract text content from supported file types.
    Returns a string (may be empty if no text found).
    """
    content = ""

    if file_type in {"txt", "md", "py"}:
        file.seek(0)  # ensure reading from start
        content = file.read().decode("utf-8")

    elif file_type == "pdf":
        file.seek(0)
        reader = PdfReader(file)
        content = "\n".join([page.extract_text() or "" for page in reader.pages])

    elif file_type == "docx":
        file.seek(0)
        doc = docx.Document(file)
        content = "\n".join([p.text for p in doc.paragraphs])

    else:
        raise ValueError(f"Unsupported file type: {file_type}")
    return content.strip()