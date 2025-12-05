from flask import request, jsonify
from core.modules import *
from core.models import *
from core.chat import *
from core import app, db
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
import uuid
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token # get_jwt


def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            user_id = uuid.UUID(get_jwt_identity())
            user = User.query.get(user_id)
            if not user or user.role != required_role:
                return jsonify({"msg": "forbidden"}), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper


# ---------- Admin Endpoints ---------
@app.route("/users", methods=["GET"])
@role_required("admin")
def list_users():
    users = User.query.all()
    out = [{
        "id": str(u.id),
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "created_at": u.created_at.isoformat()
    } for u in users]
    return jsonify({"count": len(out), "users": out})


@app.route("/users/<user_id>", methods=["DELETE"])
@role_required("admin")
def delete_user(user_id):
    u = User.query.get(user_id)
    if not u:
        return jsonify({"msg": "user not found"}), 404
    db.session.delete(u)
    db.session.commit()
    return jsonify({"msg": f"user {u.username} deleted"})


@app.route("/users/<user_id>/role", methods=["PATCH"])
@role_required("admin")
def update_user_role(user_id):
    data = request.json or {}
    new_role = data.get("role")
    if not new_role:
        return jsonify({"msg": "role required"}), 400

    u = User.query.get(user_id)
    if not u:
        return jsonify({"msg": "user not found"}), 404

    u.role = new_role
    db.session.commit()
    return jsonify({"msg": f"user {u.username} role updated to {new_role}"})


# ---------- Auth endpoints ----------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    if not username or not email or not password or not name:
        return jsonify({"msg": "name, username, email, password, role required"}), 400
    if User.query.filter((User.username==username)|(User.email==email)).first():
        return jsonify({"msg": "user with that username/email exists"}), 400
    user = User(username=username, email=email, name=name, role='user')
    user.password = password
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "user created", "user_id": user.id}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"msg": "email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "invalid credentials"}), 401
    access = create_access_token(identity=str(user.id))
    # make server-stored refresh token (session)
    session = create_session_for_user(user.id)
    return jsonify({
        "access_token": access,
        "refresh_token": session.token,
        "user_id": user.id,
        "expires_in": app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
    })


@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json or {}
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"msg": "refresh_token required"}), 400
    # check session exists and not revoked
    s = Session.query.filter_by(token=refresh_token, revoked=False).first()
    if not s or s.expires_at < datetime.now(timezone.utc):
        return jsonify({"msg": "invalid or expired refresh token"}), 401
    # create new access token
    access = create_access_token(identity=str(s.user_id))
    return jsonify({"access_token": access, "user_id": s.user_id})


@app.route("/logout", methods=["POST"])
def logout():
    data = request.json or {}
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"msg": "refresh_token required"}), 400
    revoked = revoke_refresh_token(refresh_token)
    if revoked:
        return jsonify({"msg": "logged out"}), 200
    return jsonify({"msg": "invalid token"}), 400


# ---------- User endpoints ----------
@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = uuid.UUID(get_jwt_identity())
    user = User.query.get(user_id)
    return jsonify({
        "id": user.id,
        "username": user.username,
        'name':user.name,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat()
    })


@app.route("/chat", methods=["POST"])
@jwt_required()
def chat():
    user_id = uuid.UUID(get_jwt_identity())
    data = request.json or {}
    message = data.get("message")
    session_id = data.get("session_id")
    context_window = int(data.get("context_window", 5))

    if not message:
        return jsonify({"msg": "message required"}), 400

    # If no session ID → create a new session
    if not session_id:
        s = Session(
            user_id=user_id,
            token=str(uuid.uuid4()),
            summary=None,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)
        )
        db.session.add(s)
        db.session.commit()
        session_id = str(s.id)

    # Load session
    session = Session.query.get(session_id)

    # Load recent messages for short-term context
    context_msgs = (
        ChatHistory.query
        .filter_by(user_id=user_id, session_id=session_id)
        .order_by(ChatHistory.timestamp.desc())
        .limit(context_window)
        .all()
    )
    context = [{"message": c.message, "response": c.response} for c in reversed(context_msgs)]

    # Full LLM
    response_text = generate(
        input_text=message,
        summary=session.summary or "",
        context=context
    )

    # Save chat
    chat_ = ChatHistory(
        user_id=user_id,
        session_id=session_id,
        message=message,
        response=response_text,
        chat_metadata={"context_count": len(context)}
    )
    db.session.add(chat_)
    db.session.commit()

    # Auto-summarization every 20 messages
    total_count = ChatHistory.query.filter_by(
        user_id=user_id,
        session_id=session_id
    ).count()

    if total_count % 20 == 0:
        full_history = ChatHistory.query.filter_by(
            user_id=user_id,
            session_id=session_id
        ).order_by(ChatHistory.timestamp.asc()).all()

        new_summary = summarize_chat(full_history)
        session.summary = new_summary
        db.session.commit()

    return jsonify({
        "chat_id": str(chat_.id),
        "session_id": str(session_id),
        "message": chat_.message,
        "response": chat_.response,
        "timestamp": chat_.timestamp.isoformat()
    })


@app.route("/chats", methods=["GET"])
@jwt_required()
def get_chats():
    user_id = uuid.UUID(get_jwt_identity())
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    q = ChatHistory.query.filter_by(user_id=user_id).order_by(ChatHistory.timestamp.desc())
    pag = q.paginate(page=page, per_page=per_page, error_out=False)
    items = [{
        "id": str(c.id), "message": c.message, "response": c.response, "timestamp": c.timestamp.isoformat()
    } for c in pag.items]
    return jsonify({"total": pag.total, "page": page, "per_page": per_page, "items": items})


@app.route("/sessions", methods=["GET"])
@jwt_required()
def list_sessions():
    user_id = uuid.UUID(get_jwt_identity())
    sessions = Session.query.filter_by(user_id=user_id).order_by(Session.created_at.desc()).all()
    out = [{
        "id": str(s.id),
        "created_at": s.created_at.isoformat(),
        "revoked": s.revoked
    } for s in sessions]
    return jsonify({"count": len(out), "sessions": out})


# ---------- Repositories & files ----------
@app.route("/repos", methods=["POST"])
@jwt_required()
def create_repo():
    user_id = uuid.UUID(get_jwt_identity())
    data = request.json or {}
    repo_name = data.get("repo_name")
    repo_url = data.get("repo_url")
    visibility = data.get("visibility", "private")
    if not repo_name or not repo_url:
        return jsonify({"msg": "repo_name and repo_url required"}), 400
    r = Repository(user_id=user_id, repo_name=repo_name, repo_url=repo_url, visibility=visibility)
    db.session.add(r)
    db.session.commit()
    return jsonify({"repo_id": r.id, "repo_name": r.repo_name}), 201


@app.route("/repos/<repo_id>/files", methods=["POST"])
@jwt_required()
def add_file(repo_id):
    user_id = uuid.UUID(get_jwt_identity())
    repo = Repository.query.filter_by(id=repo_id, user_id=user_id).first()
    if not repo:
        return jsonify({"msg": "repo not found"}), 404

    content = ""
    file_path = None
    file_type = None

    # ---------- Case 1: JSON body ----------
    if request.is_json:
        data = request.json or {}
        file_path = data.get("file_path")
        content = data.get("content", "")
        file_type = data.get("file_type")

        if not file_path:
            return jsonify({"msg": "file_path required"}), 400

    # ---------- Case 2: File upload ----------
    elif "file" in request.files:
        file = request.files["file"]

        if file.filename == "":
            return jsonify({"msg": "no file selected"}), 400
        if not allowed_file(file.filename):
            return jsonify({"msg": "file type not allowed"}), 400

        filename = secure_filename(file.filename)
        file_path = filename
        file_type = filename.rsplit(".", 1)[1].lower()
        content = get_file_content(file_type, file)
    else:
        return jsonify({"msg": "must provide raw JSON or upload a file"}), 400

    # ---------- Save or Update File ----------
    existing_file = File.query.filter_by(repo_id=repo.id, file_path=file_path).first()
    if existing_file:
        # Update file content
        existing_file.content = content
        existing_file.file_type = file_type
        # Delete old embeddings
        Embedding.query.filter_by(file_id=existing_file.id).delete()
        f = existing_file
    else:
        f = File(repo_id=repo.id, file_path=file_path, content=content, file_type=file_type)
        db.session.add(f)
        db.session.flush()  # ensures f.id is available

    # ---------- Chunk & Ingest ----------
    chunks = chunk_text(content)
    created = []
    for idx, chunk in chunks:
        embedding = get_embedding_for_text(chunk)
        emb = Embedding(file_id=f.id, chunk_index=idx, chunk_text=chunk, embedding=embedding)
        db.session.add(emb)
        created.append(emb)

    db.session.commit()

    return jsonify({
        "file_id": str(f.id),
        "file_path": f.file_path,
        "file_type": f.file_type,
        "length": len(content),
        "chunks_created": len(created),
        "updated": existing_file is not None
    }), 201


# Simple ingestion endpoint that also creates embeddings (stub)
@app.route("/repos/<repo_id>/ingest", methods=["POST"])
@jwt_required()
def ingest_repo(repo_id):
    """
    Optional re-ingestion endpoint.
    Body:
      {"chunks": [{"file_id": "...", "chunk_text": "text"}, ...]}
    Hugging Face will generate embeddings automatically.
    Useful if you want to reprocess files with a new model or new chunking rules.
    """
    user_id = uuid.UUID(get_jwt_identity())
    repo = Repository.query.filter_by(id=repo_id, user_id=user_id).first()
    if not repo:
        return jsonify({"msg": "repo not found"}), 404

    data = request.json or {}
    chunks = data.get("chunks", [])
    created = []

    for c in chunks:
        file_id = c.get("file_id")
        chunk_text_ = c.get("chunk_text")
        if not file_id or not chunk_text_:
            continue

        f = File.query.filter_by(id=file_id, repo_id=repo.id).first()
        if not f:
            continue

        embedding = get_embedding_for_text(chunk_text_)
        emb = Embedding(file_id=f.id, chunk_text=chunk_text_, embedding=embedding)
        db.session.add(emb)
        created.append(emb)

    db.session.commit()
    return jsonify({"created": len(created)}), 201


# ---------- Search (simple keyword; placeholder for semantic search) ----------
@app.route("/search", methods=["GET"])
@jwt_required()
def search():
    """
    Query args:
      q (query string)
      use_semantic (optional, boolean flag)
      top_k (optional, default=10)
    """
    user_id = uuid.UUID(get_jwt_identity())
    q = request.args.get("q", "")
    use_semantic = request.args.get("use_semantic", "false").lower() == "true"
    top_k = int(request.args.get("top_k", 10))

    if not q:
        return jsonify({"msg": "q param required"}), 400

    results = []

    # ---------- Keyword search ----------
    files = File.query.join(Repository).filter(
        Repository.user_id == user_id,
        File.content.ilike(f"%{q}%")
    ).all()

    for f in files:
        results.append({
            "file_id": str(f.id),
            "repo_id": str(f.repo_id),
            "file_path": f.file_path,
            "snippet": (f.content[:400] + "...") if f.content and len(f.content) > 400 else f.content,
            "score": 1.0,
            "method": "keyword"
        })

    # ---------- Semantic search ----------
    if use_semantic:
        query_embedding = get_embedding_for_text(q)

        all_embeddings = Embedding.query.join(File).join(Repository).filter(
            Repository.user_id == user_id
        ).all()

        semantic_results = []
        for emb in all_embeddings:
            score = cosine_similarity(query_embedding, emb.embedding)
            semantic_results.append({
                "file_id": str(emb.file_id),
                "chunk_id": str(emb.id),
                "chunk_index": emb.chunk_index,   # ✅ NEW: helps reconstruct context
                "chunk_text": emb.chunk_text[:200] + "...",
                "score": score,
                "method": "semantic"
            })

        # Sort by similarity
        semantic_results = sorted(semantic_results, key=lambda x: x["score"], reverse=True)
        results.extend(semantic_results[:top_k])

    return jsonify({
        "q": q,
        "count": len(results),
        "results": results[:top_k]  # ensure top_k applies globally
    })


# ---------- Bookmarks ----------
@app.route("/bookmarks", methods=["POST"])
@jwt_required()
def create_bookmark():
    user_id = uuid.UUID(get_jwt_identity())
    data = request.json or {}
    chat_id = data.get("chat_id")
    repo_id = data.get("repo_id")
    file_id = data.get("file_id")
    title = data.get("title") or "Untitled Bookmark"
    # Basic validation - must reference something
    if not (chat_id or repo_id or file_id):
        return jsonify({"msg": "chat_id, repo_id, or file_id required"}), 400
    bm = Bookmark(user_id=user_id, chat_id=chat_id, repo_id=repo_id, file_id=file_id, title=title)
    db.session.add(bm)
    db.session.commit()
    return jsonify({"bookmark_id": str(bm.id)}), 201


@app.route("/bookmarks", methods=["GET"])
@jwt_required()
def list_bookmarks():
    user_id = uuid.UUID(get_jwt_identity())
    bms = Bookmark.query.filter_by(user_id=user_id).order_by(Bookmark.created_at.desc()).all()
    out = []
    for b in bms:
        out.append({
            "id": str(b.id),
            "title": b.title,
            "chat_id": str(b.chat_id),
            "repo_id": str(b.repo_id),
            "file_id": str(b.file_id),
            "created_at": b.created_at.isoformat()
        })
    return jsonify({"count": len(out), "bookmarks": out})


@app.route("/bookmarks/<bookmark_id>", methods=["GET"])
@jwt_required()
def get_bookmark(bookmark_id):
    user_id = uuid.UUID(get_jwt_identity())
    bm = Bookmark.query.filter_by(id=bookmark_id, user_id=user_id).first()
    if not bm:
        return jsonify({"msg": "bookmark not found"}), 404

    return jsonify({
        "id": str(bm.id),
        "title": bm.title,
        "chat_id": str(bm.chat_id) if bm.chat_id else None,
        "repo_id": str(bm.repo_id) if bm.repo_id else None,
        "file_id": str(bm.file_id) if bm.file_id else None,
        "created_at": bm.created_at.isoformat()
    })


@app.route("/bookmarks/<bookmark_id>", methods=["DELETE"])
@jwt_required()
def delete_bookmark(bookmark_id):
    user_id = uuid.UUID(get_jwt_identity())
    bm = Bookmark.query.filter_by(id=bookmark_id, user_id=user_id).first()
    if not bm:
        return jsonify({"msg": "bookmark not found"}), 404

    db.session.delete(bm)
    db.session.commit()
    return jsonify({"msg": "bookmark deleted"})


# ---------- Health ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200
