# 🧠 Diana Platform – Backend API

**Diana** is a lightweight, intelligent backend system built with **Flask**, **SQLAlchemy**, and **Hugging Face embeddings** for semantic search and chat context retrieval.  
It supports **user management**, **repositories**, **file ingestion**, **semantic search**, **chat history**, and **bookmarks**, with **JWT authentication** and **role-based access control** (admin vs user).

---

## 🚀 Tech Stack

| Layer | Technology |
|-------|-------------|
| **Framework** | Flask (Python) |
| **ORM** | SQLAlchemy |
| **Database** | PostgreSQL |
| **Authentication** | Flask-JWT-Extended |
| **Embeddings** | Hugging Face Sentence Transformers |
| **Vector Handling** | JSON-stored embeddings (pgvector optional) |
| **Environment** | Railway / Local PostgreSQL |
| **Versioning** | Git & GitHub |

---

## 🧩 Project Structure
📦 diana-backend
┣ 📂 core
┃ ┣ 📜 models.py # SQLAlchemy ORM models
┃ ┣ 📜 routes.py # All Flask API routes
┃ ┣ 📜 modules.py # Helper functions
┃ ┣ 📜 init.py # App factory & DB init
┣ 📜 app.py # Main entry point
┣ 📜 requirements.txt # Dependencies
┣ 📜 README.md # Project documentation
┗ 📜 .env.example # Environment variable template


---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository
```bash
git clone https://github.com/nyametay/diana.git
cd diana-backend
```

## 2️⃣ Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # macOS/Linux
```

## 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

## 4️⃣ Configure your environment
Create a .env file:
env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=supersecretkey
JWT_SECRET_KEY=yourjwtsecret
SQLALCHEMY_DATABASE_URI=postgresql+psycopg2://user:password@host:port/dbname

## 🧱 Database Setup
If using Railway, add a PostgreSQL plugin and copy its connection string.

Initialize tables:

```bash
flask shell
>>> from core import db
>>> db.create_all()
```

## 🔑 Authentication
Diana uses JWT tokens for stateless authentication.

| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **POST** | `/signup` | Create a new user *(role=user by default)* |
| **POST** | `/login` | Get access & refresh tokens |
| **POST** | `/refresh` | Refresh your access token |
| **POST** | `/logout` | Revoke refresh token |
| **GET** | `/me` | Get current user profile |


💡 Admin users must be manually promoted once via database or /users/<id>/role route.

## 👑 Admin Endpoints
| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **GET** | `/users` | List all users *(admin only)* |
| **PATCH** | `/users/<id>/role` | Update user role *(admin only)* |
| **DELETE** | `/users/<id>` | Delete user *(admin only)* |


### Authorization header:

```makefile
Authorization: Bearer <admin_token>
```

## 📁 Repositories & Files
| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **POST** | `/repos` | Create a new repository |
| **POST** | `/repos/<repo_id>/files` | Add or upload file |
| **POST** | `/repos/<repo_id>/ingest` | Generate embeddings for repo files |

### Supported File Types
.txt, .md, .py

.pdf

.docx

## 🔍 Search API
| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **GET** | `/search?q=your+query` | Keyword search |
| **GET** | `/search?q=your+query&use_semantic=true` | Semantic search *(Hugging Face embeddings)* |


Example:

```bash
curl -H "Authorization: Bearer <token>" \
"http://localhost:5000/search?q=machine+learning&use_semantic=true"
```

## 💬 Chat API
| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **POST** | `/chat` | Send a message *(stubbed LLM reply for now)* |
| **GET** | `/chats` | Retrieve previous chat history |


The LLM currently returns mock responses ("[LLM response to] <reversed input>"),
but can be integrated with OpenAI, Anthropic, or local LLMs later.

## 🔖 Bookmarks API
| Method | Endpoint | Description |
|:--------|:----------|:-------------|
| **POST** | `/bookmarks` | Save bookmark for a chat, repo, or file |
| **GET** | `/bookmarks` | Retrieve all bookmarks |


## 🧠 Embedding Generation
This project uses Hugging Face Sentence Transformers locally instead of pgvector.

```python
from sentence_transformers import SentenceTransformer

hf_model = SentenceTransformer("all-MiniLM-L6-v2")

def get_embedding_for_text(text):
    embedding = hf_model.encode(text, convert_to_numpy=True)
    return embedding.tolist()
```
Embeddings are stored as JSON in PostgreSQL.

## 🔐 Role-Based Access Control
User → Can manage repos, files, chats, and bookmarks.

Admin → Full control over user management and roles.

Bootstrap your first admin manually:

```sql
UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';
```

## 🧪 Testing with Postman
Sign up → /signup

Log in → /login

Copy the returned access_token

Add this header in Postman:

```makefile
Authorization: Bearer <access_token>
Call protected routes such as /repos, /search, /chats, etc.
```

## 🧩 Planned Improvements
✅ Step 8: Replace JSON embeddings with pgvector (when available)

🔄 Step 9: Add audit logging for all actions

🤖 Step 10: Integrate OpenAI / local LLM

💾 Step 11: Add file preview & download endpoints

🧱 Step 12: Build admin dashboard UI

## 🧰 Run the App
```bash
flask run
Server runs on:

arduino
http://localhost:5000
```
## 🧑‍💻 Author
Isaac Nyame Taylor
© 2025 — Diana Platform MVP
