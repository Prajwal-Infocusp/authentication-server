# Initial Project Setup

**Date:** 9 July 2026
**Model:** Gemini 3.5 flash
**Purpose:** Generate the initial FastAPI project structure, SQLAlchemy models, Alembic configuration, and PostgreSQL setup.

---

## Prompt

I want to build a **production-style Authentication & Authorization Service** using the following stack:

* Python 3.13+
* FastAPI
* PostgreSQL
* SQLAlchemy 2.x (ORM)
* Alembic (database migrations)
* Pydantic v2
* JWT Authentication
* TOTP (Authenticator App) for 2FA
* UV package manager (if needed)

Do **NOT** generate API endpoints yet. I want to first build a clean project foundation and database layer.

## Project Goals

This service should support:

* User Registration
* User Login
* JWT Access Tokens
* Refresh Tokens
* Logout
* TOTP (Authenticator App) based Two-Factor Authentication
* Email Verification (implemented later)
* Password Reset (implemented later)

The project should be modular, scalable, and follow good FastAPI architecture.

---

# Project Structure

Please create a recommended folder structure similar to a real-world production FastAPI application.

Example (you may improve it if necessary):

app/
main.py

```
config/
    settings.py

db/
    database.py
    base.py
    models/

api/

schemas/

services/

security/

utils/
```

alembic/

Requirements:

* Separate database models from API routes.
* Keep business logic inside services.
* Keep configuration centralized.
* Follow SQLAlchemy 2.x style.
* Organize code so future features can be added easily.

Explain why each folder exists.

---

# Database Design

Use PostgreSQL.

Create SQLAlchemy ORM models for the following tables.

## users

Fields:

* id (UUID, Primary Key)
* name
* email (Unique)
* password_hash
* is_email_verified
* totp_secret (nullable)
* is_2fa_enabled
* created_at
* updated_at

---

## refresh_tokens

Fields:

* id (UUID, Primary Key)
* user_id (Foreign Key → users.id)
* token_hash (Unique)
* expires_at
* revoked_at (nullable)
* created_at

---

## email_verification_tokens

Fields:

* id (UUID, Primary Key)
* user_id (Foreign Key → users.id)
* token_hash (Unique)
* expires_at
* used_at (nullable)
* created_at

---

## password_reset_tokens

Fields:

* id (UUID, Primary Key)
* user_id (Foreign Key → users.id)
* token_hash (Unique)
* expires_at
* used_at (nullable)
* created_at

---

# Relationships

A single user can have:

* many refresh tokens
* many email verification tokens
* many password reset tokens

Implement proper SQLAlchemy relationships in both directions.

---

# PostgreSQL Requirements

Use:

* UUID primary keys
* gen_random_uuid() for UUID generation
* TIMESTAMPTZ for timestamps
* Appropriate indexes
* Appropriate UNIQUE constraints
* Foreign keys with ON DELETE CASCADE

Explain why each constraint/index exists.

---

# SQLAlchemy

Use SQLAlchemy 2.x declarative mapping.

Use proper:

* mapped_column()
* Mapped[]
* relationship()

Follow modern SQLAlchemy practices.

Do not use deprecated syntax.

---

# Alembic

Configure Alembic correctly.

Show:

* how to initialize Alembic
* how to connect Alembic with SQLAlchemy models
* how to generate the initial migration
* how to apply migrations

The migration should create all four tables with indexes, constraints, and relationships.

---

# Configuration

Use environment variables for:

* PostgreSQL connection string
* JWT secret (for later)
* JWT algorithm
* Token expiration values

You might take following value:

ACCESS_TOKEN_EXPIRE_MINUTES=15

REFRESH_TOKEN_EXPIRE_DAYS=30

EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS=24

PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=30

Create a clean configuration module using Pydantic Settings.

---

# Database Session

Create a reusable SQLAlchemy session setup.

Include:

* Engine
* Session factory
* Dependency for FastAPI

Explain how request-scoped database sessions work.

---

# Deliverables

Please provide:

1. Complete recommended folder structure.
2. Explanation of every folder.
3. SQLAlchemy ORM models.
4. Relationships between models.
5. Alembic configuration.
6. Initial migration.
7. Configuration module.
8. Database connection setup.
9. Explanation of every important design decision.

Do **not** implement authentication logic, JWT generation, password hashing, or API endpoints yet. I only want to establish a clean, production-ready project foundation and database layer.


---
