# Task

Implement the **User Registration** endpoint for my Authentication Service.

Do **not** implement login, JWT, refresh tokens, TOTP, email verification, or password reset yet.

Focus **only** on the registration flow.

# Existing Database Schema

## users

* id (UUID, Primary Key)
* name
* email (UNIQUE)
* password_hash
* is_email_verified
* totp_secret
* is_2fa_enabled
* created_at
* updated_at

The table already exists via Alembic migrations.

---

# Endpoint

```http
POST /auth/register
```

---

# Request Body

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "StrongPassword123!"
}
```

---

# Validation

Use Pydantic v2.

name
required
trim leading/trailing whitespace
minimum length: 2
maximum length: 100

email
required
valid email address
convert to lowercase before storing

password
minimum length: 8
maximum length: 128
must contain at least:
one uppercase letter
one lowercase letter
one digit
one special character

---

# Registration Flow

Implement the following steps exactly in this order.

1. Validate request body.
2. Normalize email to lowercase.
3. Check whether the email already exists.
4. If email already exists:

   * return HTTP 409 Conflict
   * response:

   ```json
   {
     "detail": "Email already registered."
   }
   ```
5. Hash the password using **bcrypt** via the `pwdlib` library.
6. Create a new User.
7. Save the user to PostgreSQL.
8. Commit the transaction.
9. Refresh the SQLAlchemy object.
10. Return HTTP 201 Created.

---

# Password Hashing

Do **not** store plain text passwords.

Use the **pwdlib** library with bcrypt.

Create a reusable password utility module so password hashing logic is not inside the route handler.

The utility should expose something similar to:

* hash_password(...)
* verify_password(...)

Even though verify_password() will not be used yet, implement it because it will be needed during login.

---

# Response Body

Return only safe fields.

Do NOT return:

* password
* password_hash
* totp_secret

Response:

```json
{
  "id": "uuid",
  "name": "John Doe",
  "email": "john@example.com",
  "is_email_verified": false,
  "is_2fa_enabled": false,
  "created_at": "timestamp"
}
```

---

# HTTP Status Codes

201 Created

Registration successful.

409 Conflict

Email already exists.

422 Unprocessable Entity

Automatically handled by FastAPI / Pydantic validation.

500 Internal Server Error

Unexpected server errors.


# Error Handling

Use proper HTTPException.

Do not expose database errors to the client.

Rollback the transaction if database insertion fails.

---

# Code Quality

Use:

* SQLAlchemy 2.x style
* Mapped[]
* mapped_column()
* select()
* dependency injection
* type hints
* docstrings where useful

Avoid duplicated code.

Keep functions small.

Separate responsibilities properly.

---

# Deliverables

Generate all necessary code to make registration work.

Include:

* Router
* Request schema
* Response schema
* Service
* Repository (if used)
* Password utility
* Any dependency wiring required

Explain every major design decision after the code.
