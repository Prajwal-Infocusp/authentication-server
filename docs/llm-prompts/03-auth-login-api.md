Implement the **POST /auth/login** endpoint following the existing project architecture and coding style.

Before implementing the endpoint, create a new database table named **`login_tokens`** to support the two-step login flow when 2FA is enabled.

### `login_tokens` schema

* `id` (UUID, Primary Key)
* `user_id` (UUID, Foreign Key → `users.id`, `ON DELETE CASCADE`)
* `token_hash` (VARCHAR(255), UNIQUE, NOT NULL)
* `expires_at` (TIMESTAMPTZ, NOT NULL)
* `used_at` (TIMESTAMPTZ, NULL)
* `created_at` (TIMESTAMPTZ, NOT NULL)

Generate the corresponding SQLAlchemy model and Alembic migration.

The login flow should be:

1. Validate the request body.
2. Normalize the email to lowercase.
3. Find the user by email.
4. If the user does not exist, return **401 Unauthorized** with the message:

   * `"Invalid email or password."`
5. Verify the password using the existing password utility.
6. If the password is incorrect, return the same **401 Unauthorized** response.
7. Check whether `is_2fa_enabled` is `true`.

### If 2FA is disabled

1. Generate an Access Token (JWT).
2. Generate a cryptographically secure Refresh Token.
3. Hash the refresh token before storing it.
4. Save the hashed refresh token in the `refresh_tokens` table with the appropriate expiration time.
5. Commit the transaction.
6. Return **200 OK**.

Response:

```json
{
  "access_token": "<jwt_access_token>",
  "refresh_token": "<plain_refresh_token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

`expires_in` should be derived from the existing configuration and returned in **seconds**.

### If 2FA is enabled

Do **not** issue JWTs yet.

Instead:

1. Generate a cryptographically secure temporary login token.
2. Hash the token before storing it.
3. Store the hashed token in the newly created `login_tokens` table with an appropriate expiration time (e.g., 5 minutes).
4. Return the plain token to the client.

Response:

```json
{
  "requires_2fa": true,
  "login_token": "<temporary_login_token>"
}
```

The temporary login token will later be consumed by the `/auth/verify-2fa` endpoint. It must be **single-use** (`used_at`) and expire automatically (`expires_at`).

### Request

```json
{
  "email": "john@example.com",
  "password": "Something1!"
}
```

Validate:

* email: required, valid email
* password: required, non-empty string

Do **not** enforce password complexity rules during login.

### Error Responses

* **401 Unauthorized**

  * Invalid email or password.
  * Return the same message whether the email or password is incorrect.

* **422 Unprocessable Entity**

  * Validation errors.

* **500 Internal Server Error**

  * Unexpected server errors.

### Implementation Notes

* Keep the router thin.
* Put business logic in the service layer.
* Put database operations in the repository layer.
* Reuse the existing password utility.
* Reuse the existing JWT utility if available; otherwise create one.
* Create reusable utilities where appropriate.
* Use SQLAlchemy 2.x best practices.
* Handle transactions correctly and roll back on failure.
* Keep the implementation clean, modular, and production-ready.

After generating the code, explain the major design decisions and any newly created utilities or database models.
