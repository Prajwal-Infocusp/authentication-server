Implement the **POST /auth/login** endpoint following the existing project architecture and coding style.

The login flow should be:

1. Validate the request body.
2. Normalize the email to lowercase.
3. Find the user by email.
4. If the user does not exist, return **401 Unauthorized** with a generic error message:

   * `"Invalid email or password."`
5. Verify the password using the existing password utility.
6. If the password is incorrect, return the same **401 Unauthorized** response.
7. Generate:

   * Access Token (JWT)
   * Refresh Token (cryptographically secure random token)
8. Hash the refresh token before storing it in the database.
9. Save the hashed refresh token in the `refresh_tokens` table with the appropriate expiration time.
10. Commit the transaction.
11. Return **200 OK**.

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

### Success Response

```json
{
  "access_token": "<jwt_access_token>",
  "refresh_token": "<plain_refresh_token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

* Return the **plain refresh token** only once to the client.
* Store **only the hashed refresh token** in the database.
* `expires_in` should be the access token lifetime in **seconds**, derived from the existing configuration.

### Error Responses

* **401 Unauthorized**

  * Invalid email or password.
  * Use the same message for both cases to prevent user enumeration.

* **422 Unprocessable Entity**

  * Request validation errors (handled by FastAPI/Pydantic).

* **500 Internal Server Error**

  * Unexpected server errors.

### Implementation Notes

* Keep the router thin.
* Put business logic in the service layer.
* Put database operations in the repository layer.
* Reuse the existing password utility.
* Reuse the existing JWT utility if present; otherwise create one.
* Create a reusable refresh token utility if needed.
* Use SQLAlchemy 2.x best practices.
* Use proper transactions and rollback on failure.
* Keep the code clean, modular, and production-quality.

After generating the code, explain the major design decisions and any newly added utility functions.
