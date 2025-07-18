-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES ($1, NOW(), NOW(), $2, $3, $4) RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT * FROM refresh_tokens WHERE token = $1;

-- name: UpdateRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = $1, updated_at = $2 WHERE token = $3;

