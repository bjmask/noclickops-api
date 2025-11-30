-- Seed initial tenant and user.
-- Password for admin@example.com is: Password123!

INSERT INTO tenants (name, created_at, updated_at)
VALUES ('default', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Ensure tenant_id is set for user insert
WITH t AS (
    SELECT id FROM tenants WHERE name = 'default'
)
INSERT INTO users (tenant_id, email, password_hash, created_at, updated_at)
SELECT t.id, 'admin@example.com', '$2a$10$4Sv6FkFkuUemfda2wMePf.Zxj9VfTBenTI6JOJY0wKtZ8pp8qjIje', NOW(), NOW()
FROM t
ON CONFLICT (tenant_id, email) DO NOTHING;
