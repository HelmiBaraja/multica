-- Nullable: accounts created before password auth have no credential, and
-- the login handler treats a NULL hash as "no password set".
ALTER TABLE "user" ADD COLUMN password_hash TEXT;
