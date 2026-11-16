-- Sliding-window lockout: record WHEN the last failed login happened so failures older than
-- iam.account.lockout.window-minutes stop counting. Without it the counter never decayed and
-- failures spread across days still added up to a lockout.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMPTZ;
