ALTER TABLE public."user" ALTER COLUMN deleted_at TYPE timestamptz USING deleted_at::timestamptz;
ALTER TABLE public."user" ALTER COLUMN updated_at TYPE timestamptz USING updated_at::timestamptz;
ALTER TABLE public."user" ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
ALTER TABLE public.user_auth_provider ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
