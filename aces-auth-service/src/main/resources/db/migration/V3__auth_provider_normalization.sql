DROP TABLE IF EXISTS auth_provider CASCADE;

ALTER TABLE public.user_auth_provider DROP CONSTRAINT user_auth_provider_user_unique;
ALTER TABLE public.user_auth_provider DROP COLUMN provider_id;
ALTER TABLE public.user_auth_provider ADD provider_name varchar NOT NULL;
ALTER TABLE public.user_auth_provider ADD CONSTRAINT user_auth_provider_unique UNIQUE (provider_user_oid,provider_name);
