DROP TABLE public.auth_code;

CREATE INDEX app_owner_id_idx ON public.app (owner_id);
CREATE INDEX app_name_idx ON public.app (name);
CREATE INDEX app_client_id_idx ON public.app (client_id);
CREATE INDEX app_created_at_idx ON public.app (created_at);
CREATE INDEX app_deleted_at_idx ON public.app (deleted_at);

CREATE INDEX app_user_app_id_idx ON public.app_user (app_id);
CREATE INDEX app_user_user_id_idx ON public.app_user (user_id);
CREATE INDEX app_user_granted_at_idx ON public.app_user (granted_at);

CREATE INDEX user_name_idx ON public."user" ("name");
CREATE INDEX user_created_at_idx ON public."user" (created_at);
CREATE INDEX user_deleted_at_idx ON public."user" (deleted_at);

CREATE INDEX user_auth_provider_id_idx ON public.user_auth_provider (id);
CREATE INDEX user_auth_provider_user_id_idx ON public.user_auth_provider (user_id);
CREATE INDEX user_auth_provider_provider_user_oid_idx ON public.user_auth_provider (provider_user_oid);
CREATE INDEX user_auth_provider_created_at_idx ON public.user_auth_provider (created_at);
CREATE INDEX user_auth_provider_provider_name_idx ON public.user_auth_provider (provider_name);
