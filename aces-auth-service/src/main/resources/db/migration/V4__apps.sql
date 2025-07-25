CREATE TABLE public.app (
	id uuid NOT NULL,
	owner_id uuid NOT NULL,
	name varchar NOT NULL,
	client_id varchar NOT NULL,
	client_secret varchar NOT NULL,
	redirect_uris varchar NULL,
	homepage_url varchar NOT NULL,
	created_at timestamptz NOT NULL,
	deleted_at timestamptz,
	CONSTRAINT app_pk PRIMARY KEY (id),
	CONSTRAINT app_user_fk FOREIGN KEY (owner_id) REFERENCES public."user"(id)
);

CREATE TABLE public.app_user (
	id bigserial NOT NULL,
	app_id uuid NOT NULL,
	user_id uuid NOT NULL,
	granted_at timestamptz DEFAULT now() NOT NULL,
	scopes varchar NOT NULL,
	CONSTRAINT app_user_pk PRIMARY KEY (id),
	CONSTRAINT app_user_unique UNIQUE (app_id,user_id),
	CONSTRAINT app_user_app_fk FOREIGN KEY (app_id) REFERENCES public.app(id)
);

CREATE TABLE public.auth_code (
	code varchar NOT NULL,
	app_id uuid NOT NULL,
	user_id uuid NOT NULL,
	redirect_uri varchar NOT NULL,
	scopes varchar NOT NULL,
	expires_at timestamptz NOT NULL,
	created_at timestamptz NOT NULL,
	CONSTRAINT auth_code_pk PRIMARY KEY (code)
);