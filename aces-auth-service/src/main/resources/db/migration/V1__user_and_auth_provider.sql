CREATE TABLE public."user" (
	id uuid NOT NULL,
	email varchar NOT NULL,
	username varchar NOT NULL,
	"name" varchar NULL,
	"password" varchar NULL,
	created_at date NOT NULL,
	updated_at date NULL,
	deleted_at date NULL,
	"role" varchar DEFAULT USER NOT NULL,
	CONSTRAINT user_pk PRIMARY KEY (id),
	CONSTRAINT user_unique UNIQUE (email),
	CONSTRAINT user_unique_1 UNIQUE (username)
);

CREATE TABLE public.auth_provider (
	id smallserial NOT NULL,
	"name" varchar NOT NULL,
	CONSTRAINT auth_provider_pk PRIMARY KEY (id),
	CONSTRAINT auth_provider_unique UNIQUE ("name")
);

CREATE TABLE public.user_auth_provider (
	id bigserial NOT NULL,
	user_id uuid NOT NULL,
	provider_id smallint NOT NULL,
	provider_user_oid varchar NOT NULL,
	created_at date NOT NULL,
	CONSTRAINT user_auth_provider_user_unique UNIQUE (provider_id,provider_user_oid)
);
