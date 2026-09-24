-- Crea el rol y las bases del backend en un PostgreSQL instalado localmente (sin Docker).
-- La clave NO está en este archivo: se pasa con -v clave=... (la misma que POSTGRES_PASSWORD en .env).
--
-- Uso (PowerShell, desde la carpeta del backend):
--   $clave = (Select-String -Path .env -Pattern '^POSTGRES_PASSWORD=(.*)').Matches.Groups[1].Value
--   & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -v clave=$clave -f scripts\crear_db_local.sql
--
-- Se puede correr varias veces: si el rol o las bases ya existen, no las recrea (solo actualiza la clave).

\set ON_ERROR_STOP on

SELECT 'CREATE ROLE detector LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'detector')\gexec

ALTER ROLE detector WITH LOGIN PASSWORD :'clave';

SELECT 'CREATE DATABASE detector OWNER detector'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'detector')\gexec

SELECT 'CREATE DATABASE detector_test OWNER detector'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'detector_test')\gexec

\echo 'Listo: rol detector y bases detector y detector_test.'
