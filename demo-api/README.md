# demo-api

Generado por gpt5-api-autogen.

## Requisitos
- Node.js 18+

## Configuración
1. Copia .env y ajusta variables si es necesario.
2. Instala dependencias:

```bash
npm install
```

## Scripts
- `npm run dev`: arranca con nodemon
- `npm start`: arranca en producción
- `npm test`: ejecuta tests

## Endpoints
- `/api/auth/signup`, `/api/auth/login`
- CRUD por entidad en `/api/<entidad>`

## Base de datos
Por defecto SQLite. Cambia `DATABASE_URL` a Postgres para usarlo.

## Deploy en GitHub
1. Inicializa repo: 

```bash
git init
git add .
git commit -m "init"
```
2. Crea repo en GitHub y haz push.
