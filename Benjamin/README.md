# Benjamin

> API REST en Node.js/Express generada por gpt5-api-autogen.

## Stack
- Express 4, Sequelize 6
- SQLite (por defecto) o PostgreSQL
- JWT para autenticación
- Jest + Supertest para tests
- Nodemon para desarrollo

## Requisitos
- Node.js 18+
- (Opcional) PostgreSQL 14+

## Instalación y configuración
1) Instala dependencias:
```powershell
npm install
```
2) Variables de entorno (`.env` creado por defecto):
```env
PORT=3000
JWT_SECRET=supersecretjwt
DATABASE_URL=sqlite:db.sqlite
```
- Para PostgreSQL, usa por ejemplo:
```env
DATABASE_URL=postgres://user:password@localhost:5432/benjamin
```

## Ejecutar
- Desarrollo (recarga automática):
```powershell
npm run dev
```
- Producción:
```powershell
npm start
```

## Tests
```powershell
npm test
```
Los tests no arrancan el servidor; la base de datos se sincroniza automáticamente en modo test.

## Endpoints disponibles
- Salud del servicio
  - GET `/health`
- Autenticación
  - POST `/api/auth/signup` (body: `{ email, password, name?, role? }`)
  - POST `/api/auth/login` (body: `{ email, password }`) → `{ token }`

> Nota: Este proyecto se generó sin entidades adicionales. Si generas otro proyecto con entidades, cada entidad tendrá endpoints CRUD en `/api/<entidad>` protegidos con JWT.

## Ejemplos rápidos (PowerShell)
- Health:
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/health"
```
- Signup:
```powershell
Invoke-RestMethod -Method POST -Uri "http://localhost:3000/api/auth/signup" -ContentType "application/json" -Body '{ "email":"a@a.com", "password":"Passw0rd!", "name":"Alice" }'
```
- Login y usar token:
```powershell
$login = Invoke-RestMethod -Method POST -Uri "http://localhost:3000/api/auth/login" -ContentType "application/json" -Body '{ "email":"a@a.com", "password":"Passw0rd!" }'
$token = $login.token
# ejemplo de llamada autenticada (ajusta la ruta si agregas endpoints CRUD)
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri "http://localhost:3000/health"
```

## Estructura del proyecto
```
src/
  server.js
  routes/
    auth.js
  middleware/
    auth.js
  models/
    index.js
    models.js
  tests/
    auth.test.js
```

## GitHub (opcional)
```powershell
git init
git add .
git commit -m "init"
# crea un repo en GitHub y luego
# git remote add origin <URL>
# git push -u origin main
```
