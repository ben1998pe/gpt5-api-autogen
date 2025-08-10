# gpt5-api-autogen

Generador de APIs REST que crea proyectos completos en Node.js (Express + Sequelize) o Python (Flask + SQLAlchemy) con:

- CRUD por entidad
- Autenticación JWT y middleware de autorización
- SQLite por defecto u opción a PostgreSQL
- Tests (Jest + Supertest en Node; Pytest en Flask)
- README por proyecto, `.gitignore`, `.editorconfig`, `.gitattributes`
- Listo para subir a GitHub

## Requisitos
- Node.js 18+
- (Opcional) Python 3.10+ si generas proyectos Flask

## Instalación (del generador)
```powershell
cd gpt5-api-autogen\gpt5-api-autogen
npm install
```

## Uso
- Interactivo:
```powershell
node bin/cli.js
```
- No interactivo (ejemplo Node + SQLite):
```powershell
node bin/cli.js --yes --name my-api --language node --entities "User:id,name,email; Post:id,title,content,userId" --database sqlite
```
- No interactivo (ejemplo Flask + PostgreSQL):
```powershell
node bin/cli.js --yes --name my-flask --language python --entities "Book:id,title,author" --database postgres
```

Nota PowerShell: ejecuta cada comando en su propia línea (evita `&&`).

### Flags disponibles
- `--name` / `--project-name` / `-n`: nombre del proyecto a generar
- `--language` / `-l`: `node` o `python`
- `--entities` / `-e`: formato `Entidad:campo1,campo2; Otra:campoA,campoB`
- `--database` / `-d`: `sqlite` (default) o `postgres`
- `--yes` / `-y`: no interactivo (omite preguntas si pasas todas las flags requeridas)

## Qué se genera
Estructura base (Node):
```
src/
  server.js
  routes/
  middleware/
  models/
  tests/
.env
package.json
README.md
```
- En Node, la base de datos se sincroniza automáticamente en modo test (Jest) sin abrir puerto.
- En Flask, se genera `src/app.py`, `src/db.py`, `routes/`, `models/`, `tests/` y `requirements.txt`.

## Después de generar un proyecto (Node)
```powershell
cd <nombre-proyecto>
npm install
npm test
npm run dev
```

## Después de generar un proyecto (Flask)
```powershell
cd <nombre-proyecto>
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
flask --app src/app.py run --debug
```

## Subir a GitHub
```powershell
git init
git add .
git commit -m "init"
# crea el repo en GitHub y luego:
# git remote add origin <URL>
# git push -u origin main
```

## Licencia
MIT
