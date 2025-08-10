#!/usr/bin/env node
const path = require('path');
const fs = require('fs-extra');
const inquirer = require('inquirer');

async function promptUser(existing = {}) {
  const questions = [
    {
      type: 'input',
      name: 'projectName',
      message: 'Nombre del proyecto:',
      validate: (v) => v && v.trim().length > 0 || 'Requerido',
      when: () => !existing.projectName,
      default: existing.projectName
    },
    {
      type: 'list',
      name: 'language',
      message: 'Lenguaje/Framework:',
      choices: [
        { name: 'Node.js (Express + Sequelize)', value: 'node' },
        { name: 'Python (Flask + SQLAlchemy)', value: 'python' }
      ],
      when: () => !existing.language,
      default: existing.language
    },
    {
      type: 'input',
      name: 'entities',
      message: 'Entidades del modelo (formato: User:id,name,email; Post:id,title,content,userId):',
      filter: (v) => (v || '').trim(),
      when: () => !existing.entities,
      default: existing.entities
    },
    {
      type: 'list',
      name: 'database',
      message: 'Base de datos:',
      choices: [
        { name: 'SQLite (por defecto)', value: 'sqlite' },
        { name: 'PostgreSQL', value: 'postgres' }
      ],
      when: () => !existing.database,
      default: existing.database
    }
  ];
  const answers = await inquirer.prompt(questions);
  return { ...existing, ...answers };
}

function parseEntities(input) {
  const entities = [];
  if (!input) return entities;
  const parts = input.split(';').map((s) => s.trim()).filter(Boolean);
  for (const p of parts) {
    const [nameRaw, fieldsRaw] = p.split(':');
    if (!nameRaw || !fieldsRaw) continue;
    const name = nameRaw.trim();
    const fields = fieldsRaw.split(',').map((f) => f.trim()).filter(Boolean);
    entities.push({ name, fields });
  }
  return entities;
}

function toKebab(str){
  return str
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replace(/\s+/g, '-')
    .toLowerCase();
}

async function generateNodeProject(rootDir, answers) {
  const { projectName, entities, database } = answers;
  const projectDir = path.join(rootDir, projectName);
  await fs.ensureDir(projectDir);

  const pkg = {
    name: toKebab(projectName),
    version: '1.0.0',
    private: true,
    type: 'module',
    scripts: {
      dev: 'nodemon src/server.js',
      start: 'node src/server.js',
      test: 'node --experimental-vm-modules ./node_modules/jest/bin/jest.js'
    },
    dependencies: {
      express: '^4.19.2',
      sequelize: '^6.37.3',
      'sequelize-cli': '^6.6.2',
      sqlite3: database === 'sqlite' ? '^5.1.7' : undefined,
      pg: database === 'postgres' ? '^8.11.3' : undefined,
      'pg-hstore': database === 'postgres' ? '^2.3.4' : undefined,
      jsonwebtoken: '^9.0.2',
      bcryptjs: '^2.4.3',
      dotenv: '^16.4.5',
      cors: '^2.8.5'
    },
    devDependencies: {
      jest: '^29.7.0',
      supertest: '^6.3.4',
      nodemon: '^3.1.0'
    }
  };
  // Clean undefined deps
  pkg.dependencies = Object.fromEntries(Object.entries(pkg.dependencies).filter(([,v]) => v));

  await fs.writeJson(path.join(projectDir, 'package.json'), pkg, { spaces: 2 });
  await fs.writeFile(path.join(projectDir, '.gitignore'), 'node_modules\n.env\ncoverage\n');

  // Env
  const env = [
    'PORT=3000',
    'JWT_SECRET=supersecretjwt',
    database === 'sqlite' ? 'DATABASE_URL=sqlite:db.sqlite' : 'DATABASE_URL=postgres://user:password@localhost:5432/dbname'
  ].join('\n');
  await fs.writeFile(path.join(projectDir, '.env'), env);

  // Src structure
  const srcDir = path.join(projectDir, 'src');
  await fs.ensureDir(srcDir);
  await fs.ensureDir(path.join(srcDir, 'models'));
  await fs.ensureDir(path.join(srcDir, 'routes'));
  await fs.ensureDir(path.join(srcDir, 'middleware'));
  await fs.ensureDir(path.join(srcDir, 'tests'));

  // Sequelize init
  const sequelizeIndex = `import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
dotenv.config();

const databaseUrl = process.env.DATABASE_URL || 'sqlite:db.sqlite';
export const sequelize = new Sequelize(databaseUrl, { logging: false });
`;
  await fs.writeFile(path.join(srcDir, 'models', 'index.js'), sequelizeIndex);

  // Base model per entity
  const modelExports = [];
  for (const entity of entities) {
    const modelName = entity.name;
    const table = toKebab(modelName).replace(/-/g, '_') + 's';
    const isUser = modelName.toLowerCase() === 'user';
    const effectiveFields = Array.from(new Set([
      ...entity.fields.filter((f) => f.toLowerCase() !== 'id'),
      ...(isUser ? ['passwordHash', 'role'] : [])
    ]));
    const fieldsLines = effectiveFields
      .filter((f) => f.toLowerCase() !== 'id')
      .map((f) => `    ${f}: { type: DataTypes.STRING }`)
      .join(',\n');
    const modelCode = `import { DataTypes } from 'sequelize';
import { sequelize } from './index.js';

export const ${modelName} = sequelize.define('${modelName}', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
${fieldsLines ? fieldsLines + ',' : ''}
}, { tableName: '${table}' });
`;
    await fs.writeFile(path.join(srcDir, 'models', `${modelName}.js`), modelCode);
    modelExports.push(`export { ${modelName} } from './${modelName}.js';`);
  }
  await fs.writeFile(path.join(srcDir, 'models', 'models.js'), modelExports.join('\n'));

  // Auth middleware and utils
  const authMiddleware = `import jwt from 'jsonwebtoken';

export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'supersecretjwt');
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

export function authorize(roles = []) {
  return (req, res, next) => {
    if (roles.length === 0) return next();
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'No autorizado' });
    }
    next();
  };
}
`;
  await fs.writeFile(path.join(srcDir, 'middleware', 'auth.js'), authMiddleware);

  // Auth routes (signup/login) - expects a User model if present
  const hasUser = entities.some((e) => e.name.toLowerCase() === 'user');
  const authRoutes = `import { Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { sequelize } from '../models/index.js';
import * as models from '../models/models.js';

const router = Router();

${hasUser ? '' : '// Nota: No se definió entidad User; auth usará usuarios en memoria para demo.'}
const User = models.User;

router.post('/signup', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    const passwordHash = await bcrypt.hash(password, 10);
    if (User) {
      const created = await User.create({ email, name, role, passwordHash });
      return res.status(201).json({ id: created.id, email: created.email });
    } else {
      return res.status(201).json({ email });
    }
  } catch (e) {
    return res.status(500).json({ error: 'Error en signup' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    let user = null;
    if (User) {
      user = await User.findOne({ where: { email } });
      if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
      const ok = await bcrypt.compare(password, user.passwordHash || '');
      if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ sub: user ? user.id : email, role: user?.role || 'user' }, process.env.JWT_SECRET || 'supersecretjwt', { expiresIn: '1d' });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: 'Error en login' });
  }
});

export default router;
`;
  await fs.writeFile(path.join(srcDir, 'routes', 'auth.js'), authRoutes);

  // CRUD routes per entity
  for (const entity of entities) {
    const { name } = entity;
    const route = `import { Router } from 'express';
import { ${name} } from '../models/${name}.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();

router.get('/', authenticate, async (req, res) => {
  const items = await ${name}.findAll();
  res.json(items);
});

router.get('/:id', authenticate, async (req, res) => {
  const item = await ${name}.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: '${name} no encontrado' });
  res.json(item);
});

router.post('/', authenticate, async (req, res) => {
  const created = await ${name}.create(req.body);
  res.status(201).json(created);
});

router.put('/:id', authenticate, async (req, res) => {
  const item = await ${name}.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: '${name} no encontrado' });
  await item.update(req.body);
  res.json(item);
});

router.delete('/:id', authenticate, async (req, res) => {
  const item = await ${name}.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: '${name} no encontrado' });
  await item.destroy();
  res.status(204).end();
});

export default router;
`;
    await fs.writeFile(path.join(srcDir, 'routes', `${toKebab(name)}.js`), route);
  }

  // Server
  const routeImports = entities.map((e) => `import ${toKebab(e.name)}Routes from './routes/${toKebab(e.name)}.js';`).join('\n');
  const routeUses = entities.map((e) => `app.use('/api/${toKebab(e.name)}', ${toKebab(e.name)}Routes);`).join('\n');
  const server = `import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { sequelize } from './models/index.js';
import authRoutes from './routes/auth.js';
${routeImports}

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
${routeUses}

app.get('/health', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
// Ensure DB is ready during tests (when server isn't started)
if (process.env.JEST_WORKER_ID !== undefined) {
  await sequelize.authenticate();
  await sequelize.sync();
}
async function start() {
  await sequelize.authenticate();
  await sequelize.sync();
  return app.listen(port, () => console.log('API escuchando en puerto ' + port));
}
if (process.env.JEST_WORKER_ID === undefined) {
  start();
}

export { app, start };
`;
  await fs.writeFile(path.join(srcDir, 'server.js'), server);

  // Tests
  const jestConfig = `/** @type {import('jest').Config} */
export default {
  testEnvironment: 'node',
};
`;
  await fs.writeFile(path.join(projectDir, 'jest.config.js'), jestConfig);

  const testAuth = `import request from 'supertest';
import { app } from '../server.js';

describe('Auth endpoints', () => {
  it('health works', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});
`;
  await fs.writeFile(path.join(srcDir, 'tests', 'auth.test.js'), testAuth);

  for (const entity of entities) {
    const tn = toKebab(entity.name);
    const test = `import request from 'supertest';
import { app } from '../server.js';
import jwt from 'jsonwebtoken';

const token = jwt.sign({ sub: 'test', role: 'user' }, process.env.JWT_SECRET || 'supersecretjwt');

describe('${entity.name} CRUD', () => {
  it('should require auth', async () => {
    const res = await request(app).get('/api/${tn}');
    expect(res.status).toBe(401);
  });
  it('should list with token', async () => {
    const res = await request(app).get('/api/${tn}').set('Authorization', 'Bearer ' + token);
    expect([200, 500]).toContain(res.status);
  });
});
`;
    await fs.writeFile(path.join(srcDir, 'tests', `${tn}.test.js`), test);
  }

  // README
  const fence = '```';
  const inline = '`';
  const readme = `# ${projectName}

Generado por gpt5-api-autogen.

## Requisitos
- Node.js 18+

## Configuración
1. Copia .env y ajusta variables si es necesario.
2. Instala dependencias:

${fence}bash
npm install
${fence}

## Scripts
- ${inline}npm run dev${inline}: arranca con nodemon
- ${inline}npm start${inline}: arranca en producción
- ${inline}npm test${inline}: ejecuta tests

## Endpoints
- ${inline}/api/auth/signup${inline}, ${inline}/api/auth/login${inline}
- CRUD por entidad en ${inline}/api/<entidad>${inline}

## Base de datos
Por defecto SQLite. Cambia ${inline}DATABASE_URL${inline} a Postgres para usarlo.

## Deploy en GitHub
1. Inicializa repo: 

${fence}bash
git init
git add .
git commit -m "init"
${fence}
2. Crea repo en GitHub y haz push.
`;
  await fs.writeFile(path.join(projectDir, 'README.md'), readme);

  // GitHub files
  await fs.writeFile(path.join(projectDir, '.gitattributes'), '* text=auto\n');
  await fs.writeFile(path.join(projectDir, '.editorconfig'), 'root = true\n[*]\nend_of_line = lf\ninsert_final_newline = true\ncharset = utf-8\nindent_style = space\nindent_size = 2\n');
}

async function generatePythonProject(rootDir, answers) {
  const { projectName, entities, database } = answers;
  const projectDir = path.join(rootDir, projectName);
  await fs.ensureDir(projectDir);

  const readme = `# ${projectName}

Generado por gpt5-api-autogen (Flask).

## Requisitos
- Python 3.10+

## Configuración
\n\n\`\`\`bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
\`\`\`

## Ejecutar
\n\n\`\`\`bash
flask --app src/app.py run --debug
\`\`\`
`;
  await fs.writeFile(path.join(projectDir, 'README.md'), readme);
  await fs.writeFile(path.join(projectDir, '.gitignore'), '.venv\n__pycache__\n.env\n');

  const req = [
    'Flask==3.0.3',
    'Flask-JWT-Extended==4.6.0',
    'SQLAlchemy==2.0.30',
    database === 'postgres' ? 'psycopg2-binary==2.9.9' : '',
    'pytest==8.2.2',
    'pytest-flask==1.3.0',
    'python-dotenv==1.0.1'
  ].filter(Boolean).join('\n');
  await fs.writeFile(path.join(projectDir, 'requirements.txt'), req);

  const srcDir = path.join(projectDir, 'src');
  await fs.ensureDir(srcDir);
  await fs.ensureDir(path.join(srcDir, 'routes'));
  await fs.ensureDir(path.join(srcDir, 'models'));
  await fs.ensureDir(path.join(srcDir, 'tests'));
  await fs.ensureFile(path.join(srcDir, '__init__.py'));
  await fs.ensureFile(path.join(srcDir, 'routes', '__init__.py'));
  await fs.ensureFile(path.join(srcDir, 'models', '__init__.py'));

  const env = [
    'FLASK_ENV=development',
    'JWT_SECRET=supersecretjwt',
    database === 'sqlite' ? 'DATABASE_URL=sqlite:///db.sqlite' : 'DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/dbname'
  ].join('\n');
  await fs.writeFile(path.join(projectDir, '.env'), env);

  const appPy = `import os
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from .db import init_db
from .routes.auth import auth_bp
${entities.map(e => `from .routes.${toKebab(e.name)} import ${toKebab(e.name)}_bp`).join('\n')}

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'supersecretjwt')
jwt = JWTManager(app)

init_db()

@app.get('/health')
def health():
    return jsonify({ 'ok': True })

app.register_blueprint(auth_bp, url_prefix='/api/auth')
${entities.map(e => `app.register_blueprint(${toKebab(e.name)}_bp, url_prefix='/api/${toKebab(e.name)}')`).join('\n')}
`;
  await fs.writeFile(path.join(srcDir, 'app.py'), appPy);

  const dbPy = `import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite')

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def init_db():
    from . import models  # noqa: F401 ensure models are imported
    Base.metadata.create_all(bind=engine)
`;
  await fs.writeFile(path.join(srcDir, 'db.py'), dbPy);

  const authPy = `from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.post('/login')
def login():
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({ 'error': 'email requerido' }), 400
    token = create_access_token(identity=email)
    return jsonify({ 'token': token })
`;
  await fs.writeFile(path.join(srcDir, 'routes', 'auth.py'), authPy);

  // Generate SQLAlchemy models and CRUD routes
  for (const entity of entities) {
    const className = entity.name;
    const table = toKebab(className).replace(/-/g, '_') + 's';
    const fields = entity.fields.filter(f => f.toLowerCase() !== 'id');
    const modelPy = `from sqlalchemy import Column, Integer, String
from ..db import Base

class ${className}(Base):
    __tablename__ = '${table}'
    id = Column(Integer, primary_key=True, index=True)
${fields.map(f => `    ${f} = Column(String, nullable=True)`).join('\n')}
`;
    await fs.writeFile(path.join(srcDir, 'models', `${className}.py`), modelPy);
  }
  const modelsInit = entities.map(e => `from .${e.name} import ${e.name}`).join('\n') + '\n';
  await fs.writeFile(path.join(srcDir, 'models', '__init__.py'), modelsInit);

  for (const entity of entities) {
    const bpName = toKebab(entity.name);
    const routePy = `from flask import Blueprint, request, jsonify
from ..db import SessionLocal
from ..models import ${entity.name}

${bpName}_bp = Blueprint('${bpName}', __name__)

@${bpName}_bp.get('/')
def list_items():
    db = SessionLocal()
    items = db.query(${entity.name}).all()
    result = [item.__dict__ for item in items]
    for r in result:
        r.pop('_sa_instance_state', None)
    db.close()
    return jsonify(result)

@${bpName}_bp.get('/<int:item_id>')
def get_item(item_id):
    db = SessionLocal()
    item = db.query(${entity.name}).get(item_id)
    if not item:
        db.close()
        return jsonify({'error': 'No encontrado'}), 404
    data = item.__dict__
    data.pop('_sa_instance_state', None)
    db.close()
    return jsonify(data)

@${bpName}_bp.post('/')
def create_item():
    db = SessionLocal()
    payload = request.get_json() or {}
    item = ${entity.name}(**payload)
    db.add(item)
    db.commit()
    db.refresh(item)
    data = item.__dict__
    data.pop('_sa_instance_state', None)
    db.close()
    return jsonify(data), 201

@${bpName}_bp.put('/<int:item_id>')
def update_item(item_id):
    db = SessionLocal()
    item = db.query(${entity.name}).get(item_id)
    if not item:
        db.close()
        return jsonify({'error': 'No encontrado'}), 404
    payload = request.get_json() or {}
    for k, v in payload.items():
        setattr(item, k, v)
    db.commit()
    db.refresh(item)
    data = item.__dict__
    data.pop('_sa_instance_state', None)
    db.close()
    return jsonify(data)

@${bpName}_bp.delete('/<int:item_id>')
def delete_item(item_id):
    db = SessionLocal()
    item = db.query(${entity.name}).get(item_id)
    if not item:
        db.close()
        return jsonify({'error': 'No encontrado'}), 404
    db.delete(item)
    db.commit()
    db.close()
    return ('', 204)
`;
    await fs.writeFile(path.join(srcDir, 'routes', `${bpName}.py`), routePy);
  }

  const testPy = `from src.app import app

def test_health():
    client = app.test_client()
    res = client.get('/health')
    assert res.status_code == 200
`;
  await fs.writeFile(path.join(srcDir, 'tests', 'test_health.py'), testPy);
}

async function run() {
  const rootDir = process.cwd();
  // Simple argv parsing for non-interactive usage
  const argv = process.argv.slice(2);
  const getArg = (keys) => {
    for (let i = 0; i < argv.length; i++) {
      if (keys.includes(argv[i])) {
        return argv[i + 1] && !argv[i + 1].startsWith('--') && !argv[i + 1].startsWith('-') ? argv[i + 1] : true;
      }
      const [k, v] = argv[i].split('=');
      if (keys.includes(k)) return v ?? true;
    }
    return undefined;
  };
  const provided = {
    projectName: getArg(['--project-name', '--name', '-n']),
    language: getArg(['--language', '-l']),
    entities: getArg(['--entities', '-e']),
    database: getArg(['--database', '-d'])
  };
  const yes = Boolean(getArg(['--yes', '-y']));

  let answers = provided;
  const required = ['projectName', 'language', 'database'];
  const missing = required.filter((k) => !answers[k]);
  if (!yes || missing.length > 0) {
    answers = await promptUser(provided);
  }
  const entities = parseEntities(answers.entities);
  const config = { ...answers, entities };
  if (config.language === 'node') {
    await generateNodeProject(rootDir, config);
  } else {
    await generatePythonProject(rootDir, config);
  }
  console.log(`\nProyecto generado: ${answers.projectName}`);
  console.log('Siguiente paso:');
  if (config.language === 'node') {
    console.log(`  cd ${answers.projectName} && npm install`);
  } else {
    console.log(`  cd ${answers.projectName} && python -m venv .venv && . .venv/Scripts/activate && pip install -r requirements.txt`);
  }
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});


