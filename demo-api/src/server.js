import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { sequelize } from './models/index.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/user.js';
import postRoutes from './routes/post.js';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/post', postRoutes);

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
