import { Router } from 'express';
import { User } from '../models/User.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();

router.get('/', authenticate, async (req, res) => {
  const items = await User.findAll();
  res.json(items);
});

router.get('/:id', authenticate, async (req, res) => {
  const item = await User.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'User no encontrado' });
  res.json(item);
});

router.post('/', authenticate, async (req, res) => {
  const created = await User.create(req.body);
  res.status(201).json(created);
});

router.put('/:id', authenticate, async (req, res) => {
  const item = await User.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'User no encontrado' });
  await item.update(req.body);
  res.json(item);
});

router.delete('/:id', authenticate, async (req, res) => {
  const item = await User.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'User no encontrado' });
  await item.destroy();
  res.status(204).end();
});

export default router;
