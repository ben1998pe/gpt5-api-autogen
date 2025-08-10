import { Router } from 'express';
import { Post } from '../models/Post.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();

router.get('/', authenticate, async (req, res) => {
  const items = await Post.findAll();
  res.json(items);
});

router.get('/:id', authenticate, async (req, res) => {
  const item = await Post.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'Post no encontrado' });
  res.json(item);
});

router.post('/', authenticate, async (req, res) => {
  const created = await Post.create(req.body);
  res.status(201).json(created);
});

router.put('/:id', authenticate, async (req, res) => {
  const item = await Post.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'Post no encontrado' });
  await item.update(req.body);
  res.json(item);
});

router.delete('/:id', authenticate, async (req, res) => {
  const item = await Post.findByPk(req.params.id);
  if (!item) return res.status(404).json({ error: 'Post no encontrado' });
  await item.destroy();
  res.status(204).end();
});

export default router;
