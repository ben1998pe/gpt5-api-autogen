import { Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { sequelize } from '../models/index.js';
import * as models from '../models/models.js';

const router = Router();


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
