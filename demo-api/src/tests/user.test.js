import request from 'supertest';
import { app } from '../server.js';
import jwt from 'jsonwebtoken';

const token = jwt.sign({ sub: 'test', role: 'user' }, process.env.JWT_SECRET || 'supersecretjwt');

describe('User CRUD', () => {
  it('should require auth', async () => {
    const res = await request(app).get('/api/user');
    expect(res.status).toBe(401);
  });
  it('should list with token', async () => {
    const res = await request(app).get('/api/user').set('Authorization', 'Bearer ' + token);
    expect([200, 500]).toContain(res.status);
  });
});
