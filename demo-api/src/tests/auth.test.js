import request from 'supertest';
import { app } from '../server.js';

describe('Auth endpoints', () => {
  it('health works', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});
