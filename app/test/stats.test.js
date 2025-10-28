const request = require('supertest');
const app = require('../src/index');

describe('GET /stats', () => {
    it('should return stats', async () => {
        const res = await request(app).get('/stats');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('total');
        expect(res.body).toHaveProperty('completed');
        expect(res.body).toHaveProperty('pending');
    });
});
