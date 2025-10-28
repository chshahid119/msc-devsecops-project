const request = require('supertest');
const app = require('../src/index');

describe('Tasks API', () => {
    let taskId;

    it('POST /tasks - create task', async () => {
        const res = await request(app).post('/tasks').send({ title: 'Test', description: 'Demo task' });
        expect(res.statusCode).toEqual(201);
        expect(res.body).toHaveProperty('id');
        taskId = res.body.id;
    });

    it('GET /tasks - list tasks', async () => {
        const res = await request(app).get('/tasks');
        expect(res.statusCode).toEqual(200);
        expect(res.body.length).toBeGreaterThan(0);
    });

    it('PUT /tasks/:id - update task', async () => {
        const res = await request(app).put(`/tasks/${taskId}`).send({ status: 'completed' });
        expect(res.statusCode).toEqual(200);
        expect(res.body.status).toBe('completed');
    });

    it('DELETE /tasks/:id - delete task', async () => {
        const res = await request(app).delete(`/tasks/${taskId}`);
        expect(res.statusCode).toEqual(204);
    });
});
