const express = require('express');
const router = express.Router();
const { getAllTasks, addTask, updateTask, deleteTask } = require('../data/tasks');

router.get('/', (req, res) => {
    res.json(getAllTasks());
});

router.post('/', (req, res) => {
    const { title, description } = req.body;
    if (!title || !description) {
        return res.status(400).json({ error: 'Title and description required' });
    }
    const task = addTask(title, description);
    res.status(201).json(task);
});

router.put('/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const task = updateTask(id, req.body);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
});

router.delete('/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const deleted = deleteTask(id);
    if (!deleted) return res.status(404).json({ error: 'Task not found' });
    res.status(204).send();
});

module.exports = router;
