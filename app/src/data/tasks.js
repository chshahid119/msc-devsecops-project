let tasks = [];
let nextId = 1;

const getAllTasks = () => tasks;

const addTask = (title, description) => {
    const task = { id: nextId++, title, description, status: 'pending' };
    tasks.push(task);
    return task;
};

const updateTask = (id, updatedFields) => {
    const task = tasks.find(t => t.id === id);
    if (!task) return null;
    Object.assign(task, updatedFields);
    return task;
};

const deleteTask = (id) => {
    const index = tasks.findIndex(t => t.id === id);
    if (index === -1) return false;
    tasks.splice(index, 1);
    return true;
};

const getStats = () => {
    const total = tasks.length;
    const completed = tasks.filter(t => t.status === 'completed').length;
    const pending = total - completed;
    return { total, completed, pending };
};

module.exports = { getAllTasks, addTask, updateTask, deleteTask, getStats };
