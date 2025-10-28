const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use('/health', require('./routes/health'));
app.use('/version', require('./routes/version'));
app.use('/greet', require('./routes/greet'));
app.use('/tasks', require('./routes/tasks'));
app.use('/stats', require('./routes/stats'));

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});

if (require.main === module) {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app; // For Jest
