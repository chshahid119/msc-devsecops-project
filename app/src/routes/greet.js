const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    const name = req.query.name || 'Guest';
    res.json({ message: `Hello, ${name}!` });
});

module.exports = router;
