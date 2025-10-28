const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    res.json({ version: process.env.APP_VERSION || '1.0.0' });
});

module.exports = router;
