const express = require('express');
const router = express.Router();
const { getStats } = require('../data/tasks');

router.get('/', (req, res) => {
    res.json(getStats());
});

module.exports = router;
