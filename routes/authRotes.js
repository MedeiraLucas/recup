const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const { validate, userSchema, loginSchema } = require('../middleware/validators');

router.post('/register', validate(userSchema), AuthController.register);
router.post('/login', validate(loginSchema), AuthController.login);

module.exports = router;