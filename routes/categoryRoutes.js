// PASTA: routes/categoryRoutes.js

const express = require('express');
const router = express.Router();
const CategoryController = require('../controllers/categoryController');
const authenticateToken = require('../middleware/authenticateToken');
const { validate, categorySchema } = require('../middleware/validators'); // Precisamos adicionar o categorySchema

// Protege todas as rotas de categoria com autenticação
router.use(authenticateToken);

router.post('/', validate(categorySchema), CategoryController.createCategory);
router.get('/', CategoryController.findAllCategories);
router.put('/:id', validate(categorySchema), CategoryController.updateCategory);
router.delete('/:id', CategoryController.deleteCategory);

module.exports = router;