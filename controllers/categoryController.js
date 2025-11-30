// PASTA: controllers/categoryController.js

const Category = require('../models/category');

class CategoryController {
    static async createCategory(req, res) {
        // Validação será feita por um middleware Joi
        const { name, description } = req.body;
        try {
            const category = await Category.create({ name, description });
            res.status(201).json(category);
        } catch (error) {
            res.status(500).json({ message: 'Erro ao criar categoria', error: error.message });
        }
    }

    static async findAllCategories(req, res) {
        try {
            const categories = await Category.findAll();
            res.status(200).json(categories);
        } catch (error) {
            res.status(500).json({ message: 'Erro ao buscar categorias', error: error.message });
        }
    }

    static async updateCategory(req, res) {
        const { id } = req.params;
        const { name, description } = req.body;
        try {
            const category = await Category.findByPk(id);
            if (!category) {
                return res.status(404).json({ message: 'Categoria não encontrada' });
            }

            // Atualiza apenas os campos fornecidos
            category.name = name ?? category.name;
            category.description = description ?? category.description;

            await category.save();
            res.status(200).json(category);
        } catch (error) {
            res.status(500).json({ message: 'Erro ao atualizar categoria', error: error.message });
        }
    }

    static async deleteCategory(req, res) {
        const { id } = req.params;
        try {
            const category = await Category.findByPk(id);
            if (!category) {
                return res.status(404).json({ message: 'Categoria não encontrada' });
            }
            await category.destroy();
            res.status(200).json({ message: 'Categoria deletada com sucesso' });
        } catch (error) {
            // Adicionar verificação de chave estrangeira se necessário
            res.status(500).json({ message: 'Erro ao deletar categoria', error: error.message });
        }
    }
}

module.exports = CategoryController;