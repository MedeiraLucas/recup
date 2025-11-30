const Transaction = require('../models/transaction');
const Category = require('../models/category');

class TransactionController {
    static async createTransaction(req, res) {
        // Joi já validou os campos do body.
        const { description, amount, type, date, idCategory } = req.body;
        const idUser = req.user.id; // Vem do token JWT

        try {
            const transactionData = {
                description,
                amount,
                type,
                date,
                idCategory,
                idUser
            };
            
            // Se houver um arquivo, adiciona o caminho
            if (req.file) {
                transactionData.receiptPath = req.file.path;
            }

            // Previne Mass Assignment selecionando apenas os campos permitidos
            const transaction = await Transaction.create(transactionData);

            res.status(201).json(transaction);
        } catch (error) {
            res.status(500).json({ message: 'Erro ao criar transação', error: error.message });
        }
    }

    static async findAllTransactions(req, res) {
        const idUser = req.user.id;
        try {
            const transactions = await Transaction.findAll({ 
                where: { idUser },
                include: [{ model: Category }] // Inclui dados da categoria
            });
            res.status(200).json(transactions);
        } catch (error) {
            res.status(500).json({ message: 'Erro ao buscar transações', error: error.message });
        }
    }
    // Implementar update e delete se necessário, seguindo a mesma lógica.
}

module.exports = TransactionController;