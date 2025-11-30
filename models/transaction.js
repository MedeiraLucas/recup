const Sequelize = require('sequelize');
const db = require('../config/db');

const Transaction = db.define('Transaction', {
    idTransaction: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    description: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    amount: {
        type: Sequelize.DECIMAL(10, 2),
        allowNull: false,
    },
    type: { // 'income' (receita) or 'expense' (despesa)
        type: Sequelize.ENUM('income', 'expense'),
        allowNull: false,
    },
    date: {
        type: Sequelize.DATEONLY,
        allowNull: false,
    },
    receiptPath: { // Caminho para o arquivo do cupom fiscal
        type: Sequelize.STRING,
        allowNull: true,
    },
    // Chaves estrangeiras serão definidas em server.js
});

module.exports = Transaction;