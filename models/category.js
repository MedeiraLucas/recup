const Sequelize = require('sequelize');
const db = require('../config/db');

const Category = db.define('Category', {
    idCategory: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: {
        type: Sequelize.STRING,
        allowNull: false
    },
    description: {
        type: Sequelize.STRING
    }
});

module.exports = Category;