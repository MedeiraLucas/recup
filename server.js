require('dotenv').config();
const express = require('express');
const db = require('./config/db');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');

// Importar rotas
const authRoutes = require('./routes/authRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const transactionRoutes = require('./routes/transactionRoutes');

// Importar modelos
const User = require('./models/user');
const Category = require('./models/category');
const Transaction = require('./models/transaction');

const app = express();

// Middlewares de Segurança Essenciais
app.use(helmet()); // Adiciona cabeçalhos de segurança
app.use(cors({
    origin: 'http://localhost:5173', // Altere para a URL do seu frontend
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// Configuração de proteção CSRF
const csrfProtection = csrf({ 
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    } 
});
app.use(csrfProtection);

// Rota para fornecer o token CSRF ao cliente (frontend)
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Servir arquivos estáticos da pasta 'uploads'
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rotas da API
app.use('/api/auth', authRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/transactions', transactionRoutes);

// Middleware para tratamento de erros (deve ser o último)
app.use((err, req, res, next) => {
    console.error(err.stack);
    // Tratamento específico para erro de CSRF
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ error: 'CSRF token inválido.' });
    }
    res.status(500).send('Algo deu errado!');
});


// Definindo Associações entre os Modelos
User.hasMany(Transaction, { foreignKey: 'idUser' });
Transaction.belongsTo(User, { foreignKey: 'idUser' });

Category.hasMany(Transaction, { foreignKey: 'idCategory' });
Transaction.belongsTo(Category, { foreignKey: 'idCategory' });


db.sync({ force: false }) // force: false para não apagar os dados a cada reinício
    .then(() => {
        console.log('Banco de dados conectado e sincronizado!');
        const PORT = process.env.PORT || 3001;
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });
    })
    .catch((error) => {
        console.error('Erro ao conectar com o banco de dados:', error);
    });