const jwt = require('jsonwebtoken');
const User = require('../models/user');

class AuthController {
    static async register(req, res) {
        // A validação agora é feita pelo middleware com Joi
        const { name, email, password } = req.body;
        try {
            const existingUser = await User.findOne({ where: { email } });
            if (existingUser) {
                return res.status(400).json({ error: 'Email já cadastrado.' });
            }

            // A senha já é hasheada pelo hook beforeCreate no Model
            const user = await User.create({ name, email, password });

            // Não retorna a senha
            const userResponse = { id: user.idUser, name: user.name, email: user.email };
            res.status(201).json({ message: 'Usuário criado com sucesso', user: userResponse });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao criar usuário', details: error.message });
        }
    }

    static async login(req, res) {
        // A validação agora é feita pelo middleware com Joi
        const { email, password } = req.body;
        try {
            const user = await User.findOne({ where: { email } });
            // CORREÇÃO: Usar o método validPassword para comparar senhas com bcrypt
            if (!user || !(await user.validPassword(password))) {
                return res.status(401).json({ error: "Email ou senha inválidos" });
            }

            const token = jwt.sign(
                { id: user.idUser, email: user.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            // Configura o token JWT em um cookie HttpOnly para segurança
            res.cookie('token', token, {
                httpOnly: true, // Impede acesso via JavaScript no cliente (previne XSS)
                secure: process.env.NODE_ENV === 'production', // Use secure em produção (HTTPS)
                sameSite: 'strict', // Ajuda a mitigar ataques CSRF
            });

            res.status(200).json({ 
                message: "Login bem-sucedido!",
                user: { id: user.idUser, name: user.name, email: user.email } 
            });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao realizar login', details: error.message });
        }
    }
}

module.exports = AuthController;