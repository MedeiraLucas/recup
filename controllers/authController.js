const jwt = require('jsonwebtoken');
const User = require('../models/user');
// Importar o pacote de limite de taxa (necessário instalar: ex: express-rate-limit)
// const rateLimit = require('express-rate-limit'); // <- Exemplo de import

// Checagem obrigatória da chave secreta
if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET não está definido. Por favor, defina esta variável de ambiente.');
}

// Opcional: Middlewares para limitação de taxa (Seria aplicado na rota, não no controller)
/*
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // Limita cada IP a 5 tentativas por windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Muitas tentativas de login. Tente novamente em 15 minutos.' }
});
*/

class AuthController {
    /**
     * @route POST /register
     * Cria um novo usuário.
     */
    static async register(req, res) {
        // Assume-se que a validação de formato (Joi/middleware) já ocorreu
        const { name, email, password } = req.body;
        
        try {
            // 1. Verificar usuário existente (prevenção de colisão de e-mail)
            const existingUser = await User.findOne({ where: { email } });
            if (existingUser) {
                // Retorna 409 Conflict ou 400 Bad Request
                return res.status(409).json({ error: 'Email já cadastrado.' });
            }

            // 2. Criação do usuário (hashing da senha feito no Model Hook)
            const user = await User.create({ name, email, password });

            // 3. Resposta de sucesso (APENAS dados públicos)
            const userResponse = { id: user.idUser, name: user.name, email: user.email };
            res.status(201).json({ 
                message: 'Usuário criado com sucesso', 
                user: userResponse 
            });
        } catch (error) {
            // Logs de erro podem ser importantes aqui para ver problemas de DB
            res.status(500).json({ error: 'Erro interno do servidor ao criar usuário', details: error.message });
        }
    }

    ---

    /**
     * @route POST /login
     * Autentica o usuário e emite um token JWT.
     */
    static async login(req, res) {
        // Assume-se que a validação de formato (Joi/middleware) já ocorreu
        const { email, password } = req.body;
        
        try {
            const user = await User.findOne({ where: { email } });

            // 1. Checagem de Credenciais (mitiga ataque de enumeração de usuário)
            // É uma boa prática usar uma mensagem genérica para não revelar se o erro é no e-mail ou na senha.
            const invalidCredentials = () => res.status(401).json({ error: "Credenciais inválidas." });
            
            // Se o usuário não existe, retorna erro genérico imediatamente.
            if (!user) {
                return invalidCredentials();
            }
            
            // 2. Compara a senha (ASSÍNCRONO e SEGURO)
            // A verificação é feita no Model, que usa o bcrypt com um fator de custo adequado.
            const isPasswordValid = await user.validPassword(password);
            
            if (!isPasswordValid) {
                return invalidCredentials();
            }

            // 3. Criação do Token JWT
            const token = jwt.sign(
                { id: user.idUser, email: user.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' } // Tempo de expiração definido
            );
            
            // 4. Configuração do Cookie (HttpOnly)
            res.cookie('token', token, {
                httpOnly: true, // ESSENCIAL: Impede acesso via JavaScript no cliente (previne XSS)
                secure: process.env.NODE_ENV === 'production', // ESSENCIAL: Usa apenas em HTTPS em produção
                sameSite: 'strict', // RECOMENDADO: Ajuda a mitigar ataques CSRF
                maxAge: 3600000 // 1 hora em milissegundos, alinhado com o 'expiresIn' do JWT
            });

            // 5. Resposta de sucesso
            res.status(200).json({ 
                message: "Login bem-sucedido!",
                user: { id: user.idUser, name: user.name, email: user.email } 
            });
        } catch (error) {
            res.status(500).json({ error: 'Erro interno do servidor ao realizar login', details: error.message });
        }
    }

    // Opcional: Adicionar um método de logout
    static async logout(req, res) {
        // Para fazer logout seguro com cookie HttpOnly, basta sobrescrever/expirar o cookie.
        res.cookie('token', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(0) // Expira o cookie imediatamente
        });
        res.status(200).json({ message: 'Logout bem-sucedido.' });
    }
}

module.exports = AuthController;