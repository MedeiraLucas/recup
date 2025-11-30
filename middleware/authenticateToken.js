const jwt = require('jsonwebtoken');

// A variável de ambiente é preferida. 'seusegredotaguardado' é apenas um fallback.
const SECRET = process.env.JWT_SECRET || 'seusegredotaguardado'; 

/**
 * Middleware para autenticar um token JWT presente no cabeçalho 'Authorization'.
 * * Espera o formato "Bearer <token>".
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    
    // 1. Tenta obter o token. Usa optional chaining e nullish coalescing para maior segurança.
    const token = authHeader?.split(' ')[1]; 

    // 2. Verifica a ausência do token (401 Unauthorized)
    if (!token) {
        // Log de erro pode ser adicionado aqui para fins de debug
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    // 3. Verifica e decodifica o token
    try {
        const user = jwt.verify(token, SECRET);
        
        // 4. Anexa o payload (usuário) à requisição
        req.user = user;
        
        // 5. Continua para a próxima função da rota
        next();
    } catch (err) {
        
        return res.status(403).json({ message: 'Token inválido ou expirado.' });
    }
}

module.exports = authenticateToken;