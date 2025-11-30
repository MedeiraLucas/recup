const express = require('express');
const router = express.Router();
const TransactionController = require('../controllers/transactionController');
const { validate, transactionSchema } = require('../middleware/validators');
const authenticateToken = require('../middleware/authenticateToken');
const multer = require('multer');

// Configuração do Multer para upload de arquivos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Pasta onde os arquivos serão salvos
    },
    filename: function (req, file, cb) {
        // Garante um nome de arquivo único
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const fileFilter = (req, file, cb) => {
    // Aceita apenas imagens e PDF
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'application/pdf') {
        cb(null, true);
    } else {
        cb(new Error('Formato de arquivo não suportado!'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 1024 * 1024 * 5 // Limite de 5MB
    },
    fileFilter: fileFilter
});

// Todas as rotas de transação exigem autenticação
router.use(authenticateToken);

// .single('receipt') indica que esperamos um arquivo no campo 'receipt' do form-data
router.post('/', upload.single('receipt'), validate(transactionSchema), TransactionController.createTransaction);
router.get('/', TransactionController.findAllTransactions);

module.exports = router;