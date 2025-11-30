const Joi = require('joi');

const validate = (schema) => (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
        const errors = error.details.map((detail) => detail.message);
        return res.status(400).json({ errors });
    }
    next();
};

const userSchema = Joi.object({
    name: Joi.string().min(3).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const transactionSchema = Joi.object({
    description: Joi.string().min(3).required(),
    amount: Joi.number().positive().required(),
    type: Joi.string().valid('income', 'expense').required(),
    date: Joi.date().iso().required(),
    idCategory: Joi.number().integer().required()
});


module.exports = {
    validate,
    userSchema,
    loginSchema,
    transactionSchema,
    categorySchema,
};

