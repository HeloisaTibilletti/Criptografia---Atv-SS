import { Request, Response } from 'express';
import { User } from '../models/User';
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt';
import validator from 'validator';
import jwt from 'jsonwebtoken';

// Configuração do Mailtrap
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: '3c06f9dbdde467', 
        pass: 'b338ed92a62e61',
    },
});

const JWT_SECRET = '1234';

const generateRandomPassword = (): string => {
    return Math.random().toString(36).slice(-8); 
};

export const ping = (req: Request, res: Response) => {
    res.json({ pong: true });
};

export const register = async (req: Request, res: Response) => {
    console.log('Iniciando processo de registro...');

    const { email, password, name, discipline } = req.body;

    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ error: 'E-mail inválido ou não fornecido.' });
    }

    if (!password || password.length < 6) {
        return res.status(400).json({ error: 'Senha deve ter no mínimo 6 caracteres.' });
    }

    if (!name || name.length < 2) {
        return res.status(400).json({ error: 'Nome deve ter no mínimo 2 caracteres.' });
    }

    if (!discipline || discipline.trim() === '') {
        return res.status(400).json({ error: 'A disciplina é obrigatória.' });
    }

    try {
        console.log('Verificando se o usuário já existe...');
        let hasUser = await User.findOne({ where: { email } });

        if (hasUser) {
            console.warn(`Usuário com o e-mail ${email} já cadastrado.`);
            return res.status(409).json({ error: 'Este e-mail já está em uso.' });
        }

        console.log('Criando novo usuário...');

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        let newUser = await User.create({
            email,
            password: hashedPassword,
            name,
            discipline
        });

        console.log('Usuário cadastrado com sucesso:', { email, name, discipline });

        const token = jwt.sign(
            { id: newUser.id, email: newUser.email }, 
            JWT_SECRET,
            { expiresIn: '1h' } 
        );

        return res.status(201).json({
            message: 'Usuário cadastrado com sucesso.',
            token,
            user: {
                id: newUser.id,
                email: newUser.email,
                name: newUser.name,
                discipline: newUser.discipline
            }
        });

    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
        return res.status(500).json({ error: 'Erro interno ao processar o registro.' });
    }
};

// Função de login
export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    }

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Senha incorreta.' });
        }

        // Gerar o token JWT
        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        return res.status(200).json({
            message: 'Login realizado com sucesso.',
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                discipline: user.discipline
            }
        });

    } catch (error) {
        console.error('Erro ao realizar login:', error);
        return res.status(500).json({ error: 'Erro interno ao processar o login.' });
    }
};


export const listAll = async (req: Request, res: Response) => {
    try {
        const users = await User.findAll();
        res.status(200).json({ users });
    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
    }
};


export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.body;

    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ error: 'E-mail inválido ou não fornecido.' });
    }

    try {

        const hasUser = await User.findOne({ where: { email } });

        if (!hasUser) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const randomPassword = generateRandomPassword();
        console.log('Senha gerada:', randomPassword);


        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

        hasUser.password = hashedPassword;
        await hasUser.save();

        const mailOptions = {
            from: 'no-reply@seu-dominio.com',
            to: email,
            subject: 'Recuperação de senha',
            text: `Sua nova senha é: ${randomPassword}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar o e-mail:', error);
                return res.status(500).json({ error: 'Erro ao enviar o e-mail.' });
            } else {
                console.log('E-mail enviado:', info.response);
                return res.status(200).json({ message: 'Senha enviada por e-mail com sucesso.' });
            }
        });

    } catch (error) {
        console.error('Erro ao processar a recuperação de senha:', error);
        return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
    }
};
