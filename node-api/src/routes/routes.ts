import { Router } from 'express';
const fb = require('fibonacci');

import * as ApiController from '../controllers/apiController';

const router = Router();

router.post('/registerUser', ApiController.register);

router.get('/listAll', ApiController.listAll);

router.post('/login', ApiController.login)

router.post('/forgotPassword/:email', ApiController.forgotPassword); // FALTA ADICIONAR A FUNÇÃO A ROTA

router






export default router;
