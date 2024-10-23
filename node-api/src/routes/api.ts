import { Router } from 'express';

import * as ApiController from '../controllers/apiController';

const router = Router();

router.post('/registerUser', ApiController.register);
router.post('/login', ApiController.login);
router.get('/listAll', ApiController.listAll);
router.post('/forgotPassword/:email', ApiController.forgotPassword);

export default router;