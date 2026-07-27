const express = require('express');
const { requireAuth } = require('../middlewares/auth');
const upload = require('../middlewares/upload');
const controller = require('../controllers/noteController');

const router = express.Router();

// Todas las rutas requieren autenticacion real (fix VULN-10) y el
// controlador/servicio filtra siempre por el usuario dueno (fix IDOR).
router.get('/', requireAuth, controller.list);
router.get('/:id', requireAuth, controller.getOne);
router.post('/', requireAuth, upload.single('file'), controller.create);
router.put('/:id', requireAuth, controller.update);
router.delete('/:id', requireAuth, controller.remove);

module.exports = router;
