// Validacion de entrada centralizada con zod (fix de la falta total de
// validacion en fase1, que permitia payloads arbitrarios).
function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: 'Datos invalidos', details: result.error.flatten() });
    }
    req.body = result.data;
    next();
  };
}

module.exports = { validateBody };
