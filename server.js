import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';  
import multer from 'multer'; 
import Stripe from 'stripe';
import path from 'path'; 
import { fileURLToPath } from 'url';
import { dirname } from 'path';


dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const __dirname = dirname(__filename);
const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuración de multer para manejar la subida de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Asegúrate de tener una carpeta "uploads" en tu proyecto
  },
  filename: (req, file, cb) => {
    cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({ storage });

// Endpoint para subir la imagen
app.post('/upload', upload.fields([
  { name: 'foto', maxCount: 1 },
  { name: 'foto2', maxCount: 1 },
  { name: 'foto3', maxCount: 1 }
]), (req, res) => {
  if (!req.files) {
    return res.status(400).json({ message: 'No se subieron archivos' });
  }

  // Obtener los archivos subidos
  const filepaths = {
    foto: req.files['foto'] ? `uploads/${req.files['foto'][0].filename}` : '',
    foto2: req.files['foto2'] ? `uploads/${req.files['foto2'][0].filename}` : '',
    foto3: req.files['foto3'] ? `uploads/${req.files['foto3'][0].filename}` : ''
  };

  // Filtrar solo los campos con archivos subidos
  const filteredFilepaths = Object.fromEntries(
    Object.entries(filepaths).filter(([key, value]) => value !== '')
  );

  // Responder con las rutas de los archivos subidos
  res.status(200).json(filteredFilepaths);
});


const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT 
});

db.connect(err => {
    if (err) {
        console.error('Error al conectar con la BD:', err);
        return;
    }
    console.log('Conectado a la base de datos');
});


// Función para crear un cupón
const createCupon = (porcentaje, codigo, fecha_expiracion, usos_maximos, activo, callback) => {
    const query = 'INSERT INTO cupones (porcentaje, codigo, fecha_expiracion, usos_maximos, activo) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [porcentaje, codigo, fecha_expiracion, usos_maximos, activo], callback);
};

// Actualizar cupón
const updateCupon = (idcupon, porcentaje, codigo, fecha_expiracion, usos_maximos, activo, callback) => {
    const query = 'UPDATE cupones SET porcentaje = ?, codigo = ?, fecha_expiracion = ?, usos_maximos = ?, activo = ? WHERE idcupon = ?';
    db.query(query, [porcentaje, codigo, fecha_expiracion, usos_maximos, activo, idcupon], callback);
};

// Eliminar cupón
const deleteCupon = (idcupon, callback) => {
    const query = 'DELETE FROM cupones WHERE idcupon = ?';
    db.query(query, [idcupon], callback);
};


// Funciones del modelo de usuario
const createUser = async (user, password, email, fecha_nacimiento, sexo, foto, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo, foto, idrol) VALUES (?, ?, ?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, foto, idrol], callback); // idrol por defecto es 1
    } catch (err) {
        callback(err, null);
    }
};
const createAdmin = async (user, password, email, fecha_nacimiento, sexo, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo, idrol) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, idrol], callback);
    } catch (err) {
        callback(err, null);
    }
};


const updateUser = async (iduser, user, password, email, fecha_nacimiento, sexo, idrol, foto, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'UPDATE users SET user = ?, password = ?, email = ?, fecha_nacimiento = ?, sexo = ?, idrol = ?, foto = ? WHERE iduser = ?';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, foto, idrol, iduser], callback);
    } catch (err) {
        callback(err, null);
    }
};

const deleteUser = (iduser, callback) => {
    const query = 'DELETE FROM users WHERE iduser = ?';
    db.query(query, [iduser], callback);
};

const authenticateUser = async (email, password, callback) => {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            return callback(err, null);
        }
        if (results.length === 0) {
            return callback(new Error('Usuario no encontrado'), null);
        }

        const user = results[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return callback(new Error('Contraseña incorrecta'), null);
        }

        // Generar remember_token
        const remember_token = crypto.randomBytes(16).toString('hex');
        const updateTokenQuery = 'UPDATE users SET remember_token = ? WHERE email = ?';
        db.query(updateTokenQuery, [remember_token, email], (err) => {
            if (err) {
                return callback(err, null);
            }
            user.remember_token = remember_token;
            callback(null, user);
        });
    });
};

// Función para contar productos
const countProducto = async (callback) => {
  try {
    const query = 'SELECT COUNT(*) AS total_productos FROM producto';
    db.query(query, callback);
  } catch (err) {
    callback(err, null);
  }
};

// Funciones de modelo de Emails
const createEmail = async (nombre, asunto, correo, mensaje, callback) => {
  try {
    const query = 'INSERT INTO emails (nombre, asunto, correo, mensaje) VALUES (?, ?, ?, ?)';
    db.query(query, [nombre, asunto, correo, mensaje], callback);
  } catch (err) {
    callback(err, null);
  }
};
// Función para actualizar un email
const updateEmail = async (idemail, nombre, asunto, correo, mensaje, callback) => {
  try {
    const query = 'UPDATE emails SET nombre = ?, asunto = ?, correo = ?, mensaje = ? WHERE idemail = ?';
    db.query(query, [nombre, asunto, correo, mensaje, idemail], callback);
  } catch (err) {
    callback(err, null);
  }
};
// Función para eliminar un email
const deleteEmail = async (idemail, callback) => {
  try {
    const query = 'DELETE FROM emails WHERE idemail = ?';
    db.query(query, [idemail], callback);
  } catch (err) {
    callback(err, null);
  }
};
// Funciones de modelo de Productos
const createProducto = async (p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, callback) => {
  try {
    // Calculamos p_final basado en el descuento
    const p_final = p_producto - (p_producto * (descuento / 100));

    const query = 'INSERT INTO producto (p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final], callback);
  } catch (err) {
    callback(err, null);
  }
};

const updateProducto = async (idproducto, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, callback) => {
  try {
    // Calculamos p_final basado en el descuento
    const p_final = p_producto - (p_producto * (descuento / 100));

    const query = 'UPDATE producto SET p_producto = ?, nomprod = ?, clave = ?, descripcion = ?, foto = ?, foto2 = ?, foto3 = ?, descuento = ?, p_final = ? WHERE idproducto = ?';
    db.query(query, [p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final, idproducto], callback);
  } catch (err) {
    callback(err, null);
  }
};

const deleteProducto = (idproducto, callback) => {
  const query = 'DELETE FROM producto WHERE idproducto = ?';
  db.query(query, [idproducto], callback);
};

const searchProducto = (nombre, callback) => {
    const query = 'SELECT * FROM producto WHERE nomprod LIKE ?';
    db.query(query, [`%${nombre}%`], callback);
};

//prueba de compras en formato Json

//modelo de crear compras
const createCompras = (fecha, iduser, productos, callback) => {
    const query = 'INSERT INTO compras (iduser, productos, total, fecha) VALUES (?, ?, ?, ?)';
    db.query(query, [iduser, JSON.stringify(productos), calcularTotal(productos), fecha], callback);
};


const updateCompras = (idcompra, fecha, iduser, productos, callback) => {
    // Actualizar la compra principal
    const query = 'UPDATE compras SET fecha = ?, iduser = ?, productos = ?, total = ? WHERE idcompra = ?';
    db.query(query, [fecha, iduser, JSON.stringify(productos), calcularTotal(productos), idcompra], callback);
};

// Modelo de eliminación de compras
const deleteCompras = (idcompra, callback) => {
    const query = 'DELETE FROM compras WHERE idcompra = ?';
    db.query(query, [idcompra], callback);
};


//modelo compras detalle con JSON

// Función para insertar los detalles de compra en la base de datos
const createComprasDetalles = (idcompra, productos, callback) => {
    const query = 'INSERT INTO compras_detalle (idcompra, productos, total) VALUES (?, ?, ?)';
    db.query(query, [idcompra, JSON.stringify(productos), calcularTotal(productos)], callback);
};


const updateComprasDetalles = (iddetalle, idcompra, productos, callback) => {
    // Actualizar el detalle de la compra
    const query = 'UPDATE compras_detalle SET idcompra = ?, productos = ?, total = ? WHERE iddetalle = ?';
    db.query(query, [idcompra, JSON.stringify(productos), calcularTotal(productos), iddetalle], callback);
};


const deleteComprasDetalles = (iddetalle, callback) => {
    const query = 'DELETE FROM compras_detalle WHERE iddetalle = ?';
    db.query(query, [iddetalle], callback);
};




// Función para calcular el total de la compra sumando todos los totales de los productos
const calcularTotal = (productos) => {
    return productos.reduce((acc, producto) => acc + producto.total_producto, 0);
};


//modelo de compra
const createCompra = (fecha, iduser, idproducto, cantidad, callback) => {
    const getProductPriceQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
    db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
        if (productErr) {
            return callback(productErr, null);
        }
        if (productResults.length === 0) {
            return callback(new Error('Producto no encontrado'), null);
        }

        const total = productResults[0].p_final * cantidad;

        const query = 'INSERT INTO compra (total, fecha, iduser, idproducto, cantidad) VALUES (?, ?, ?, ?, ?)';
        db.query(query, [total, fecha, iduser, idproducto, cantidad], callback);
    });
};

const updateCompra = (idcompra, fecha, iduser, idproducto, cantidad, callback) => {
    // Obtener el precio del producto
    const getProductPriceQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
    db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
        if (productErr) {
            return callback(productErr, null);
        }
        if (productResults.length === 0) {
            return callback(new Error('Producto no encontrado'), null);
        }

        const total = productResults[0].p_final * cantidad;

        const query = 'UPDATE compra SET total = ?, fecha = ?, iduser = ?, idproducto = ?, cantidad = ? WHERE idcompra = ?';
        db.query(query, [total, fecha, iduser, idproducto, cantidad, idcompra], callback);
    });
};
const deleteCompra = (idcompra, callback) => {
    const query = 'DELETE FROM compra WHERE idcompra = ?';
    db.query(query, [idcompra], callback);
};

// funciones de modelo de roles

const createRol = async (nomrol, callback) => {
    try {
        const query = 'INSERT INTO rol (nomrol) VALUES (?)';
        db.query(query, [nomrol], callback);
    } catch (err) {
        callback(err, null);
    }
};
const updateRol = async (idrol, nomrol, callback) => {
    try {
        const query = 'UPDATE rol SET nomrol = ? WHERE idrol = ?';
        db.query(query, [ nomrol, idrol], callback);
    } catch (err) {
        callback(err, null);
    }
};

const deleteRol = (idrol, callback) => {
    const query = 'DELETE FROM rol WHERE idrol = ?';
    db.query(query, [idrol], callback);
};

// funciones de modelo de permisos

const createPermiso = async (nompermiso, clave, callback) => {
    try {
        const query = 'INSERT INTO permiso (nompermiso , clave) VALUES (?,?)';
        db.query(query, [nompermiso, clave], callback);
    } catch (err) {
        callback(err, null);
    }
};
const updatePermiso = async (idpermiso, nompermiso, clave, callback) => {
    try {
        const query = 'UPDATE permiso SET nompermiso = ?, clave = ? WHERE idpermiso = ?';
        db.query(query, [ nompermiso, clave, idpermiso], callback);
    } catch (err) {
        callback(err, null);
    }
};


const deletePermiso = (idpermiso, callback) => {
    const query = 'DELETE FROM permiso WHERE idpermiso = ?';
    db.query(query, [idpermiso], callback);
};


const createRolxPermiso = (idrol, idpermiso, callback) => {
    try {
        const query = 'INSERT INTO rolxpermiso (idrol, idpermiso) VALUES (?, ?)';
        db.query(query, [idrol, idpermiso], callback);
    } catch (err) {
        callback(err, null);
    }
};

const updateRolxPermiso = (idrol, idpermiso, callback) => {
    try {
        const query = 'UPDATE rolxpermiso SET idpermiso = ? WHERE idrol = ?';
        db.query(query, [idpermiso, idrol], callback);
    } catch (err) {
        callback(err, null);
    }
};

const deleteRolxPermiso = (idrol, idpermiso, callback) => {
    const query = 'DELETE FROM rolxpermiso WHERE idrol = ? AND idpermiso = ?';
    db.query(query, [idrol, idpermiso], callback);
};

// Funciones de modelo de Compra Detalle

const createCompraDetalle = (idcompra, idproducto, cantidad, callback) => {
    const checkCompraQuery = 'SELECT * FROM compra WHERE idcompra = ?';
    db.query(checkCompraQuery, [idcompra], (compraErr, compraResults) => {
        if (compraErr) {
            return callback(compraErr, null);
        }
        if (compraResults.length === 0) {
            return callback(new Error('Compra no encontrada'), null);
        }

        const getProductPriceQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
        db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
            if (productErr) {
                return callback(productErr, null);
            }
            if (productResults.length === 0) {
                return callback(new Error('Producto no encontrado'), null);
            }

            const total = productResults[0].p_final * cantidad;

            const query = 'INSERT INTO compra_detalle (idcompra, idproducto, cantidad, total) VALUES (?, ?, ?, ?)';
            db.query(query, [idcompra, idproducto, cantidad, total], callback);
        });
    });
};

const updateCompraDetalle = async (iddetalle, idcompra, idproducto, cantidad, callback) => {
    try {
        // Verificar si la compra existe
        const checkCompraQuery = 'SELECT * FROM compra WHERE idcompra = ?';
        db.query(checkCompraQuery, [idcompra], (compraErr, compraResults) => {
            if (compraErr) {
                return callback(compraErr, null);
            }
            if (compraResults.length === 0) {
                return callback(new Error('Compra no encontrada'), null);
            }

            // Obtener el precio unitario del producto
            const getProductPriceQuery = 'SELECT p_finalFROM producto WHERE idproducto = ?';
            db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
                if (productErr) {
                    return callback(productErr, null);
                }
                if (productResults.length === 0) {
                    return callback(new Error('Producto no encontrado'), null);
                }

                const total = productResults[0].p_final * cantidad;

                const query = 'UPDATE compra_detalle SET idcompra = ?, idproducto = ?, cantidad = ?, total = ? WHERE iddetalle = ?';
                db.query(query, [idcompra, idproducto, cantidad, total, iddetalle], callback);
            });
        });
    } catch (err) {
        callback(err, null);
    }
};

const deleteCompraDetalle = (iddetalle, callback) => {
    const query = 'DELETE FROM compra_detalle WHERE iddetalle = ?';
    db.query(query, [iddetalle], callback);
};

// Ruta para agregar un comentario
app.post('/comentarios', (req, res) => {
    const { idproducto, iduser, comentario } = req.body;

    // Consulta para verificar si el usuario ya ha comentado sobre el producto
    const checkQuery = 'SELECT * FROM comentarios WHERE idproducto = ? AND iduser = ?';
    db.query(checkQuery, [idproducto, iduser], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Error al verificar los comentarios existentes:', checkErr);
            res.status(500).json({ error: 'Error al verificar los comentarios existentes' });
            return;
        }

        if (checkResults.length > 0) {
            // El usuario ya ha comentado sobre este producto
            res.status(400).json({ error: 'Solo puedes comentar una vez por producto' });
        } else {
            // El usuario no ha comentado sobre este producto, proceder a agregar el comentario
            const query = 'INSERT INTO comentarios (idproducto, iduser, comentario) VALUES (?, ?, ?)';
            db.query(query, [idproducto, iduser, comentario], (err, results) => {
                if (err) {
                    console.error('Error al agregar el comentario:', err);
                    res.status(500).json({ error: 'Error al agregar el comentario' });
                    return;
                }
                res.status(201).json({ message: 'Comentario agregado correctamente' });
            });
        }
    });
});

// Crear una nueva entrada en el carrusel
const createSlide = (foto, callback) => {
    const query = 'INSERT INTO carrusel (foto) VALUES (?)';
    db.query(query, [foto], callback);
};

// Actualizar una entrada del carrusel
const updateSlide = (idfoto, foto, callback) => {
    const query = 'UPDATE carrusel SET foto = ? WHERE idfoto = ?';
    db.query(query, [foto, idfoto], callback);
};

// Eliminar una entrada del carrusel
const deleteSlide = (idfoto, callback) => {
    const query = 'DELETE FROM carrusel WHERE idfoto = ?';
    db.query(query, [idfoto], callback);
};

// Endpoint GET para obtener todas las fotos del carrusel
app.get('/carrusel', (req, res) => {
    const query = 'SELECT * FROM carrusel';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

// Middleware para verificar y registrar visitas (si decides usarlo)


// Endpoint para registrar visitas (sumando 1 en cada visita)
app.post('/registrar-visita', (req, res) => {
  const { fecha_visita } = req.body;
  const mes = fecha_visita.slice(0, 7); // Extrae el mes de la fecha

  // Incrementa las visitas en 1 en cada registro
  const queryInsert = 'INSERT INTO visitas_por_mes (mes, numero_de_visitas) VALUES (?, ?) ON DUPLICATE KEY UPDATE numero_de_visitas = numero_de_visitas + 1';
  db.query(queryInsert, [mes, 1], (err) => {
    if (err) {
      console.error('Error al insertar o actualizar el registro de visitas:', err);
      return res.status(500).send('Error en el servidor');
    }
    res.status(200).send('Visita registrada');
  });
});
// AQUI EMPIEZAN LAS GRAFICAS
// Ruta GET para obtener compras por mes
app.get('/compras-por-mes', (req, res) => {
  const query = `
    SELECT 
      DATE_FORMAT(fecha, '%Y-%m') AS mes,
      SUM(total) AS total_compras
    FROM 
      compra
    GROUP BY 
      DATE_FORMAT(fecha, '%Y-%m')
    ORDER BY 
      mes;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener las compras por mes:', err);
      res.status(500).json({ error: 'Error al obtener las compras por mes' });
      return;
    }
    res.status(200).json(result);
  });
});

app.get('/ordenes-por-mes', (req, res) => {
  const query = `
    SELECT 
      DATE_FORMAT(fecha, '%Y-%m') AS mes,
      COUNT(*) AS total_ordenes
    FROM 
      compra
    GROUP BY 
      DATE_FORMAT(fecha, '%Y-%m')
    ORDER BY 
      mes;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener las órdenes por mes:', err);
      res.status(500).json({ error: 'Error al obtener las órdenes por mes' });
      return;
    }
    res.status(200).json(result);
  });
});
// Endpoint para obtener visitas por mes
app.get('/visitas-por-mes', (req, res) => {
    const query = 'SELECT mes, numero_de_visitas FROM visitas_por_mes ORDER BY mes';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

app.get('/mejores-productos', (req, res) => {
  const query = `
    SELECT 
      foto, 
      nomprod, 
      COUNT(*) AS total_ventas
    FROM 
      compra
    JOIN 
      producto ON compra.idproducto = producto.idproducto
    GROUP BY 
      nomprod, foto
    ORDER BY 
      total_ventas DESC
    LIMIT 5;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los mejores productos:', err);
      res.status(500).json({ error: 'Error al obtener los mejores productos' });
      return;
    }
    res.status(200).json(result);
  });
});

app.get('/total-compras', (req, res) => {
  const query = 'SELECT COUNT(*) AS total_compras FROM compra;';

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener el total de compras:', err);
      res.status(500).json({ error: 'Error al obtener el total de compras' });
      return;
    }
    res.status(200).json(result[0]); // result[0] porque COUNT(*) devuelve un solo registro con el conteo
  });
});

// Endpoint para obtener el total de dinero de compras
app.get('/total-dinero-compras', (req, res) => {
  const query = 'SELECT SUM(total) AS total_dinero_compras FROM compra';

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener el total de dinero de compras:', err);
      res.status(500).json({ error: 'Error al obtener el total de dinero de compras' });
      return;
    }
    res.status(200).json({ total_dinero_compras: result[0].total_dinero_compras });
  });
});
// Endpoint GET para obtener una foto específica del carrusel por ID
app.get('/carrusel/:idfoto', (req, res) => {
    const { idfoto } = req.params;
    const query = 'SELECT * FROM carrusel WHERE idfoto = ?';
    db.query(query, [idfoto], (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (result.length === 0) {
            res.status(404).json({ message: 'Foto no encontrada' });
            return;
        }
        res.status(200).json(result[0]);
    });
});

// Endpoint POST para agregar una nueva foto al carrusel
app.post('/nuevo-carrusel', (req, res) => {
    const { foto } = req.body;
    createSlide(foto, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Foto agregada exitosamente', idfoto: results.insertId });
    });
});

// Endpoint PUT para actualizar una foto del carrusel
app.put('/actualizar-carrusel/:idfoto', (req, res) => {
    const { idfoto } = req.params;
    const { foto } = req.body;
    updateSlide(idfoto, foto, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Foto no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Foto actualizada exitosamente' });
    });
});

// Endpoint DELETE para eliminar una foto del carrusel
app.delete('/eliminar-carrusel/:idfoto', (req, res) => {
    const { idfoto } = req.params;
    deleteSlide(idfoto, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Foto no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Foto eliminada exitosamente' });
    });
});

// Ruta para obtener comentarios de un producto
app.get('/comentarios/:idproducto', (req, res) => {
    const { idproducto } = req.params;

    const query = `
        SELECT c.comentario, c.fecha, u.user as user, u.foto as userFoto 
        FROM comentarios c 
        JOIN users u ON c.iduser = u.iduser 
        WHERE c.idproducto = ? 
        ORDER BY c.fecha DESC
    `;
    db.query(query, [idproducto], (err, results) => {
        if (err) {
            console.error('Error al obtener los comentarios:', err);
            res.status(500).json({ error: 'Error al obtener los comentarios' });
            return;
        }
        res.status(200).json(results);
    });
});
// Endpoint GET para obtener todos los usuarios
app.get('/usuarios', (req, res) => {
    const query = 'SELECT * FROM users';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

// Endpoint POST para registrar un usuario
app.post('/nuevo-usuario', async (req, res) => {
    const { user, password, email, fecha_nacimiento, sexo, foto } = req.body;
    const idrol = 1; // ID de rol predeterminado
    const defaultFoto = foto || 'uploads/default.jpg'; // Asignar imagen por defecto si no se proporciona una
    createUser(user, password, email, fecha_nacimiento, sexo, defaultFoto, idrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    });
});


// Endpoint POST para registrar un administrador
app.post('/nuevo-admin', async (req, res) => {
    const { user, password, email, fecha_nacimiento, sexo } = req.body;
    const idrol = 2; // ID de rol para administrador
    createAdmin(user, password, email, fecha_nacimiento, sexo, idrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Admin registrado exitosamente' });
    });
});


// Endpoint PUT para actualizar un usuario
app.put('/actualizar-usuario/:iduser', async (req, res) => {
    const { iduser } = req.params;
    const { user, password, email, fecha_nacimiento, sexo, foto, idrol } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, foto, idrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Usuario actualizado exitosamente' });
    });
});

app.put('/actualizar-perfil/:iduser', async (req, res) => {
    const { iduser } = req.params;
    const { user, password, email, fecha_nacimiento, sexo, foto, idrol } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, foto, idrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Usuario actualizado exitosamente' });
    });
});

// Endpoint DELETE para eliminar un usuario
app.delete('/eliminar-usuario/:iduser', (req, res) => {
    const { iduser } = req.params;
    deleteUser(iduser, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Usuario eliminado exitosamente' });
    });
});
// Endpoint GET para obtener un usuario por ID
app.get('/perfil-usuario/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM users WHERE iduser = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }
        res.status(200).json(results[0]);
    });
});

app.get('/usuarios/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM users WHERE iduser = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }
        res.status(200).json(results[0]);
    });
});

// Endpoint POST para login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    authenticateUser(email, password, (err, user) => {
        if (err) {
            res.status(401).json({ message: err.message });
            return;
        }
        res.status(200).json({ message: 'Login exitoso', user, remember_token: user.remember_token });
    });
});


// endpoint para logout
app.post('/logout', (req, res) => {
    const { remember_token } = req.body;

    const query = 'UPDATE users SET remember_token = NULL WHERE remember_token = ?';
    db.query(query, [remember_token], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json({ message: 'Logout exitoso' });
    });
});

// Endpoint para verificar el token
app.post('/auth/check-token', (req, res) => {
    const { token } = req.body;

    const query = 'SELECT * FROM users WHERE remember_token = ?';
    db.query(query, [token], (err, results) => {
        if (err || results.length === 0) {
            res.status(401).json({ message: 'Token inválido' });
            return;
        }
        res.status(200).json({ user: results[0] });
    });
});

// Ruta para contar productos
app.get('/contar-productos', (req, res) => {
  countProducto((err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results[0]);
  });
});

//Endpoint para contar los productos con descuento

app.get('/contar-productos-con-descuento', (req, res) => {
  const query = 'SELECT COUNT(*) as total FROM producto WHERE descuento > 0';
  
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results[0]);
  });
});


// Endpoint GET para obtener todos los productos
app.get('/productos', (req, res) => {
  const query = 'SELECT * FROM producto';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

// Endpoint para obtener los primeros 4 registros más recientes
app.get('/productos-recientes', (req, res) => {
  const query = 'SELECT * FROM producto ORDER BY created_at DESC LIMIT 4';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

//Endpoint para obtener los productos con descuentos
app.get('/productos-con-descuento', (req, res) => {
  const query = 'SELECT * FROM producto WHERE descuento > 0';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});


// Endpoint para obtener un producto por ID
app.get('/productos/:id', (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM producto WHERE idproducto = ?';
  db.query(query, [id], (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ message: 'Producto no encontrado' });
      return;
    }
    res.status(200).json(results[0]);
  });
});

// Endpoint POST para agregar producto
app.post('/nuevo-producto', async (req, res) => {
  const { p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento } = req.body;

  // Validar si se ha enviado un descuento, de lo contrario poner 0
  const descuentoAplicado = descuento || 0;

  createProducto(p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuentoAplicado, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(201).json({ message: 'Producto agregado exitosamente' });
  });
});

// Endpoint PUT para actualizar un producto
app.put('/actualizar-producto/:idproducto', async (req, res) => {
  const { idproducto } = req.params;
  const { p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento } = req.body;

  // Validar si se ha enviado un descuento, de lo contrario poner 0
  const descuentoAplicado = descuento || 0;

  updateProducto(idproducto, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuentoAplicado, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.affectedRows === 0) {
      res.status(404).json({ message: 'Producto no encontrado' });
      return;
    }
    res.status(200).json({ message: 'Información del producto actualizada exitosamente' });
  });
});

// Endpoint DELETE para eliminar un producto
app.delete('/eliminar-producto/:idproducto', (req, res) => {
  const { idproducto } = req.params;
  deleteProducto(idproducto, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.affectedRows === 0) {
      res.status(404).json({ message: 'Producto no encontrado' });
      return;
    }
    res.status(200).json({ message: 'Producto eliminado exitosamente' });
  });
});


// Endpoint GET para buscar producto por nombre
app.get('/buscar-producto', (req, res) => {
    const { nombre } = req.query;
    searchProducto(nombre, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Producto no encontrado' });
            return;
        }
        res.status(200).json(results);
    });
}); 

// Endpoint GET para buscar productos con descuento por nombre
app.get('/buscar-producto-descuento', (req, res) => {
    const { nombre } = req.query;
    const query = 'SELECT * FROM producto WHERE nomprod LIKE ? AND descuento > 0';
    db.query(query, [`%${nombre}%`], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Producto no encontrado' });
            return;
        }
        res.status(200).json(results);
    });
});
//endpoint para obtener las claves
app.get('/claves-productos', (req, res) => {
  const query = 'SELECT DISTINCT clave FROM producto';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});
//endpoint para obtener un producto por clave
app.get('/clave-producto/:clave', (req, res) => {
  const { clave } = req.params;
  const query = 'SELECT * FROM producto WHERE clave = ?';
  db.query(query, [clave], (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

// Endpoint para obtener las claves de los productos con descuento
app.get('/claves-productos-con-descuento', (req, res) => {
  const query = 'SELECT clave FROM producto WHERE descuento > 0';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

// Endpoint para obtener productos con descuento por clave
app.get('/clave-producto-con-descuento/:clave', (req, res) => {
  const { clave } = req.params;
  const query = 'SELECT * FROM producto WHERE clave = ? AND descuento > 0';
  db.query(query, [clave], (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});


// Endpoint para obtener productos aleatorios por clave
app.get('/productos-aleatorios/:id/:clave', (req, res) => {
  const { id, clave } = req.params;
  const query = `
    SELECT * 
    FROM producto 
    WHERE clave = ? AND idproducto != ? 
    ORDER BY RAND() 
    LIMIT 4`; // Limitamos los resultados a 4

  db.query(query, [clave, id], (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});
// Endpoint GET para obtener todos los emails
app.get('/emails', (req, res) => {
  const query = 'SELECT * FROM emails';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});
// Endpoint para resetear emails
app.post('/resetear-emails', (req, res) => {
  const query = 'ALTER TABLE emails AUTO_INCREMENT = 1';

  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send({ error: 'Error al reiniciar el contador de autoincremento', details: err });
      return;
    }
    res.status(200).json({ message: 'Contador de autoincremento reiniciado correctamente' });
  });
});

// Endpoint POST para crear un nuevo email
app.post('/nuevo-email', (req, res) => {
  const { nombre, asunto, correo, mensaje } = req.body;

  createEmail(nombre, asunto, correo, mensaje, (err, result) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(201).json({ message: 'Email creado correctamente' });
  });
});

// Endpoint PUT para actualizar un email
app.put('/actualizar-email/:idemail', (req, res) => {
  const { idemail } = req.params;
  const { nombre, asunto, correo, mensaje } = req.body;

  updateEmail(idemail, nombre, asunto, correo, mensaje, (err, result) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json({ message: 'Email actualizado correctamente' });
  });
});

// Endpoint DELETE para eliminar un email
app.delete('/eliminar-email/:idemail', (req, res) => {
  const { idemail } = req.params;

  deleteEmail(idemail, (err, result) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Email no encontrado' });
    }
    res.status(200).json({ message: 'Email eliminado correctamente' });
  });
});

// Endpoint GET para obtener todas las compras
app.get('/compras', (req, res) => {
    const query = `
        SELECT 
            compra.idcompra, 
            compra.total, 
            compra.fecha, 
            producto.nomprod as producto,
            users.email as usuario,
            compra.cantidad
        FROM compra
        JOIN users ON compra.iduser = users.iduser
        JOIN producto ON compra.idproducto = producto.idproducto
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

// Endpoint GET para obtener una compra por idcompra
app.get('/compras/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM compra WHERE idcompra = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'compra no encontrado' });
            return;
        }
        res.status(200).json(results[0]);
    });
});

// Endpoint get para obtener una compra por iduser
app.get('/compras/usuario/:id', (req, res) => {
    const { id } = req.params;
    const query = `
        SELECT 
            producto.nomprod AS producto, 
            producto.foto AS productoFoto, 
            compra.cantidad, 
            compra.total 
        FROM compra 
        JOIN producto ON compra.idproducto = producto.idproducto 
        WHERE iduser = ?`;
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Este usuario no ha realizado compras' });
            return;
        }
        res.status(200).json(results);
    });
});


app.get('/compra', (req, res) => {
    const query = `
        SELECT 
            c.idcompra, 
            u.email AS usuario, 
            c.productos, 
            c.total, 
            c.fecha 
        FROM compras c
        JOIN users u ON c.iduser = u.iduser
    `;

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }

        // Primero mapeamos las compras para extraer los productos
        const compras = results.map(compra => {
            let productosParsed;
            try {
                // Parseamos los productos si están almacenados como JSON
                productosParsed = typeof compra.productos === 'string'
                    ? JSON.parse(compra.productos)
                    : compra.productos;

                // Para cada producto, obtenemos su nombre desde la tabla producto
                const productosConNombre = productosParsed.map(producto => {
                    return new Promise((resolve, reject) => {
                        const productQuery = 'SELECT nomprod FROM producto WHERE idproducto = ?';
                        db.query(productQuery, [producto.idproducto], (err, productResults) => {
                            if (err) return reject(err);

                            // Reemplazamos idproducto por nomprod
                            if (productResults.length > 0) {
                                producto.idproducto = productResults[0].nomprod;
                            } else {
                                producto.idproducto = null;
                            }
                            resolve(producto);
                        });
                    });
                });

                // Retornamos una promesa que espera a que todos los nombres de productos se obtengan
                return Promise.all(productosConNombre).then(productos => ({
                    idcompra: compra.idcompra,
                    usuario: compra.usuario,  // Ahora es email de la tabla users
                    productos,  // Productos con idproducto reemplazado por nomprod
                    total: compra.total,
                    fecha: compra.fecha
                }));
            } catch (error) {
                return res.status(500).json({ message: 'Error al parsear productos' });
            }
        });

        // Ejecutamos todas las promesas y enviamos la respuesta cuando todas se completen
        Promise.all(compras).then(comprasFinal => {
            res.json(comprasFinal);
        }).catch(err => {
            res.status(500).send(err);
        });
    });
});


app.get('/compra/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    // Consulta para obtener la compra específica
    const query = 'SELECT c.idcompra, c.iduser, c.productos, c.total, c.fecha FROM compras c WHERE c.idcompra = ?';

    db.query(query, [idcompra], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Compra no encontrada' });
        }

        const compra = results[0];
        let productosParsed;

        try {
            // Parsear los productos del JSON
            productosParsed = typeof compra.productos === 'string'
                ? JSON.parse(compra.productos)
                : compra.productos;

            // Para cada producto, obtenemos su nombre desde la tabla producto
            const productosConNombre = productosParsed.map(producto => {
                return new Promise((resolve, reject) => {
                    const productQuery = 'SELECT nomprod FROM producto WHERE idproducto = ?';
                    db.query(productQuery, [producto.idproducto], (err, productResults) => {
                        if (err) return reject(err);

                        // Reemplazar idproducto por nomprod
                        if (productResults.length > 0) {
                            producto.idproducto = productResults[0].nomprod;
                        } else {
                            producto.idproducto = null;
                        }
                        resolve(producto);
                    });
                });
            });

            // Retornamos una promesa que espera a que todos los nombres de productos se obtengan
            Promise.all(productosConNombre).then(productos => {
                res.json({
                    idcompra: compra.idcompra,
                    iduser: compra.iduser,
                    productos,  // Productos con idproducto reemplazado por nomprod
                    total: compra.total,
                    fecha: compra.fecha
                });
            }).catch(err => {
                res.status(500).send(err);
            });
        } catch (error) {
            res.status(500).json({ message: 'Error al parsear productos' });
        }
    });
});

// Endpoint para obtener las compras por iduser
app.get('/compra/usuario/:iduser', (req, res) => {
    const { iduser } = req.params;

    // Consulta para obtener todas las compras asociadas al iduser
    const query = 'SELECT c.idcompra, c.iduser, c.productos, c.total, c.fecha FROM compras c WHERE c.iduser = ?';

    db.query(query, [iduser], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'No se encontraron compras para el usuario' });
        }

        // Procesar cada compra para reemplazar los IDs de productos con sus nombres
        const comprasConProductos = results.map(compra => {
            let productosParsed;

            try {
                // Parsear los productos del JSON
                productosParsed = typeof compra.productos === 'string'
                    ? JSON.parse(compra.productos)
                    : compra.productos;

                // Para cada producto, obtenemos su nombre desde la tabla producto
                const productosConNombre = productosParsed.map(producto => {
                    return new Promise((resolve, reject) => {
                        const productQuery = 'SELECT nomprod FROM producto WHERE idproducto = ?';
                        db.query(productQuery, [producto.idproducto], (err, productResults) => {
                            if (err) return reject(err);

                            // Reemplazar idproducto por nomprod
                            if (productResults.length > 0) {
                                producto.idproducto = productResults[0].nomprod;
                            } else {
                                producto.idproducto = null;
                            }
                            resolve(producto);
                        });
                    });
                });

                // Retornamos una promesa que espera a que todos los nombres de productos se obtengan
                return Promise.all(productosConNombre).then(productos => {
                    return {
                        idcompra: compra.idcompra,
                        iduser: compra.iduser,
                        productos,  // Productos con idproducto reemplazado por nomprod
                        total: compra.total,
                        fecha: compra.fecha
                    };
                }).catch(err => {
                    throw err;
                });
            } catch (error) {
                throw new Error('Error al parsear productos');
            }
        });

        // Retornar todas las compras una vez que se han procesado
        Promise.all(comprasConProductos).then(compras => {
            res.json(compras);
        }).catch(err => {
            res.status(500).send(err);
        });
    });
});




app.post('/nueva-compras', (req, res) => {
    const { fecha, iduser, productos } = req.body;

    console.log('Datos recibidos en la solicitud:', req.body); // Verificar los datos recibidos

    // Verificar que el usuario exista
    const userQuery = 'SELECT * FROM users WHERE iduser = ?';
    db.query(userQuery, [iduser], (userErr, userResults) => {
        if (userErr) {
            console.error('Error al consultar el usuario:', userErr);
            return res.status(500).send(userErr);
        }
        if (userResults.length === 0) {
            console.log('Usuario no encontrado:', iduser);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        // Procesar los productos para obtener precios y totales
        const productosProcesados = [];
        productos.forEach((producto, index) => {
            const productQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
            db.query(productQuery, [producto.idproducto], (productErr, productResults) => {
                if (productErr) {
                    console.error('Error al consultar el producto:', productErr);
                    return res.status(500).send(productErr);
                }
                if (productResults.length === 0) {
                    console.log('Producto no encontrado:', producto.idproducto);
                    return res.status(404).json({ message: `Producto con id ${producto.idproducto} no encontrado` });
                }

                const p_final = productResults[0].p_final;
                const total_producto = p_final * producto.cantidad;

                productosProcesados.push({
                    idproducto: producto.idproducto,
                    cantidad: producto.cantidad,
                    total_producto: total_producto
                });

                console.log('Producto procesado:', productosProcesados[productosProcesados.length - 1]); // Verificar producto procesado

                // Si ya se procesaron todos los productos, crear la compra
                if (index === productos.length - 1) {
                    console.log('Productos procesados antes de crear la compra:', productosProcesados); // Verificar productos procesados

                    createCompras(fecha, iduser, productosProcesados, (compraErr, compraResults) => {
                        if (compraErr) {
                            console.error('Error al crear la compra:', compraErr);
                            return res.status(500).send(compraErr);
                        }

                        const idcompra = compraResults.insertId;  // Obtener el id de la compra creada

                        console.log('Compra creada con ID:', idcompra); // Verificar ID de la compra

                        // Llamar al modelo createComprasDetalles para crear los detalles de la compra
                        createComprasDetalles(idcompra, productosProcesados, (detalleErr) => {
                            if (detalleErr) {
                                console.error('Error al crear los detalles de la compra:', detalleErr);
                                return res.status(500).send(detalleErr);
                            }
                            console.log('Detalles de la compra creados exitosamente');
                            res.status(201).json({ message: 'Compra y detalles creados exitosamente' });
                        });
                    });
                }
            });
        });
    });
});


// Endpoint PUT para actualizar una compra
app.put('/actualizar-compras/:idcompra', (req, res) => {
    const { fecha, iduser, productos } = req.body;
    const idcompra = req.params.idcompra;

    // Verificar que el usuario exista
    const userQuery = 'SELECT * FROM users WHERE iduser = ?';
    db.query(userQuery, [iduser], (userErr, userResults) => {
        if (userErr) {
            return res.status(500).send(userErr);
        }
        if (userResults.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        // Obtener los detalles de los productos
        const productosProcesados = [];
        productos.forEach((producto, index) => {
            const productQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';  // No necesitamos nomprod
            db.query(productQuery, [producto.idproducto], (productErr, productResults) => {
                if (productErr) {
                    return res.status(500).send(productErr);
                }
                if (productResults.length === 0) {
                    return res.status(404).json({ message: `Producto con id ${producto.idproducto} no encontrado` });
                }

                // Calcular el total por producto
                const p_final = productResults[0].p_final;
                const total_producto = p_final * producto.cantidad;

                // Añadir el producto procesado al arreglo
                productosProcesados.push({
                    idproducto: producto.idproducto,  // Solo mantenemos idproducto
                    cantidad: producto.cantidad,
                    total_producto: total_producto
                });

                // Si ya hemos procesado todos los productos, actualizar la compra
                if (index === productos.length - 1) {
                    updateCompras(idcompra, fecha, iduser, productosProcesados, (updateErr) => {
                        if (updateErr) {
                            return res.status(500).send(updateErr);
                        }
                        res.status(200).json({ message: 'Compra actualizada exitosamente' });
                    });
                }
            });
        });
    });
});



// Endpoint DELETE para eliminar una compra
app.delete('/eliminar-compras/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    deleteCompras(idcompra, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Compra no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Compra eliminada exitosamente' });
    });
});


//endpoint de compras detalle con formato JSON

app.get('/compra-detalle', (req, res) => {
    const query = 'SELECT cd.iddetalle, cd.idcompra, cd.productos, cd.total FROM compras_detalle cd';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }

        // Primero mapeamos los detalles para extraer los productos
        const detalles = results.map(detalle => {
            let productosParsed;
            try {
                // Parseamos los productos si están almacenados como JSON
                productosParsed = typeof detalle.productos === 'string'
                    ? JSON.parse(detalle.productos)
                    : detalle.productos;

                // Para cada producto, obtenemos su nombre desde la tabla producto
                const productosConNombre = productosParsed.map(producto => {
                    return new Promise((resolve, reject) => {
                        const productQuery = 'SELECT nomprod FROM producto WHERE idproducto = ?';
                        db.query(productQuery, [producto.idproducto], (err, productResults) => {
                            if (err) return reject(err);

                            // Reemplazamos idproducto por nomprod
                            if (productResults.length > 0) {
                                producto.idproducto = productResults[0].nomprod;
                            } else {
                                producto.idproducto = null;
                            }
                            resolve(producto);
                        });
                    });
                });

                // Retornamos una promesa que espera a que todos los nombres de productos se obtengan
                return Promise.all(productosConNombre).then(productos => ({
                    iddetalle: detalle.iddetalle,
                    idcompra: detalle.idcompra,
                    productos,  // Productos con idproducto reemplazado por nomprod
                    total: detalle.total
                }));
            } catch (error) {
                return res.status(500).json({ message: 'Error al parsear productos' });
            }
        });

        // Ejecutamos todas las promesas y enviamos la respuesta cuando todas se completen
        Promise.all(detalles).then(detallesFinal => {
            res.json(detallesFinal);
        }).catch(err => {
            res.status(500).send(err);
        });
    });
});

app.get('/compra-detalle/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    // Consulta para obtener los detalles de una compra específica
    const query = 'SELECT cd.iddetalle, cd.idcompra, cd.productos, cd.total FROM compras_detalle cd WHERE cd.idcompra = ?';
    
    db.query(query, [idcompra], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Detalles de compra no encontrados' });
        }

        // Procesar los detalles para extraer los productos
        const detalles = results.map(detalle => {
            let productosParsed;
            try {
                // Parsear los productos del JSON
                productosParsed = typeof detalle.productos === 'string'
                    ? JSON.parse(detalle.productos)
                    : detalle.productos;

                // Obtener los nombres de los productos
                const productosConNombre = productosParsed.map(producto => {
                    return new Promise((resolve, reject) => {
                        const productQuery = 'SELECT nomprod FROM producto WHERE idproducto = ?';
                        db.query(productQuery, [producto.idproducto], (err, productResults) => {
                            if (err) return reject(err);

                            // Reemplazar idproducto por nomprod
                            if (productResults.length > 0) {
                                producto.idproducto = productResults[0].nomprod;
                            } else {
                                producto.idproducto = null;
                            }
                            resolve(producto);
                        });
                    });
                });

                // Retornar una promesa que espera a que todos los nombres de productos se obtengan
                return Promise.all(productosConNombre).then(productos => ({
                    iddetalle: detalle.iddetalle,
                    idcompra: detalle.idcompra,
                    productos,  // Productos con idproducto reemplazado por nomprod
                    total: detalle.total
                }));
            } catch (error) {
                return res.status(500).json({ message: 'Error al parsear productos' });
            }
        });

        // Ejecutar todas las promesas y enviar la respuesta cuando todas se completen
        Promise.all(detalles).then(detallesFinal => {
            res.json(detallesFinal);
        }).catch(err => {
            res.status(500).send(err);
        });
    });
});


app.post('/nueva-compras-detalles', (req, res) => {
    const { idcompra, productos } = req.body;

    // Procesar los productos
    const productosProcesados = [];
    productos.forEach((producto, index) => {
        const productQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
        db.query(productQuery, [producto.idproducto], (productErr, productResults) => {
            if (productErr) {
                return res.status(500).send(productErr);
            }
            if (productResults.length === 0) {
                return res.status(404).json({ message: `Producto con id ${producto.idproducto} no encontrado` });
            }

            const p_final = productResults[0].p_final;
            const total_producto = p_final * producto.cantidad;

            // Agregar producto procesado con cantidad
            productosProcesados.push({
                idproducto: producto.idproducto,
                cantidad: producto.cantidad,
                total_producto: total_producto
            });

            // Verificar si todos los productos han sido procesados
            if (index === productos.length - 1) {
                // Crear los detalles de la compra
                createComprasDetalles(idcompra, productosProcesados, (detalleErr) => {
                    if (detalleErr) {
                        return res.status(500).send(detalleErr);
                    }
                    res.status(201).json({ message: 'Detalles de compra creados exitosamente' });
                });
            }
        });
    });
});


app.put('/actualizar-compras-detalles/:iddetalle', (req, res) => {
    const { idcompra, productos } = req.body;
    const iddetalle = req.params.iddetalle;

    // Obtener los detalles de los productos
    const productosProcesados = [];
    productos.forEach((producto, index) => {
        const productQuery = 'SELECT p_final FROM producto WHERE idproducto = ?';
        db.query(productQuery, [producto.idproducto], (productErr, productResults) => {
            if (productErr) {
                return res.status(500).send(productErr);
            }
            if (productResults.length === 0) {
                return res.status(404).json({ message: `Producto con id ${producto.idproducto} no encontrado` });
            }

            // Calcular el total por producto
            const p_final = productResults[0].p_final;
            const total_producto = p_final * producto.cantidad;

            // Añadir el producto procesado al arreglo
            productosProcesados.push({
                idproducto: producto.idproducto,
                cantidad: producto.cantidad,
                total_producto: total_producto
            });

            // Si ya hemos procesado todos los productos, actualizar el detalle de compra
            if (index === productos.length - 1) {
                updateComprasDetalles(iddetalle, idcompra, productosProcesados, (updateErr) => {
                    if (updateErr) {
                        return res.status(500).send(updateErr);
                    }
                    res.status(200).json({ message: 'Detalle de compra actualizado exitosamente' });
                });
            }
        });
    });
});



app.delete('/eliminar-compras-detalles/:iddetalle', (req, res) => {
    const { iddetalle } = req.params;

    deleteComprasDetalles(iddetalle, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Detalle de compra no encontrado' });
        }
        res.status(200).json({ message: 'Detalle de compra eliminado exitosamente' });
    });
});


//aqui empieza el formato habitual que teniamos de compras

// Endpoint POST para agregar una compra
app.post('/nueva-compra-producto', (req, res) => {
    const { fecha, iduser, idproducto, cantidad } = req.body;

    // Verificar que el usuario exista
    const userQuery = 'SELECT * FROM users WHERE iduser = ?';
    db.query(userQuery, [iduser], (userErr, userResults) => {
        if (userErr) {
            res.status(500).send(userErr);
            return;
        }
        if (userResults.length === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }

        // Verificar que el producto exista
        const productQuery = 'SELECT * FROM producto WHERE idproducto = ?';
        db.query(productQuery, [idproducto], (productErr, productResults) => {
            if (productErr) {
                res.status(500).send(productErr);
                return;
            }
            if (productResults.length === 0) {
                res.status(404).json({ message: 'Producto no encontrado' });
                return;
            }

            // Crear la compra
            createCompra(fecha, iduser, idproducto, cantidad, (compraErr, compraResults) => {
                if (compraErr) {
                    res.status(500).send(compraErr);
                    return;
                }

                const idcompra = compraResults.insertId;

                // Crear el detalle de compra
                createCompraDetalle(idcompra, idproducto, cantidad, (detalleErr, detalleResults) => {
                    if (detalleErr) {
                        res.status(500).send(detalleErr);
                        return;
                    }
                    res.status(201).json({ message: 'Compra y detalle de compra realizados exitosamente' });
                });
            });
        });
    });
});

//comprar varios productos

app.post('/nueva-compra', (req, res) => {
    const { fecha, iduser, productos } = req.body;

    const userQuery = 'SELECT * FROM users WHERE iduser = ?';
    db.query(userQuery, [iduser], (userErr, userResults) => {
        if (userErr) {
            res.status(500).send(userErr);
            return;
        }
        if (userResults.length === 0) {
            res.status(404).json({ message: 'Usuario no encontrado' });
            return;
        }

        const productIds = productos.map(producto => producto.idproducto);
        const productQuery = 'SELECT idproducto FROM producto WHERE idproducto IN (?)';
        db.query(productQuery, [productIds], (productErr, productResults) => {
            if (productErr) {
                res.status(500).send(productErr);
                return;
            }
            if (productResults.length !== productos.length) {
                res.status(404).json({ message: 'Uno o más productos no encontrados' });
                return;
            }

            const promises = productos.map(producto => {
                return new Promise((resolve, reject) => {
                    createCompra(fecha, iduser, producto.idproducto, producto.cantidad, (compraErr, compraResults) => {
                        if (compraErr) {
                            reject(compraErr);
                        } else {
                            const idcompra = compraResults.insertId;
                            createCompraDetalle(idcompra, producto.idproducto, producto.cantidad, (detalleErr, detalleResults) => {
                                if (detalleErr) {
                                    reject(detalleErr);
                                } else {
                                    resolve();
                                }
                            });
                        }
                    });
                });
            });

            Promise.all(promises)
                .then(() => {
                    res.status(201).json({ message: 'Compras y detalles de compra realizados exitosamente' });
                })
                .catch((err) => {
                    res.status(500).send(err);
                });
        });
    });
});

// Endpoint PUT para actualizar una compra
app.put('/actualizar-compra/:idcompra', (req, res) => {
    const { idcompra } = req.params;
    const { fecha, iduser, idproducto, cantidad } = req.body;

    updateCompra(idcompra, fecha, iduser, idproducto, cantidad, (err, results) => {
        if (err) {
            if (err.message === 'Usuario no encontrado') {
                res.status(404).json({ message: 'Usuario no encontrado' });
            } else if (err.message === 'Producto no encontrado') {
                res.status(404).json({ message: 'Producto no encontrado' });
            } else {
                res.status(500).send(err);
            }
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Compra no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Compra actualizada exitosamente' });
    });
});

// Endpoint DELETE para eliminar una compra
app.delete('/eliminar-compra/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    deleteCompra(idcompra, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Compra no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Compra eliminada exitosamente' });
    });
});
// Endpoint GET para obtener todos los roles
app.get('/roles', (req, res) => {
    const query = 'SELECT * FROM rol';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

app.get('/roles/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM rol WHERE idrol = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Rol no encontrado' });
            return;
        }
        res.status(200).json(results[0]);
    });
});


// Endpoint POST para registrar un rol
app.post('/nuevo-rol', async (req, res) => {
    const { nomrol } = req.body;
    createRol(nomrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Rol agregado exitosamente' });
    });
});
// Endpoint PUT para actualizar un rol
app.put('/actualizar-rol/:idrol', async (req, res) => {
    const { idrol } = req.params;
    const { nomrol } = req.body;
    updateRol(idrol,nomrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Rol no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Rol actualizado exitosamente' });
    });
});

// Endpoint DELETE para eliminar un rol
app.delete('/eliminar-rol/:idrol', (req, res) => {
    const { idrol } = req.params;
    deleteRol(idrol, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Rol no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Rol eliminado exitosamente' });
    });
});



// Endpoint GET para obtener todas las relaciones rol-permiso
app.get('/permisos', (req, res) => {
    const query = 'SELECT * FROM permiso';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

// buscar permiso por ID
app.get('/permisos/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM permiso WHERE idpermiso = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ message: 'Permiso no encontrado' });
            return;
        }
        res.status(200).json(results[0]);
    });
});

// Endpoint POST para registrar un permiso
app.post('/nuevo-permiso', async (req, res) => {
    const { nompermiso, clave } = req.body;
    createPermiso(nompermiso, clave, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Permiso registrado exitosamente' });
    });
});

// Endpoint PUT para actualizar un permiso
app.put('/actualizar-permiso/:idpermiso', async (req, res) => {
    const { idpermiso } = req.params;
    const { nompermiso, clave } = req.body;
    updatePermiso(idpermiso, nompermiso, clave, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Permiso no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Permiso actualizado exitosamente' });
    });
});

// Endpoint DELETE para eliminar un permiso
app.delete('/eliminar-permiso/:idpermiso', (req, res) => {
    const { idpermiso } = req.params;
    deletePermiso(idpermiso, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Permiso no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Permiso eliminado exitosamente' });
    });
});

// Endpoint GET para obtener todas las relaciones rol-permiso
app.get('/rolxpermiso', (req, res) => {
    const query = 'SELECT * FROM rolxpermiso';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

app.get('/rolxpermiso/:idrol', (req, res) => {
    const { idrol } = req.params;
    const query = `
        SELECT rp.idpermiso, p.nompermiso AS nombre_permiso
        FROM rolxpermiso rp
        JOIN permiso p ON rp.idpermiso = p.idpermiso
        WHERE rp.idrol = ?
    `;
    db.query(query, [idrol], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

//endpoint post para agregar un rolxpermiso

app.post('/agregar-rolxpermiso', async (req, res) => {
    const { idrol, idpermiso } = req.body;

    // Verificar que el rol exista
    const roleQuery = 'SELECT * FROM rol WHERE idrol = ?';
    db.query(roleQuery, [idrol], (roleErr, roleResults) => {
        if (roleErr) {
            res.status(500).send(roleErr);
            return;
        }
        if (roleResults.length === 0) {
            res.status(404).json({ message: 'Rol no encontrado' });
            return;
        }

        // Verificar que el permiso exista
        const permisoQuery = 'SELECT * FROM permiso WHERE idpermiso = ?';
        db.query(permisoQuery, [idpermiso], (permisoErr, permisoResults) => {
            if (permisoErr) {
                res.status(500).send(permisoErr);
                return;
            }
            if (permisoResults.length === 0) {
                res.status(404).json({ message: 'Permiso no encontrado' });
                return;
            }

            // Crear la relación rol-permiso
            createRolxPermiso(idrol, idpermiso, (createErr, createResults) => {
                if (createErr) {
                    res.status(500).send(createErr);
                    return;
                }
                res.status(201).json({ message: 'Relación rol-permiso agregada exitosamente' });
            });
        });
    });
});



// Endpoint para actualizar el permiso de un rol específico
app.put('/actualizar-rolxpermiso/:idrol', (req, res) => {
    const { idrol } = req.params;
    const { idpermiso } = req.body;

    if (typeof idpermiso !== 'number') {
        res.status(400).json({ message: 'idpermiso debe ser un número válido' });
        return;
    }

    updateRolxPermiso(idrol, idpermiso, (updateErr, updateResults) => {
        if (updateErr) {
            res.status(500).send(updateErr);
            return;
        }
        if (updateResults.affectedRows === 0) {
            res.status(404).json({ message: 'Relación rol-permiso no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Permiso del rol actualizado exitosamente' });
    });
});

//endpoint Delete para eliminar una relacion rolxpermimso

app.delete('/eliminar-rolxpermiso', async (req, res) => {
    const { idrol, idpermiso } = req.body;

    deleteRolxPermiso(idrol, idpermiso, (deleteErr, deleteResults) => {
        if (deleteErr) {
            res.status(500).send(deleteErr);
            return;
        }
        if (deleteResults.affectedRows === 0) {
            res.status(404).json({ message: 'Relación rol-permiso no encontrada' });
            return;
        }
        res.status(200).json({ message: 'Relación rol-permiso eliminada exitosamente' });
    });
});

// Endpoint GET para obtener todos los detalles de compra
app.get('/compras-detalles', (req, res) => {
    const query = 'SELECT idcompra, idproducto, cantidad, total FROM compra_detalle';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).json(results);
    });
});

// Get compra detalle por id de la compra
app.get('/compras-detalles/:idcompra', (req, res) => {
    const { idcompra } = req.params;
    const query = `
        SELECT producto.nomprod AS producto, compra_detalle.cantidad, compra_detalle.total
        FROM compra_detalle
        JOIN producto ON compra_detalle.idproducto = producto.idproducto
        WHERE compra_detalle.idcompra = ?
    `;

    db.query(query, [idcompra], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(404).send({ message: 'Compra no encontrada' });
            return;
        }
        res.status(200).json(results);
    });
});

// Endpoint POST para agregar un detalle de compra
app.post('/nuevo-compra-detalle', async (req, res) => {
    const { idcompra, idproducto, cantidad } = req.body;
    createCompraDetalle(idcompra, idproducto, cantidad, (err, results) => {
        if (err) {
            if (err.message === 'Compra no encontrada' || err.message === 'Producto no encontrado') {
                res.status(404).json({ message: err.message });
                return;
            }
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Detalle de compra agregado exitosamente' });
    });
});

// Endpoint PUT para actualizar un detalle de compra
app.put('/actualizar-compra-detalle/:iddetalle', async (req, res) => {
    const { iddetalle } = req.params;
    const { idcompra, idproducto, cantidad } = req.body;
    updateCompraDetalle(iddetalle, idcompra, idproducto, cantidad, (err, results) => {
        if (err) {
            if (err.message === 'Compra no encontrada' || err.message === 'Producto no encontrado') {
                res.status(404).json({ message: err.message });
                return;
            }
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Detalle de compra no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Información del detalle de compra actualizada exitosamente' });
    });
});

// Endpoint DELETE para eliminar un detalle de compra
app.delete('/eliminar-compra-detalle/:iddetalle', (req, res) => {
    const { iddetalle } = req.params;
    deleteCompraDetalle(iddetalle, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).json({ message: 'Detalle de compra no encontrado' });
            return;
        }
        res.status(200).json({ message: 'Detalle de compra eliminado exitosamente' });
    });
});

// Endpoint POST para crear un pago
app.post('/crear-pago', async (req, res) => {
    const { iduser, productos } = req.body;

    try {
        // Verificar que el usuario existe
        const userQuery = 'SELECT * FROM users WHERE iduser = ?';
        db.query(userQuery, [iduser], (userErr, userResults) => {
            if (userErr) {
                res.status(500).send(userErr);
                return;
            }
            if (userResults.length === 0) {
                res.status(404).json({ message: 'Usuario no encontrado' });
                return;
            }

            // Calcular el total de la compra
            const total = productos.reduce((acc, producto) => acc + producto.precio * producto.cantidad, 0);

            // Crear el PaymentIntent en Stripe
            stripe.paymentIntents.create({
                amount: total * 100, // Stripe usa centavos
                currency: 'usd',
                metadata: { iduser }, // Opcional: Añadir información adicional
            }).then(paymentIntent => {
                res.status(200).json({
                    clientSecret: paymentIntent.client_secret,
                    paymentIntentId: paymentIntent.id,
                });
            }).catch(err => {
                res.status(500).json({ message: 'Error creando el pago con Stripe', error: err });
            });
        });
    } catch (error) {
        res.status(500).json({ message: 'Error procesando el pago', error });
    }
});

app.get('/cupones', (req, res) => {
    const query = 'SELECT * FROM cupones'; // Consulta para obtener todos los cupones

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(results); // Devuelve todos los cupones en formato JSON
    });
});


// Endpoint POST para crear un cupón
app.post('/nuevo-cupon', (req, res) => {
    const { porcentaje, codigo, fecha_expiracion, usos_maximos, activo } = req.body;
    createCupon(porcentaje, codigo, fecha_expiracion, usos_maximos, activo, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.status(201).json({ message: 'Cupón creado exitosamente' });
    });
});

// Endpoint PUT para actualizar un cupón
app.put('/actualizar-cupon/:idcupon', (req, res) => {
    const { idcupon } = req.params;
    const { porcentaje, codigo, fecha_expiracion, usos_maximos, activo } = req.body;
    updateCupon(idcupon, porcentaje, codigo, fecha_expiracion, usos_maximos, activo, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Cupón no encontrado' });
        }
        res.status(200).json({ message: 'Cupón actualizado exitosamente' });
    });
});

// Endpoint DELETE para eliminar un cupón
app.delete('/eliminar-cupon/:idcupon', (req, res) => {
    const { idcupon } = req.params;
    deleteCupon(idcupon, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Cupón no encontrado' });
        }
        res.status(200).json({ message: 'Cupón eliminado exitosamente' });
    });
});


// Endpoint POST para validar cupón
app.post('/validar-cupon', (req, res) => {
    const { codigo } = req.body;
    const query = 'SELECT * FROM cupones WHERE codigo = ? AND activo = 1 AND usos_maximos > 0 AND fecha_expiracion >= NOW()';

    db.query(query, [codigo], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón no válido o expirado' });
        }
        res.status(200).json(results[0]);
    });
});
// Endpoint GET para obtener un cupón por ID
app.get('/cupones/:idcupon', (req, res) => {
    const { idcupon } = req.params;
    const query = 'SELECT * FROM cupones WHERE idcupon = ?';

    db.query(query, [idcupon], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón no encontrado' });
        }
        res.status(200).json(results[0]);
    });
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor funcionando en el puerto ${port}`);
});
