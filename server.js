import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';  
import multer from 'multer';
import paypal from '@paypal/checkout-server-sdk';
import path from 'path'; 
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs';



dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuración de multer para manejar la subida de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
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




// Función para convertir base64 a archivo
const base64ToFile = (base64Str, fileName) => {
  const matches = base64Str.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
  const response = {};

  if (!matches || matches.length !== 3) {
    return new Error('Formato de base64 inválido');
  }

  response.type = matches[1];
  response.data = Buffer.from(matches[2], 'base64');

  // Generar un ID aleatorio para el archivo
  const uniqueId = crypto.randomBytes(16).toString('hex');
  const newFileName = `${fileName}-${uniqueId}${path.extname(fileName)}`;
  const relativePath = path.join('uploads', newFileName); // Ruta relativa
  const absolutePath = path.join(__dirname, relativePath); // Ruta absoluta

  fs.writeFileSync(absolutePath, response.data, { encoding: 'base64' });

  return relativePath; // Retorna la ruta relativa
};

  



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

const environment = new paypal.core.SandboxEnvironment(
  process.env.PAYPAL_CLIENT_ID, 
  process.env.PAYPAL_CLIENT_SECRET
);
const client = new paypal.core.PayPalHttpClient(environment);



// Función para crear un cupón
const createCupon = (porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion, callback) => {
    const query = 'INSERT INTO cupones (porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion], callback);
};


// Actualizar cupón
const updateCupon = (idcupon, porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion, callback) => {
    const query = 'UPDATE cupones SET porcentaje = ?, codigo = ?, fecha_expiracion = ?, usos_maximos = ?, activo = ?, descripcion = ? WHERE idcupon = ?';
    db.query(query, [porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion, idcupon], callback);
};


// Eliminar cupón
const deleteCupon = (idcupon, callback) => {
    const query = 'DELETE FROM cupones WHERE idcupon = ?';
    db.query(query, [idcupon], callback);
};


// Funciones del modelo de usuario
const createUser = async (user, password, email, fecha_nacimiento, sexo, foto, estado, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo, foto, estado, idrol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, foto, estado, idrol], callback);
    } catch (err) {
        callback(err, null);
    }
};

const createAdmin = async (user, password, email, fecha_nacimiento, sexo, foto, estado, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo, foto, estado, idrol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, estado, idrol], callback);
    } catch (err) {
        callback(err, null);
    }
};

const updateUser = async (iduser, user, password, email, fecha_nacimiento, sexo, foto, estado, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'UPDATE users SET user = ?, password = ?, email = ?, fecha_nacimiento = ?, sexo = ?, foto = ?, estado = ?, idrol = ? WHERE iduser = ?';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, foto, estado, idrol, iduser], callback);
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

//personalizacion
const createPersonalizacion = async (idproducto, texto_personalizado, imagen_personalizada, color, callback) => {
  try {
    const query = 'INSERT INTO personalizaciones (idproducto, texto_personalizado, imagen_personalizada, color) VALUES (?, ?, ?, ?)';
    db.query(query, [idproducto, texto_personalizado, imagen_personalizada, color], callback);
  } catch (err) {
    callback(err, null);
  }
};

const updatePersonalizacion = async (idpersonalizacion, idproducto, texto_personalizado, imagen_personalizada, color, callback) => {
  try {
    const query = 'UPDATE personalizaciones SET idproducto = ?, texto_personalizado = ?, imagen_personalizada = ?, color = ? WHERE idpersonalizacion = ?';
    db.query(query, [idproducto, texto_personalizado, imagen_personalizada, color, idpersonalizacion], callback);
  } catch (err) {
    callback(err, null);
  }
};

const deletePersonalizacion = (idpersonalizacion, callback) => {
  const query = 'DELETE FROM personalizaciones WHERE idpersonalizacion = ?';
  db.query(query, [idpersonalizacion], callback);
};


// Función para crear un producto
const createProducto = async (iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, tipo_personalizacion, callback) => {
    try {
      const p_final = p_producto - (p_producto * (descuento / 100));
  
      const query = 'INSERT INTO producto (iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final, tipo_personalizacion) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
      db.query(query, [iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final, tipo_personalizacion], callback);
    } catch (err) {
      callback(err, null);
    }
  };
  
  // Función para actualizar un producto
  const updateProducto = async (idproducto, iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, tipo_personalizacion, callback) => {
    try {
      const p_final = p_producto - (p_producto * (descuento / 100));
  
      const query = 'UPDATE producto SET iduser = ?, p_producto = ?, nomprod = ?, clave = ?, descripcion = ?, foto = ?, foto2 = ?, foto3 = ?, descuento = ?, p_final = ?, tipo_personalizacion = ? WHERE idproducto = ?';
      db.query(query, [iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, p_final, tipo_personalizacion, idproducto], callback);
    } catch (err) {
      callback(err, null);
    }
  };
  
  // Función para eliminar un producto (no necesita modificar ya que iduser no se usa en esta operación)
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
const createComprasDetalles = (idcompra, productos, codigoCupon, callback) => {
    const query = 'INSERT INTO compras_detalle (idcompra, productos, total, codigoCupon) VALUES (?, ?, ?, ?)';
    db.query(query, [idcompra, JSON.stringify(productos), calcularTotal(productos), codigoCupon], callback);
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

//modelo de detalle de entrega

const createDetalleEntrega = (idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, callback) => {
    const query = `
        INSERT INTO detalle_entrega 
        (idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(query, [idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono], callback); 
    };



const updateDetalleEntrega = (identrega, idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, callback) => {
    const query = `UPDATE detalle_entrega SET 
                    idcompra = ?, pais = ?, nombre = ?, apellidos = ?, direccion = ?, colonia = ?, codigo_postal = ?, ciudad = ?, estado = ?, telefono = ? 
                  WHERE identrega = ?`;
    db.query(query, [idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, identrega], callback);
};


const deleteDetalleEntrega = (identrega, callback) => {
    const query = 'DELETE FROM detalle_entrega WHERE identrega = ?';
    db.query(query, [identrega], callback);
};

// modelos para detalle_personalizacion

const createDetallePersonalizacion = (idcompra, lado_frontal, lado_trasero, foto, foto2, callback) => {
    const query = `
        INSERT INTO detalle_personalizacion 
        (idcompra, lado_frontal, lado_trasero, foto, foto2)
        VALUES (?, ?, ?, ?, ?)
    `;
    db.query(query, [idcompra, lado_frontal, lado_trasero, foto, foto2], callback);
};

const updateDetallePersonalizacion = (idpersonalizacion, idcompra, lado_frontal, lado_trasero, foto, foto2, callback) => {
    const query = `UPDATE detalle_personalizacion SET 
                    idcompra = ?, lado_frontal = ?, lado_trasero = ?, foto = ?, foto2 = ?
                  WHERE idpersonalizacion = ?`;
    db.query(query, [idcompra, lado_frontal, lado_trasero, foto, foto2, idpersonalizacion], callback);
};

const deleteDetallePersonalizacion = (idpersonalizacion, callback) => {
    const query = 'DELETE FROM detalle_personalizacion WHERE idpersonalizacion = ?';
    db.query(query, [idpersonalizacion], callback);
};



// Ruta para capturar la orden de PayPal
app.post('/capture-order', async (req, res) => {
    console.log('Solicitud de captura recibida:', req.body);

    const { orderID, iduser } = req.body;

    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.requestBody({});

    try {
        const capture = await client.execute(request);
        console.log('Respuesta de captura:', capture.result);

        const purchaseUnit = capture.result.purchase_units ? capture.result.purchase_units[0] : null;

        if (!purchaseUnit) {
            console.error('Error: No se encontró la información de la unidad de compra en la captura.');
            return res.status(500).json({ message: 'No se encontró la información de la unidad de compra en la captura' });
        }

        console.log('Contenido de purchase_units[0]:', purchaseUnit);

        if (!purchaseUnit.payments || !purchaseUnit.payments.captures || !purchaseUnit.payments.captures[0]) {
            console.error('Error: No se encontró la captura de pagos.');
            return res.status(500).json({ message: 'No se encontró la captura de pagos en la respuesta' });
        }

        const captureDetail = purchaseUnit.payments.captures[0];
        const total = captureDetail.amount.value;
        const currency = captureDetail.amount.currency_code;
        const description = captureDetail.note_to_payer || 'Pago Finalizado';

        console.log('Estado de la orden:', capture.result.status);

        if (capture.result.status !== 'COMPLETED') {
            console.error('Error: la orden no fue completada');
            return res.status(400).json({ message: 'La orden no fue completada', details: capture.result });
        }

        // Actualizar el registro existente en lugar de crear uno nuevo
        const updateQuery = `
            UPDATE paypal_logs 
            SET status = ?, total = ?, currency = ?, description = ?, details = ?
            WHERE order_id = ? AND iduser = ?
        `;
        const details = JSON.stringify(capture.result);
        
        db.query(updateQuery, [capture.result.status, total, currency, description, details, orderID, iduser], (updateErr, updateResult) => {
            if (updateErr) {
                console.error('Error al actualizar el log de PayPal:', updateErr);
                return res.status(500).json({ message: 'Error interno al actualizar el log de PayPal' });
            }

            if (updateResult.affectedRows === 0) {
                console.error('No se encontró un registro para actualizar');
                return res.status(404).json({ message: 'No se encontró un registro para actualizar' });
            }

            res.json({ status: capture.result.status, details: capture.result });
        });
    } catch (err) {
        if (err.statusCode === 422 && err.message.includes("ORDER_ALREADY_CAPTURED")) {
            console.error('Error: La orden ya fue capturada anteriormente');
            return res.status(400).json({ message: 'La orden ya fue capturada anteriormente' });
        }

        console.error('Error al capturar la orden:', err);
        res.status(500).send('Error al capturar la orden de PayPal');
    }
});

// Endpoint para crear una orden de PayPal
app.post('/create-order', async (req, res) => {
    const { total, currency, description, iduser } = req.body;

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
            amount: {
                currency_code: currency || 'USD',
                value: total
            },
            description: description || 'Compra en Proceso'
        }],
        application_context: {
            return_url: "http://localhost:5173/carrito",
            cancel_url: "http://localhost:5173/perfil"
        }
    });

    try {
        const order = await client.execute(request);

        const logQuery = `
            INSERT INTO paypal_logs (order_id, status, iduser, total, currency, description, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const details = JSON.stringify(order.result);
        db.query(logQuery, [order.result.id, 'CREATED', iduser, total, currency, description, details], (logErr, logResult) => {
            if (logErr) {
                console.error('Error al guardar el log de PayPal:', logErr);
                return res.status(500).json({ message: 'Error interno al guardar el log de PayPal' });
            }

            res.json({ id: order.result.id, links: order.result.links });
        });
    } catch (err) {
        console.error('Error al crear la orden:', err);
        res.status(500).send('Error al crear la orden de PayPal');
    }
});
// Endpoint para crear una orden de PayPal
app.post('/create-orders', async (req, res) => {
    const { total, currency, description, iduser } = req.body;

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
            amount: {
                currency_code: currency || 'USD',
                value: total
            },
            description: description || 'Compra en Proceso'
        }],
        application_context: {
            return_url: "http://localhost:5173/ventanillas/:id",
            cancel_url: "http://localhost:5173/perfil"
        }
    });

    try {
        const order = await client.execute(request);

        const logQuery = `
            INSERT INTO paypal_logs (order_id, status, iduser, total, currency, description, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const details = JSON.stringify(order.result);
        db.query(logQuery, [order.result.id, 'CREATED', iduser, total, currency, description, details], (logErr, logResult) => {
            if (logErr) {
                console.error('Error al guardar el log de PayPal:', logErr);
                return res.status(500).json({ message: 'Error interno al guardar el log de PayPal' });
            }

            res.json({ id: order.result.id, links: order.result.links });
        });
    } catch (err) {
        console.error('Error al crear la orden:', err);
        res.status(500).send('Error al crear la orden de PayPal');
    }
});

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

// Endpoint para obtener el resumen de compras por año
app.get('/resumen-compras', (req, res) => {
    const query = `
        SELECT 
            YEAR(compra.fecha) AS Año, 
            COUNT(*) AS Count, 
            SUM(compra.total) AS Sum, 
            AVG(compra.total) AS Avg, 
            ROUND((SUM(compra.total) / (SELECT SUM(total) FROM compra)) * 100, 2) AS Porcentaje
        FROM compra
        LEFT JOIN producto ON compra.idproducto = producto.idproducto
        GROUP BY YEAR(compra.fecha)
        ORDER BY Año ASC;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener el resumen de compras:', err);
            res.status(500).json({ error: 'Error al obtener el resumen de compras' });
            return;
        }
        res.status(200).json(results);
    });
});

// Endpoint para obtener las ventas por producto por año
app.get('/ventas-por-producto', (req, res) => {
    const query = `
        SELECT 
            source.Producto_Idproducto_nomprod AS Nombre_Producto, 
            source.Año AS Año, 
            SUM(source.total) AS Total
        FROM (
            SELECT 
                compra.idproducto AS idproducto, 
                compra.total AS total, 
                compra.fecha AS fecha,
                YEAR(compra.fecha) AS Año,
                Producto_Idproducto.nomprod AS Producto_Idproducto_nomprod,
                Producto_Idproducto.idproducto AS Producto_Idproducto_idproducto
            FROM compra
            LEFT JOIN producto AS Producto_Idproducto ON compra.idproducto = Producto_Idproducto.idproducto
            LEFT JOIN comentarios AS Comentarios_Idproducto ON compra.idproducto = Comentarios_Idproducto.idproducto
        ) AS source
        GROUP BY 
            source.Producto_Idproducto_nomprod, 
            source.Año
        ORDER BY 
            source.Producto_Idproducto_nomprod DESC, 
            source.Año DESC;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener el resumen de compras:', err);
            res.status(500).json({ error: 'Error al obtener el resumen de compras' });
            return;
        }
        res.status(200).json(results);
    });
});


// Endpoint para obtener el total de productos vendidos por cada usuario
app.get('/productos-vendidos-por-usuario', (req, res) => {
    const query = `
        SELECT 
    users.user AS nombre_usuario, 
    SUM(
        JSON_UNQUOTE(
            JSON_EXTRACT(compras.productos, CONCAT('$[', idx.i, '].cantidad'))
        )
    ) AS total_productos_vendidos
FROM producto
JOIN compras 
    ON JSON_CONTAINS(
        compras.productos, 
        JSON_OBJECT('idproducto', producto.idproducto)
    )
JOIN users 
    ON producto.iduser = users.iduser
JOIN (
    SELECT 0 AS i UNION ALL 
    SELECT 1 UNION ALL 
    SELECT 2 UNION ALL 
    SELECT 3 UNION ALL 
    SELECT 4 UNION ALL 
    SELECT 5 UNION ALL 
    SELECT 6 UNION ALL 
    SELECT 7 UNION ALL 
    SELECT 8 UNION ALL 
    SELECT 9
) idx
GROUP BY users.user
ORDER BY total_productos_vendidos DESC;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener productos vendidos por usuario:', err);
            res.status(500).json({ error: 'Error interno del servidor' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ message: 'No se encontraron usuarios con productos vendidos' });
            return;
        }

        res.status(200).json(results);
    });
});


// Endpoint para obtener el número de productos creados por cada usuario y ordenarlos de mayor a menor
app.get('/productos-por-usuario', (req, res) => {
    const query = `
        SELECT 
            users.user AS nombre_usuario,
            COUNT(producto.idproducto) AS total_productos
        FROM 
            users
        LEFT JOIN 
            producto ON users.iduser = producto.iduser
        GROUP BY 
            users.user
        ORDER BY 
            total_productos DESC;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener los productos por usuario:', err);
            res.status(500).json({ error: 'Error al obtener los productos por usuario' });
            return;
        }
        res.status(200).json(results);
    });
});


// Endpoint para obtener productos con clave PER y su cantidad total comprada
app.get('/productos-clave-PER', (req, res) => {
    const query = `
        SELECT 
            producto.nomprod AS nombre_producto,
            SUM(
                JSON_UNQUOTE(
                    JSON_EXTRACT(compras.productos, CONCAT('$[', idx.i, '].cantidad'))
                )
            ) AS total_cantidad_comprada
        FROM producto
        JOIN compras
            ON JSON_CONTAINS(
                compras.productos, 
                JSON_OBJECT('idproducto', producto.idproducto)
            )
        JOIN (
            SELECT 0 AS i UNION ALL 
            SELECT 1 UNION ALL 
            SELECT 2 UNION ALL 
            SELECT 3 UNION ALL 
            SELECT 4 UNION ALL 
            SELECT 5 UNION ALL 
            SELECT 6 UNION ALL 
            SELECT 7 UNION ALL 
            SELECT 8 UNION ALL 
            SELECT 9
        ) idx
        WHERE producto.clave = 'PER'
        GROUP BY producto.nomprod
        ORDER BY total_cantidad_comprada DESC;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener productos con la clave PER:', err);
            res.status(500).json({ error: 'Error interno del servidor' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ message: 'No se encontraron productos con la clave PER' });
            return;
        }

        res.status(200).json(results);
    });
});

//

// Función para obtener compras por producto y mes usando JSON_EXTRACT
const getComprasOrdenadasPorMes = (callback) => {
    const query = `
        SELECT 
            p.nomprod AS producto, 
            DATE_FORMAT(c.fecha, '%Y-%m') AS mes,
            SUM(CASE 
                WHEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[0].cantidad')) IS NOT NULL 
                THEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[0].cantidad')) 
                ELSE 0 
            END) +
            SUM(CASE 
                WHEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[1].cantidad')) IS NOT NULL 
                THEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[1].cantidad')) 
                ELSE 0 
            END) +
            SUM(CASE 
                WHEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[2].cantidad')) IS NOT NULL 
                THEN JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[2].cantidad')) 
                ELSE 0 
            END) AS total_comprado
        FROM compras c
        JOIN producto p ON JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[0].idproducto')) = p.idproducto
        GROUP BY p.nomprod, mes
        ORDER BY mes, producto;
    `;

    db.query(query, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        callback(null, results);
    });
};

// Endpoint para obtener las compras ordenadas por producto y mes desde la tabla 'compras'
app.get('/compras-ordenadas', (req, res) => {
    getComprasOrdenadasPorMes((err, results) => {
        if (err) {
            return res.status(500).send('Error al obtener las compras ordenadas');
        }
        res.status(200).json(results);
    });
});

// Función para obtener órdenes por mes
const getOrdenesPorMes = (callback) => {
    const query = `
        SELECT 
            DATE_FORMAT(fecha, '%Y-%m') AS mes, 
            COUNT(*) AS total_ordenes
        FROM 
            compras
        GROUP BY 
            mes
        ORDER BY 
            mes;
    `;

    db.query(query, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        callback(null, results);
    });
};

// Endpoint para obtener las órdenes ordenadas por mes
app.get('/ordenes-por-mes-c', (req, res) => {
    getOrdenesPorMes((err, results) => {
        if (err) {
            return res.status(500).send('Error al obtener las órdenes por mes');
        }
        res.status(200).json(results);
    });
});


// Ruta GET para obtener el conteo de usuarios por sexo
app.get('/usuarios-por-sexo', (req, res) => {
  const query = `
    SELECT 
      sexo, 
      COUNT(*) AS cantidad 
    FROM 
      users 
    WHERE 
      sexo IN ('hombre', 'mujer') 
    GROUP BY 
      sexo;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los usuarios por sexo:', err);
      res.status(500).json({ error: 'Error al obtener los usuarios por sexo' });
      return;
    }
    res.status(200).json(result);
  });
});

app.get('/usuarios-estados', (req, res) => {
  const query = `
    SELECT 
      estado, 
      COUNT(*) AS total_usuarios 
    FROM 
      users 
    GROUP BY 
      estado;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los usuarios por estado:', err);
      return res.status(500).json({ error: 'Error al obtener los usuarios por estado' });
    }
    
    if (!result || result.length === 0) {
      return res.status(404).json({ error: 'No se encontraron usuarios por estado' });
    }

    res.status(200).json(result);
  });
});

// Ruta GET para obtener el conteo de usuarios por rangos de edad
app.get('/usuarios-por-edad', (req, res) => {
  const query = `
    SELECT 
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 10 AND 15 THEN 1 ELSE 0 END) AS '10-15',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 16 AND 20 THEN 1 ELSE 0 END) AS '16-20',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 21 AND 35 THEN 1 ELSE 0 END) AS '21-35',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 36 AND 50 THEN 1 ELSE 0 END) AS '36-50',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 51 AND 70 THEN 1 ELSE 0 END) AS '51-70'
    FROM users;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los usuarios por edad:', err);
      res.status(500).json({ error: 'Error al obtener los usuarios por edad' });
      return;
    }
    res.status(200).json(result[0]); // Devuelve el primer (y único) registro con los rangos de edad
  });
});

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
// Ruta GET para obtener los usuarios por rangos de edad
app.get('/rango-por-edad', (req, res) => {
    const query = `
     SELECT 
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 10 AND 20 THEN 1 ELSE 0 END) AS '10-20',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 21 AND 35 THEN 1 ELSE 0 END) AS '21-35',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 36 AND 50 THEN 1 ELSE 0 END) AS '36-50',
      SUM(CASE WHEN TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) BETWEEN 51 AND 80 THEN 1 ELSE 0 END) AS '51-80'
    FROM users;
    `;
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener los usuarios por edad:', err);
        res.status(500).json({ error: 'Error al obtener los usuarios por edad' });
        return;
      }

      // Agregar console.log para verificar los datos que devuelve la consulta
      console.log('Resultado de la consulta:', result);

      res.status(200).json(result[0]);
    });
});


// Función para obtener nuevos usuarios mensuales
const getNuevosUsuariosMensuales = (callback) => {
    const query = `
        SELECT 
            DATE_FORMAT(created_at, '%M %Y') AS mes,
            COUNT(*) AS total_nuevos
        FROM 
            users
        GROUP BY 
            mes
        ORDER BY 
            MIN(created_at);
    `;

    db.query(query, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        callback(null, results);
    });
};

// Endpoint para obtener nuevos usuarios mensuales
app.get('/nuevos-usuarios-mensuales', (req, res) => {
    getNuevosUsuariosMensuales((err, results) => {
        if (err) {
            return res.status(500).send('Error al obtener nuevos usuarios mensuales');
        }
        res.status(200).json(results);
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
    const query = `
      SELECT SUM(
        JSON_UNQUOTE(
          JSON_EXTRACT(producto, '$.cantidad')
        )
      ) AS total_productos_comprados
      FROM compras, JSON_TABLE(productos, '$[*]' COLUMNS (producto JSON PATH '$')) AS p;
    `;
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener el total de productos comprados:', err);
        res.status(500).json({ error: 'Error al obtener el total de productos comprados' });
        return;
      }
      res.status(200).json({ total_productos_comprados: result[0].total_productos_comprados });
    });
  });
  

// Endpoint para obtener el total de dinero de compras
app.get('/total-dinero-compras', (req, res) => {
    const query = 'SELECT SUM(total) AS total_dinero_compras FROM compras';
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener el total de dinero de compras:', err);
        res.status(500).json({ error: 'Error al obtener el total de dinero de compras' });
        return;
      }
      res.status(200).json({ total_dinero_compras: result[0].total_dinero_compras });
    });
  });

  app.get('/total-dinero-compras-mes', (req, res) => {
    const query = `
      SELECT DATE_FORMAT(fecha, '%Y-%m') AS mes, 
             SUM(total) AS total_compras 
      FROM compras
      GROUP BY mes
      ORDER BY mes;
    `;
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener el total de dinero de compras por mes:', err);
        res.status(500).json({ error: 'Error al obtener el total de dinero de compras por mes' });
        return;
      }
      res.status(200).json(result);
    });
  });
  

 //obtener media del dinero total 

 app.get('/media-dinero-compras', (req, res) => {
    const query = 'SELECT ROUND(AVG(total), 1) AS media_dinero_compras FROM compras';
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener la media de dinero de compras:', err);
        res.status(500).json({ error: 'Error al obtener la media de dinero de compras' });
        return;
      }
      res.status(200).json({ media_dinero_compras: result[0].media_dinero_compras });
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

app.get('/cupones-mas-usados', (req, res) => {
    const query = `
        SELECT 
            cupones.codigo AS nombre_codigo,
            COUNT(cupones_usados.idcupon) AS cantidad_usados
        FROM 
            cupones_usados
        JOIN 
            cupones ON cupones_usados.idcupon = cupones.idcupon
        GROUP BY 
            cupones.codigo
        ORDER BY 
            cantidad_usados DESC
        LIMIT 5;
    `;
  
    db.query(query, (err, result) => {
        if (err) {
            console.error('Error al obtener los cupones más usados:', err);
            res.status(500).json({ error: 'Error al obtener los cupones más usados' });
            return;
        }
        res.status(200).json(result);
    });
});
app.get('/usuarios-cupones-usados', (req, res) => {
    const query = `
        SELECT 
            users.user AS nombre_usuario,
            users.foto AS foto_usuario,
            COUNT(cupones_usados.idcupon) AS cantidad_usados
        FROM 
            cupones_usados
        JOIN 
            users ON cupones_usados.iduser = users.iduser
        GROUP BY 
            users.user, users.foto
        ORDER BY 
            cantidad_usados DESC
        LIMIT 5;
    `;
  
    db.query(query, (err, result) => {
        if (err) {
            console.error('Error al obtener los usuarios con más cupones usados:', err);
            res.status(500).json({ error: 'Error al obtener los usuarios con más cupones usados' });
            return;
        }
        res.status(200).json(result);
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

// Ruta para obtener comentarios de un producto con calificación
app.get('/comentarios/:idproducto', (req, res) => {
    const { idproducto } = req.params;

    const query = `
        SELECT c.comentario, c.fecha, c.calificacion, u.user as user, u.foto as userFoto 
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

// Ruta para obtener el resumen de calificaciones por producto
app.get('/calificaciones-resumen/:idproducto', (req, res) => {
    const { idproducto } = req.params;

    const query = `
        SELECT
          idproducto,
          SUM(CASE WHEN calificacion = 1 THEN 1 ELSE 0 END) AS '1',
          SUM(CASE WHEN calificacion = 2 THEN 1 ELSE 0 END) AS '2',
          SUM(CASE WHEN calificacion = 3 THEN 1 ELSE 0 END) AS '3',
          SUM(CASE WHEN calificacion = 4 THEN 1 ELSE 0 END) AS '4',
          SUM(CASE WHEN calificacion = 5 THEN 1 ELSE 0 END) AS '5',
          COUNT(*) AS 'TOTAL',
          ROUND(
            (
              (SUM(CASE WHEN calificacion = 1 THEN 1 ELSE 0 END) * 1 +
               SUM(CASE WHEN calificacion = 2 THEN 1 ELSE 0 END) * 2 +
               SUM(CASE WHEN calificacion = 3 THEN 1 ELSE 0 END) * 3 +
               SUM(CASE WHEN calificacion = 4 THEN 1 ELSE 0 END) * 4 +
               SUM(CASE WHEN calificacion = 5 THEN 1 ELSE 0 END) * 5
              ) / COUNT(*)
            ), 2
          ) AS calificacion_final
        FROM
          comentarios
        WHERE
          idproducto = ?
        GROUP BY
          idproducto
    `;

    db.query(query, [idproducto], (err, results) => {
        if (err) {
            console.error('Error al obtener el resumen de calificaciones:', err);
            res.status(500).json({ error: 'Error al obtener el resumen de calificaciones' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ message: 'No se encontraron calificaciones para este producto' });
            return;
        }

        res.status(200).json(results[0]);
    });
});




// Ruta para agregar un comentario
app.post('/comentarios', (req, res) => {
    const { idproducto, iduser, comentario, calificacion } = req.body;

    // Validar que la calificación esté en el rango permitido
    if (calificacion < 1 || calificacion > 5) {
        return res.status(400).json({ error: 'La calificación debe estar entre 1 y 5' });
    }

    // Consulta para verificar si el usuario ya ha comentado sobre el producto
    const checkQuery = 'SELECT * FROM comentarios WHERE idproducto = ? AND iduser = ?';
    db.query(checkQuery, [idproducto, iduser], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Error al verificar los comentarios existentes:', checkErr);
            res.status(500).json({ error: 'Error al verificar los comentarios existentes' });
            return;
        }

        if (checkResults.length > 0) {
            res.status(400).json({ error: 'Solo puedes comentar una vez por producto' });
        } else {
            const query = 'INSERT INTO comentarios (idproducto, iduser, comentario, calificacion) VALUES (?, ?, ?, ?)';
            db.query(query, [idproducto, iduser, comentario, calificacion], (err, results) => {
                if (err) {
                    console.error('Error al agregar el comentario:', err);
                    res.status(500).json({ error: 'Error al agregar el comentario' });
                    return;
                }
                res.status(201).json({ message: 'Comentario y calificación agregados correctamente' });
            });
        }
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
    const { user, password, email, fecha_nacimiento, sexo, foto, estado } = req.body;
    const idrol = 1; // ID de rol predeterminado
    const defaultFoto = foto || 'uploads/default.jpg'; // Asignar imagen por defecto si no se proporciona una

    createUser(user, password, email, fecha_nacimiento, sexo, defaultFoto, estado, idrol, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }

        const userId = results.insertId; // Obtener el ID del nuevo usuario

        // Buscar el cupón con el código NUEVOU53R
        const queryCupon = 'SELECT idcupon FROM cupones WHERE codigo = "NUEVOU53R" AND activo = 1';
        db.query(queryCupon, (err, resultsCupon) => {
            if (err) {
                return res.status(500).send(err);
            }
            
            if (resultsCupon.length === 0) {
                return res.status(404).json({ message: 'Cupón no encontrado o inactivo' });
            }

            const cuponId = resultsCupon[0].idcupon;

            // Asignar el cupón al nuevo usuario
            const queryAsignarCupon = 'INSERT INTO user_cupones (iduser, idcupon) VALUES (?, ?)';
            db.query(queryAsignarCupon, [userId, cuponId], (err) => {
                if (err) {
                    return res.status(500).send(err);
                }

                res.status(201).json({ message: 'Usuario registrado exitosamente y cupón asignado' });
            });
        });
    });
});




// Endpoint POST para registrar un administrador
app.post('/nuevo-admin', async (req, res) => {
    const { user, password, email, fecha_nacimiento, sexo, foto, estado } = req.body;
    const idrol = 2; // ID de rol para administrador
    const defaultFoto = foto || 'uploads/default.jpg';
    createAdmin(user, password, email, fecha_nacimiento, sexo, defaultFoto, estado, idrol, (err, results) => {
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
    const { user, password, email, fecha_nacimiento, sexo, foto, estado, idrol } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, foto, estado, idrol, (err, results) => {
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
    const { user, password, email, fecha_nacimiento, sexo, foto, estado, idrol } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, foto, estado, idrol, (err, results) => {
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
  const query = `
    SELECT 
      producto.*, 
      users.user AS nombre_usuario, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    LEFT JOIN 
      users ON producto.iduser = users.iduser
    WHERE 
      producto.tipo_personalizacion = 'no_personalizado' 
    GROUP BY 
      producto.idproducto, users.user
  `;

  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

app.get('/productos-usuario/:iduser', (req, res) => {
    const { iduser } = req.params;
  
    const query = `
      SELECT 
        producto.*, 
        users.user AS nombre_usuario, 
        IFNULL(ROUND(
          (
            SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
            SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
            SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
            SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
            SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
          ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
      FROM 
        producto
      LEFT JOIN 
        comentarios ON producto.idproducto = comentarios.idproducto
      LEFT JOIN 
        users ON producto.iduser = users.iduser
      WHERE 
        producto.iduser = ? 
        AND producto.tipo_personalizacion = 'no_personalizado'
      GROUP BY 
        producto.idproducto, users.user
    `;
  
    db.query(query, [iduser], (err, results) => {
      if (err) {
        res.status(500).send(err);
        return;
      }
      res.status(200).json(results);
    });
  });

app.get('/productos-personalizados-usuario/:iduser', (req, res) => {
    const { iduser } = req.params;
  
    const query = `
      SELECT 
        producto.*, 
        users.user AS nombre_usuario, 
        IFNULL(ROUND(
          (
            SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
            SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
            SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
            SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
            SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
          ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
      FROM 
        producto
      LEFT JOIN 
        comentarios ON producto.idproducto = comentarios.idproducto
      LEFT JOIN 
        users ON producto.iduser = users.iduser
      WHERE 
        producto.iduser = ? 
        AND producto.tipo_personalizacion = 'personalizado'
      GROUP BY 
        producto.idproducto, users.user
    `;
  
    db.query(query, [iduser], (err, results) => {
      if (err) {
        res.status(500).send(err);
        return;
      }
      res.status(200).json(results);
    });
  });
  
  

app.get('/productos-personalizados', (req, res) => {
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    WHERE 
      producto.tipo_personalizacion = 'personalizado'  
    GROUP BY 
      producto.idproducto
  `;

  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(200).json(results);
  });
});

app.get('/productos-admin', (req, res) => {
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    GROUP BY 
      producto.idproducto
  `;

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
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    WHERE 
      producto.tipo_personalizacion = 'no_personalizado' 
    GROUP BY 
      producto.idproducto
    ORDER BY 
      producto.created_at DESC 
    LIMIT 4
  `;

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
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    WHERE 
      producto.descuento > 0
    GROUP BY 
      producto.idproducto
  `;

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
  
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    WHERE 
      producto.idproducto = ?
    GROUP BY 
      producto.idproducto
  `;

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
    const { iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, tipo_personalizacion } = req.body;
  
    const descuentoAplicado = descuento || 0;
  
    createProducto(iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuentoAplicado, tipo_personalizacion, (err, results) => {
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
    const { iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuento, tipo_personalizacion } = req.body;
  
    const descuentoAplicado = descuento || 0;
  
    updateProducto(idproducto, iduser, p_producto, nomprod, clave, descripcion, foto, foto2, foto3, descuentoAplicado, tipo_personalizacion, (err, results) => {
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
    
    const query = `
        SELECT 
            producto.*, 
            IFNULL(ROUND(
                (
                    SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
                    SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
                    SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
                    SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
                    SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
                ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
        FROM 
            producto
        LEFT JOIN 
            comentarios ON producto.idproducto = comentarios.idproducto
        WHERE 
            producto.nomprod LIKE ?
        GROUP BY 
            producto.idproducto
    `;
    
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

// Endpoint GET para buscar productos con descuento por nombre
app.get('/buscar-producto-descuento', (req, res) => {
    const { nombre } = req.query;
    const query = `
        SELECT 
            producto.*, 
            IFNULL(ROUND(
                (
                    SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
                    SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
                    SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
                    SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
                    SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
                ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
        FROM 
            producto
        LEFT JOIN 
            comentarios ON producto.idproducto = comentarios.idproducto
        WHERE 
            producto.nomprod LIKE ? AND producto.descuento > 0
        GROUP BY 
            producto.idproducto
    `;
    
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
// Endpoint para obtener un producto por clave
app.get('/clave-producto/:clave', (req, res) => {
    const { clave } = req.params;
    
    const query = `
      SELECT 
        producto.*, 
        IFNULL(ROUND(
          (
            SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
            SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
            SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
            SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
            SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
          ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
      FROM 
        producto
      LEFT JOIN 
        comentarios ON producto.idproducto = comentarios.idproducto
      WHERE 
        producto.clave = ?
      GROUP BY 
        producto.idproducto
    `;
  
    db.query(query, [clave], (err, results) => {
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

// Endpoint para obtener las claves de los productos con descuento
app.get('/claves-productos-con-descuento', (req, res) => {
  const query = 'SELECT DISTINCT clave FROM producto WHERE descuento > 0';
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
    
    const query = `
      SELECT 
        producto.*, 
        IFNULL(ROUND(
          (
            SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
            SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
            SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
            SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
            SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
          ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
      FROM 
        producto
      LEFT JOIN 
        comentarios ON producto.idproducto = comentarios.idproducto
      WHERE 
        producto.clave = ? AND producto.descuento > 0
      GROUP BY 
        producto.idproducto
    `;
  
    db.query(query, [clave], (err, results) => {
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


// Endpoint para obtener productos aleatorios por clave
app.get('/productos-aleatorios/:id/:clave', (req, res) => {
  const { id, clave } = req.params;
  const query = `
    SELECT 
      producto.*, 
      IFNULL(ROUND(
        (
          SUM(CASE WHEN comentarios.calificacion = 1 THEN 1 ELSE 0 END) * 1 +
          SUM(CASE WHEN comentarios.calificacion = 2 THEN 1 ELSE 0 END) * 2 +
          SUM(CASE WHEN comentarios.calificacion = 3 THEN 1 ELSE 0 END) * 3 +
          SUM(CASE WHEN comentarios.calificacion = 4 THEN 1 ELSE 0 END) * 4 +
          SUM(CASE WHEN comentarios.calificacion = 5 THEN 1 ELSE 0 END) * 5
        ) / NULLIF(COUNT(comentarios.calificacion), 0), 2), 0) AS calificacion_final
    FROM 
      producto
    LEFT JOIN 
      comentarios ON producto.idproducto = comentarios.idproducto
    WHERE 
      producto.clave = ? AND producto.idproducto != ?
    GROUP BY 
      producto.idproducto
    ORDER BY 
      RAND() 
    LIMIT 4
  `;

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
    const { fecha, iduser, productos, codigoCupon, detalleEntrega, detallePersonalizacion } = req.body;

    // Desestructurar los valores de detalleEntrega
    const { pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono } = detalleEntrega;

    console.log('Datos recibidos en la solicitud:', req.body);

    const procesarProductosConDescuento = (descuento) => {
        const productosProcesados = [];

        productos.forEach((producto, index) => {
            const productQuery = 'SELECT p_final, clave FROM producto WHERE idproducto = ?';
            db.query(productQuery, [producto.idproducto], (productErr, productResults) => {
                if (productErr) {
                    console.error('Error al consultar el producto:', productErr);
                    return res.status(500).json({ message: 'Error interno del servidor' });
                }
                if (productResults.length === 0) {
                    return res.status(404).json({ message: `Producto con id ${producto.idproducto} no encontrado` });
                }
                const { p_final, clave } = productResults[0];
                let total_producto = p_final * producto.cantidad;
                if (descuento > 0) {
                    total_producto -= total_producto * (descuento / 100);
                }
                productosProcesados.push({
                    idproducto: producto.idproducto,
                    cantidad: producto.cantidad,
                    talla: producto.talla, // Guardar la talla
                    tipo_personalizacion: producto.tipo_personalizacion,
                    total_producto: total_producto,
                    clave: clave // Agregar la clave aquí para utilizarla en la verificación de cupones
                });

                if (index === productos.length - 1) {
                    createCompras(fecha, iduser, productosProcesados, (compraErr, compraResults) => {
                        if (compraErr) {
                            console.error('Error al crear la compra:', compraErr);
                            return res.status(500).json({ message: 'Error interno del servidor' });
                        }
                        const idcompra = compraResults.insertId;

                        // Crear los detalles de la compra
                        createComprasDetalles(idcompra, productosProcesados, codigoCupon, (detalleErr) => {
                            if (detalleErr) {
                                console.error('Error al crear los detalles de la compra:', detalleErr);
                                return res.status(500).json({ message: 'Error interno del servidor' });
                            }

                            // Crear el detalle de entrega
                            createDetalleEntrega(idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, (entregaErr) => {
                                if (entregaErr) {
                                    console.error('Error al crear el detalle de entrega:', entregaErr);
                                    return res.status(500).json({ message: 'Error interno del servidor al crear detalle de entrega' });
                                }

                                // Crear el detalle de personalización solo si es personalizado
                                if (producto.tipo_personalizacion === 'personalizado') {
                                    const { lado_frontal, lado_trasero, foto, foto2 } = detallePersonalizacion;
                                    let fotoPath = '';
                                    let foto2Path = '';
                                    try {
                                        if (foto) {
                                            fotoPath = base64ToFile(foto, 'fotofrontal.png');
                                        }
                                        if (foto2) {
                                            foto2Path = base64ToFile(foto2, 'fototrasero.png');
                                        }
                                    } catch (error) {
                                        console.error('Error al convertir imágenes:', error);
                                        return res.status(500).json({ message: 'Error interno del servidor al convertir imágenes' });
                                    }
                                    createDetallePersonalizacion(idcompra, lado_frontal, lado_trasero, fotoPath, foto2Path, (personalizacionErr) => {
                                        if (personalizacionErr) {
                                            console.error('Error al crear el detalle de personalización:', personalizacionErr);
                                            return res.status(500).json({ message: 'Error interno del servidor al crear detalle de personalización' });
                                        }
                                        verificarYAsignarCupones(iduser, productosProcesados, (err, cuponMessage) => {
                                            if (err) {
                                                console.error('Error al asignar cupones:', err);
                                                return res.status(500).json({ message: 'Error al asignar cupones' });
                                            }
                                            res.status(201).json({ message: `Compra y detalles creados exitosamente. ${cuponMessage}` });
                                        });
                                    });
                                } else {
                                    createDetallePersonalizacion(idcompra, null, null, null, null, (personalizacionErr) => {
                                        if (personalizacionErr) {
                                            console.error('Error al crear el detalle de personalización:', personalizacionErr);
                                            return res.status(500).json({ message: 'Error interno del servidor al crear detalle de personalización' });
                                        }
                                        verificarYAsignarCupones(iduser, productosProcesados, (err, cuponMessage) => {
                                            if (err) {
                                                console.error('Error al asignar cupones:', err);
                                                return res.status(500).json({ message: 'Error al asignar cupones' });
                                            }
                                            res.status(201).json({ message: `Compra y detalles creados exitosamente. ${cuponMessage}` });
                                        });
                                    });
                                }
                            });
                        });
                    });
                }
            });
        });
    };

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
        if (codigoCupon) {
            const cuponQuery = 'SELECT * FROM cupones WHERE codigo = ? AND activo = 1 AND usos_maximos > 0 AND fecha_expiracion >= NOW()';
            db.query(cuponQuery, [codigoCupon], (cuponErr, cuponResults) => {
                if (cuponErr) {
                    console.error('Error al validar el cupón:', cuponErr);
                    return res.status(500).send(cuponErr);
                }
                if (cuponResults.length === 0) {
                    return res.status(404).json({ message: 'Cupón no válido o expirado' });
                }
                const descuento = cuponResults[0].porcentaje; // Obtener el porcentaje de descuento
                procesarProductosConDescuento(descuento);
            });
        } else {
            procesarProductosConDescuento(0);
        }
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
                    talla: producto.talla, 
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

// Crear pago
app.post('/create-payment', async (req, res) => {
  const request = new paypal.orders.OrdersCreateRequest();
  request.prefer("return=representation");
  request.requestBody({
    intent: 'CAPTURE',
    purchase_units: [{
      amount: {
        currency_code: 'USD',
        value: '100.00' // Cambia este valor según lo que quieras cobrar
      }
    }]
  });

  try {
    const order = await client.execute(request);
    res.json({ id: order.result.id }); // Devuelve el ID del pedido para usar en la captura
  } catch (err) {
    res.status(500).send(err);
  }
});

// Capturar el pago
app.post('/capture-payment', async (req, res) => {
  const orderID = req.body.orderID;
  const request = new paypal.orders.OrdersCaptureRequest(orderID);
  request.requestBody({});

  try {
    const capture = await client.execute(request);
    res.json({ status: capture.result.status });
  } catch (err) {
    res.status(500).send(err);
  }
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
    const query = 'SELECT cd.iddetalle, cd.idcompra,  cd.productos, cd.total , cd.codigoCupon FROM compras_detalle cd WHERE cd.idcompra = ?';
    
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
                    total: detalle.total,
                    codigoCupon : detalle.codigoCupon
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
    const { idcompra, productos, codigoCupon } = req.body; // Ahora recibe codigoCupon

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
                talla: producto.talla, // Guardar la talla
                total_producto: total_producto
            });

            // Verificar si todos los productos han sido procesados
            if (index === productos.length - 1) {
                // Crear los detalles de la compra incluyendo el codigoCupon
                createComprasDetalles(idcompra, productosProcesados, codigoCupon, (detalleErr) => {
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
    const { porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion } = req.body;
    createCupon(porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.status(201).json({ message: 'Cupón creado exitosamente' });
    });
});


// Endpoint PUT para actualizar un cupón
app.put('/actualizar-cupon/:idcupon', (req, res) => {
    const { idcupon } = req.params;
    const { porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion } = req.body;
    updateCupon(idcupon, porcentaje, codigo, fecha_expiracion, usos_maximos, activo, descripcion, (err, results) => {
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

// Endpoint para validar y usar el cupón
app.post('/validar-cupon', (req, res) => {
    const { iduser, codigo } = req.body;

    // Validar el cupón y verificar si ya ha sido usado por el usuario
    const queryValidarCupon = `
        SELECT cupones.idcupon, cupones.porcentaje, cupones.usos_maximos, cupones.usos_actuales 
        FROM cupones 
        JOIN user_cupones ON cupones.idcupon = user_cupones.idcupon 
        LEFT JOIN cupones_usados ON cupones.idcupon = cupones_usados.idcupon AND cupones_usados.iduser = user_cupones.iduser
        WHERE cupones.codigo = ? 
          AND cupones.activo = 1 
          AND cupones.usos_maximos > cupones.usos_actuales 
          AND cupones.fecha_expiracion >= NOW() 
          AND user_cupones.iduser = ?
          AND cupones_usados.idcupon IS NULL
    `;
    
    db.query(queryValidarCupon, [codigo, iduser], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón no válido, expirado, ya usado o no reclamado por el usuario' });
        }

        const cupon = results[0];

        // Actualizar los usos del cupón
        const queryActualizarUsos = 'UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE idcupon = ?';
        db.query(queryActualizarUsos, [cupon.idcupon], (err) => {
            if (err) {
                return res.status(500).send(err);
            }

            res.status(200).json({ message: 'Cupón válido', porcentaje: cupon.porcentaje });

            // Registrar el uso del cupón en la tabla cupones_usados
            const queryRegistrarUso = 'INSERT INTO cupones_usados (iduser, idcupon, fecha_uso) VALUES (?, ?, NOW())';
            db.query(queryRegistrarUso, [iduser, cupon.idcupon], (err) => {
                if (err) {
                    console.error('Error al registrar el uso del cupón:', err);
                }
            });
        });
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


app.get('/detalle-entrega', (req, res) => {
    const query = 'SELECT * FROM detalle_entrega';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.get('/detalle-entrega/:identrega', (req, res) => {
    const { identrega } = req.params;

    const query = 'SELECT * FROM detalle_entrega WHERE identrega = ?';

    db.query(query, [identrega], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error al buscar el detalle de entrega' });
        }

        if (result.length === 0) {
            return res.status(404).json({ message: 'Detalle de entrega no encontrado' });
        }

        res.json(result[0]);
    });
});



// Ruta para obtener un detalle de entrega por idcompra
app.get('/detalle-entregaxcompra/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    const query = 'SELECT * FROM detalle_entrega WHERE idcompra = ?';
    
    db.query(query, [idcompra], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error al buscar el detalle de entrega' });
        }

        if (result.length === 0) {
            return res.status(404).json({ message: 'Detalle de entrega no encontrado' });
        }

        // Devolver todos los registros como array, no solo el primero
        res.json(result);
    });
});


// Ruta para obtener un detalle de persoanlizacion por idcompra
app.get('/detalle-perxcompra/:idcompra', (req, res) => {
    const { idcompra } = req.params;

    const query = 'SELECT * FROM detalle_personalizacion WHERE idcompra = ?';
    
    db.query(query, [idcompra], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error al buscar el detalle de la personalizacion' });
        }

        if (result.length === 0) {
            return res.status(404).json({ message: 'detalle de la personalizacion no encontrado' });
        }

        // Devolver todos los registros como array, no solo el primero
        res.json(result);
    });
});


//apis para detalle de entrega

app.post('/nuevo-detalle-entrega', (req, res) => {
    const { idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono } = req.body;
    createDetalleEntrega(idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(201).json({ message: 'Detalle de entrega creado con éxito', identrega: result.insertId });
    });
});



app.put('/actualizar-detalle-entrega/:identrega', (req, res) => {
    const { identrega } = req.params;
    const { idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono } = req.body;

    updateDetalleEntrega(identrega, idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json({ message: 'Detalle de entrega actualizado con éxito' });
    });
});


app.delete('/eliminar-detalle-entrega/:identrega', (req, res) => {
    const { identrega } = req.params;

    deleteDetalleEntrega(identrega, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json({ message: 'Detalle de entrega eliminado con éxito' });
    });
});


// Endpoint para obtener los detalles de la compra y los detalles de entrega
app.get('/generar-pdf/:idcompra', (req, res) => {
  const { idcompra } = req.params;

  // Consulta para obtener los detalles de la compra
  const queryCompras = 'SELECT idcompra, iduser, productos, total, fecha FROM compras WHERE idcompra = ?';

  // Consulta para obtener los detalles de la compra (compras_detalle)
  const queryComprasDetalle = 'SELECT iddetalle, idcompra, productos, total, codigoCupon FROM compras_detalle WHERE idcompra = ?';

  // Consulta para obtener los detalles de entrega
  const queryDetalleEntrega = 'SELECT identrega, idcompra, pais, nombre, apellidos, direccion, colonia, codigo_postal, ciudad, estado, telefono FROM detalle_entrega WHERE idcompra = ?';

  db.query(queryCompras, [idcompra], (err, comprasResults) => {
    if (err) {
      return res.status(500).send(err);
    }

    if (comprasResults.length === 0) {
      return res.status(404).json({ message: 'Compra no encontrada' });
    }

    const compra = comprasResults[0];

    db.query(queryComprasDetalle, [idcompra], (err, comprasDetalleResults) => {
      if (err) {
        return res.status(500).send(err);
      }

      if (comprasDetalleResults.length === 0) {
        return res.status(404).json({ message: 'Detalles de compra no encontrados' });
      }

      const comprasDetalle = comprasDetalleResults[0];

      db.query(queryDetalleEntrega, [idcompra], (err, detalleEntregaResults) => {
        if (err) {
          return res.status(500).send(err);
        }

        if (detalleEntregaResults.length === 0) {
          return res.status(404).json({ message: 'Detalles de entrega no encontrados' });
        }

        const detalleEntrega = detalleEntregaResults[0];

        // Procesar los productos de la compra
        let productosParsed;

        try {
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
            res.json({
              compra,
              comprasDetalle,
              detalleEntrega,
              productos
            });
          }).catch(err => {
            throw err;
          });
        } catch (error) {
          throw new Error('Error al parsear productos');
        }
      });
    });
  });
});
// Endpoint POST para agregar personalización
app.post('/nueva-personalizacion', async (req, res) => {
  const { idproducto, texto_personalizado, imagen_personalizada, color } = req.body;

  createPersonalizacion(idproducto, texto_personalizado, imagen_personalizada, color, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.status(201).json({ message: 'Personalización agregada exitosamente' });
  });
});

// Endpoint PUT para actualizar una personalización
app.put('/actualizar-personalizacion/:idpersonalizacion', async (req, res) => {
  const { idpersonalizacion } = req.params;
  const { idproducto, texto_personalizado, imagen_personalizada, color } = req.body;

  updatePersonalizacion(idpersonalizacion, idproducto, texto_personalizado, imagen_personalizada, color, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.affectedRows === 0) {
      res.status(404).json({ message: 'Personalización no encontrada' });
      return;
    }
    res.status(200).json({ message: 'Información de la personalización actualizada exitosamente' });
  });
});

// Endpoint DELETE para eliminar una personalización
app.delete('/eliminar-personalizacion/:idpersonalizacion', (req, res) => {
  const { idpersonalizacion } = req.params;
  deletePersonalizacion(idpersonalizacion, (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.affectedRows === 0) {
      res.status(404).json({ message: 'Personalización no encontrada' });
      return;
    }
    res.status(200).json({ message: 'Personalización eliminada exitosamente' });
  });
});


// Endpoint para obtener los productos más calificados
app.get('/productos-mas-calificados', (req, res) => {
    const query = `
      SELECT p.idproducto, p.nomprod, AVG(c.calificacion) AS promedio_calificacion
      FROM producto p
      JOIN comentarios c ON p.idproducto = c.idproducto
      GROUP BY p.idproducto
      ORDER BY promedio_calificacion DESC
      LIMIT 3;  -- Puedes ajustar el límite según lo que necesites
    `;
  
    db.query(query, (err, results) => {
      if (err) {
        console.error('Error al obtener los productos más calificados:', err);
        res.status(500).json({ error: 'Error al obtener los productos más calificados' });
        return;
      }
      res.status(200).json(results);
    });
  });
// Endpoint para obtener la cantidad de administradores
app.get('/cantidad-administradores', (req, res) => {
    // Cambia '2' por el idrol correspondiente al rol de administrador en tu base de datos
    const idRolAdministrador = 2; 
    const query = 'SELECT COUNT(*) AS cantidad_administradores FROM users WHERE idrol = ?';
  
    db.query(query, [idRolAdministrador], (err, result) => {
      if (err) {
        console.error('Error al obtener la cantidad de administradores:', err);
        res.status(500).json({ error: 'Error al obtener la cantidad de administradores' });
        return;
      }
      res.status(200).json({ cantidad_administradores: result[0].cantidad_administradores });
    });
  });
 // Endpoint para obtener la cantidad total de usuarios
app.get('/cantidad-usuarios', (req, res) => {
    const query = 'SELECT COUNT(*) AS cantidad_usuarios FROM users'; // Asegúrate de que la tabla y columna sean correctas
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener la cantidad de usuarios:', err);
        res.status(500).json({ error: 'Error al obtener la cantidad de usuarios' });
        return;
      }
      res.status(200).json({ cantidad_usuarios: result[0].cantidad_usuarios });
    });
  });


  //visitas totales

  app.get('/vistas-totales', (req, res) => {
    const query = 'SELECT SUM(numero_de_visitas) AS total_visitas FROM visitas_por_mes'; 
  
    db.query(query, (err, result) => {
      if (err) {
        console.error('Error al obtener el total de visitas:', err);
        res.status(500).json({ error: 'Error al obtener el total de visitas' });
        return;
      }
      res.status(200).json({ total_visitas: result[0].total_visitas });
    });
  });


// Usuarios Recientes
  app.get('/usuarios-recientes', (req, res) => {
  const query = `
    SELECT *
FROM users
ORDER BY created_at DESC
LIMIT 8;

  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los usuarios recientes:', err);
      res.status(500).json({ error: 'Error al obtener los usuarios recientes' });
      return;
    }
    res.status(200).json(result);
  });
});


// Top estados

app.get('/top-estados', (req, res) => {
  const query = `
    SELECT 
        estado,
        COUNT(*) AS total_usuarios,
        ROUND((COUNT(*) / (SELECT COUNT(*) FROM users) * 100), 1) AS porcentaje
    FROM 
        users
    GROUP BY 
        estado
    ORDER BY 
        total_usuarios DESC
    LIMIT 5;
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los estados con más usuarios:', err);
      res.status(500).json({ error: 'Error al obtener los estados con más usuarios' });
      return;
    }
    res.status(200).json(result);
  });
});



  //Backend

//TOP COMPRAS
const getTopPurchasedProducts = (callback) => {
    const query = `
        SELECT 
            p.idproducto,
            p.nomprod AS nombre_producto,
            p.foto AS foto,
            SUM(
                JSON_UNQUOTE(JSON_EXTRACT(productos, '$[0].cantidad')) +
                IF(JSON_UNQUOTE(JSON_EXTRACT(productos, '$[1].cantidad')) IS NOT NULL, JSON_UNQUOTE(JSON_EXTRACT(productos, '$[1].cantidad')), 0) +
                IF(JSON_UNQUOTE(JSON_EXTRACT(productos, '$[2].cantidad')) IS NOT NULL, JSON_UNQUOTE(JSON_EXTRACT(productos, '$[2].cantidad')), 0)
            ) AS total_comprado
        FROM compras c
        JOIN producto p ON JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[0].idproducto')) = p.idproducto
        GROUP BY p.idproducto, p.nomprod, p.foto
        ORDER BY total_comprado DESC
        LIMIT 5;
    `;

    db.query(query, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        callback(null, results);
    });
};

// Uso de la función en un endpoint
app.get('/top-productos-comprados', (req, res) => {
    getTopPurchasedProducts((err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener los productos más comprados' });
        }
        res.status(200).json(results);
    });
});

//TOP USERS
const getTopUserPurchases = (callback) => {  
    const query = `
        SELECT 
            u.user AS nombre_usuario,
            u.foto AS foto_usuario,
            c.iduser,
            SUM(
                COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[0].cantidad')) AS UNSIGNED), 0) +
                COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[1].cantidad')) AS UNSIGNED), 0) +
                COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[2].cantidad')) AS UNSIGNED), 0) +
                COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[3].cantidad')) AS UNSIGNED), 0) +
                COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(c.productos, '$[4].cantidad')) AS UNSIGNED), 0)
            ) AS cantidad_compras
        FROM compras c
        JOIN users u ON c.iduser = u.iduser
        GROUP BY c.iduser, u.user, u.foto
        ORDER BY cantidad_compras DESC
        LIMIT 6;  
    `;

    db.query(query, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        callback(null, results);
    });
};

// Endpoint para obtener los 10 usuarios con más compras
app.get('/top-usuarios-compras', (req, res) => {
    getTopUserPurchases((err, results) => {
        if (err) {
            res.status(500).json({ error: 'Error al obtener el ranking de usuarios' });
            return;
        }
        res.status(200).json(results);
    });
});


//ENDPOINT PARA DETALLE DE PERSONALIZACION


app.post('/nuevo-detalle-personalizacion', (req, res) => {
    const { idcompra, lado_frontal, lado_trasero, foto, foto2 } = req.body;
    createDetallePersonalizacion(idcompra, lado_frontal, lado_trasero, foto, foto2, (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(201).json({ message: 'Detalle de personalización creado con éxito', idpersonalizacion: result.insertId });
    });
});

app.put('/actualizar-detalle-personalizacion/:idpersonalizacion', (req, res) => {
    const { idpersonalizacion } = req.params;
    const { idcompra, lado_frontal, lado_trasero, foto, foto2 } = req.body;

    updateDetallePersonalizacion(idpersonalizacion, idcompra, lado_frontal, lado_trasero, foto, foto2, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json({ message: 'Detalle de personalización actualizado con éxito' });
    });
});

app.delete('/eliminar-detalle-personalizacion/:idpersonalizacion', (req, res) => {
    const { idpersonalizacion } = req.params;

    deleteDetallePersonalizacion(idpersonalizacion, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json({ message: 'Detalle de personalización eliminado con éxito' });
    });
});

app.get('/compras-no-personalizado', (req, res) => {
    const query = `SELECT * FROM compras WHERE JSON_CONTAINS(productos, '{"tipo_personalizacion": "no_personalizado"}')`;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener las compras:', err);
            return res.status(500).json({ message: 'Error interno del servidor' });
        }
        res.status(200).json(results);
    });
});

app.get('/compras-personalizado', (req, res) => {
    const query = `SELECT * FROM compras WHERE JSON_CONTAINS(productos, '{"tipo_personalizacion": "personalizado"}')`;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener las compras:', err);
            return res.status(500).json({ message: 'Error interno del servidor' });
        }
        res.status(200).json(results);
    });
});


// TODO LO QUE TENGA QUE VER CON CUPONES VA AQUI

// Endpoint GET para obtener cupones reclamados por un usuario
app.get('/cupones-reclamados/:iduser', (req, res) => {
    const { iduser } = req.params;

    const query = `
        SELECT cupones.*, user_cupones.fecha_reclamacion, cupones_usados.fecha_uso 
        FROM cupones 
        JOIN user_cupones ON cupones.idcupon = user_cupones.idcupon
        LEFT JOIN cupones_usados ON cupones.idcupon = cupones_usados.idcupon AND cupones_usados.iduser = user_cupones.iduser
        WHERE user_cupones.iduser = ?
    `;

    db.query(query, [iduser], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'No se encontraron cupones para este usuario' });
        }
        res.status(200).json(results);
    });
});




// REGLAS DE CUPONES

const cuponesReglas = [
    { clave: 'One Piece', cantidadRequerida: 3, codigoCupon: 'ONEPIECE5', descripcion: 'Compra 3 productos con la temática de One Piece y obtén un cupón del 5%' },
    { clave: 'Dragon Ball', cantidadRequerida: 2, codigoCupon: 'SAIYAN2', descripcion: 'Compra 2 productos con temática de Dragon Ball y obtén un cupón de descuento del 5%' },
    { clave: 'Dragon Ball', cantidadRequerida: 3, codigoCupon: 'DRAGON2024', descripcion: 'Compra 3 productos con temática de Dragon Ball y obtén un cupón de descuento del 10%' }
];

const verificarYAsignarCupones = (iduser, productos, callback) => {
    let cuponesAsignados = [];

    cuponesReglas.forEach((cupon, index) => {
        const productoCount = productos.reduce((count, producto) => {
            return producto.clave === cupon.clave ? count + producto.cantidad : count;
        }, 0);

        console.log(`Cantidad de productos con clave ${cupon.clave}: ${productoCount}`);

        if (productoCount >= cupon.cantidadRequerida && !cuponesAsignados.includes(cupon.codigoCupon)) {
            console.log(`Verificando existencia del cupón ${cupon.codigoCupon} para el usuario ${iduser}`);
            const queryVerificarCupon = `
                SELECT cupones.idcupon 
                FROM user_cupones 
                JOIN cupones ON user_cupones.idcupon = cupones.idcupon 
                WHERE user_cupones.iduser = ? 
                  AND cupones.codigo = ?
            `;
            db.query(queryVerificarCupon, [iduser, cupon.codigoCupon], (err, results) => {
                if (err) {
                    console.error('Error al verificar existencia del cupón:', err);
                    return callback(err);
                }

                if (results.length > 0) {
                    console.log(`El usuario ${iduser} ya tiene el cupón ${cupon.codigoCupon}`);
                    if (index === cuponesReglas.length - 1 && cuponesAsignados.length === 0) {
                        callback(null, 'No se asignaron cupones adicionales');
                    }
                    return;
                }

                const queryVerificarHistorial = `
                    SELECT cupones_usados.idcupon 
                    FROM cupones_usados 
                    JOIN cupones ON cupones_usados.idcupon = cupones.idcupon 
                    WHERE cupones_usados.iduser = ? 
                      AND cupones.codigo = ?
                `;
                db.query(queryVerificarHistorial, [iduser, cupon.codigoCupon], (err, results) => {
                    if (err) {
                        console.error('Error al verificar historial del cupón:', err);
                        return callback(err);
                    }

                    if (results.length > 0) {
                        console.log(`El usuario ${iduser} ya ha utilizado el cupón ${cupon.codigoCupon}`);
                        if (index === cuponesReglas.length - 1 && cuponesAsignados.length === 0) {
                            callback(null, 'No se asignaron cupones adicionales');
                        }
                        return;
                    }

                    console.log(`Asignando cupón ${cupon.codigoCupon} al usuario ${iduser}`);
                    const queryCupon = 'SELECT idcupon FROM cupones WHERE codigo = ? AND activo = 1';
                    db.query(queryCupon, [cupon.codigoCupon], (err, results) => {
                        if (err) {
                            console.error('Error al buscar el cupón:', err);
                            return callback(err);
                        }

                        if (results.length === 0) {
                            console.log(`Cupón ${cupon.codigoCupon} no encontrado o inactivo`);
                            return callback(new Error(`Cupón ${cupon.codigoCupon} no encontrado o inactivo`));
                        }

                        const cuponId = results[0].idcupon;
                        console.log(`Cupón ${cupon.codigoCupon} encontrado con id ${cuponId}`);

                        const queryAsignarCupon = 'INSERT INTO user_cupones (iduser, idcupon) VALUES (?, ?)';
                        db.query(queryAsignarCupon, [iduser, cuponId], (err) => {
                            if (err) {
                                console.error('Error al asignar el cupón:', err);
                                return callback(err);
                            }

                            cuponesAsignados.push(cupon.codigoCupon);
                            console.log(`Cupón ${cupon.codigoCupon} asignado exitosamente al usuario ${iduser}`);

                            if (index === cuponesReglas.length - 1) {
                                callback(null, `Cupones asignados: ${cuponesAsignados.join(', ')}`);
                            }
                        });
                    });
                });
            });
        } else if (index === cuponesReglas.length - 1 && cuponesAsignados.length === 0) {
            callback(null, 'No se asignaron cupones adicionales');
        }
    });
};


// Endpoint para registrar el uso del cupón
app.post('/registrar-uso-cupon', (req, res) => {
    const { iduser, codigo } = req.body;

    const queryCupon = 'SELECT idcupon FROM cupones WHERE codigo = ?';
    db.query(queryCupon, [codigo], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón no encontrado' });
        }

        const cuponId = results[0].idcupon;
        const queryRegistrarUso = 'INSERT INTO cupones_usados (iduser, idcupon, fecha_uso) VALUES (?, ?, NOW())';
        db.query(queryRegistrarUso, [iduser, cuponId], (err) => {
            if (err) {
                return res.status(500).send(err);
            }
            res.status(200).json({ message: 'Uso del cupón registrado exitosamente' });
        });
    });
});


const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor funcionando en el puerto ${port}`);
});

