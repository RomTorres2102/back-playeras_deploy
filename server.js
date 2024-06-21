import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import crypto from 'crypto';  
import multer from 'multer'; 
import path from 'path'; 
import { fileURLToPath } from 'url';
import { dirname } from 'path';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
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
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No se subió ningún archivo' });
  }
  res.status(200).json({ filepath: `uploads/${req.file.filename}` });
});

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect(err => {
    if (err) {
        console.error('Error al conectar con la BD:', err);
        return;
    }
    console.log('Conectado a la base de datos');
});

// Funciones del modelo de usuario
const createUser = async (user, password, email, fecha_nacimiento, sexo, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo, idrol) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, 1], callback); // idrol por defecto es 1
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


const updateUser = async (iduser, user, password, email, fecha_nacimiento, sexo, idrol, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'UPDATE users SET user = ?, password = ?, email = ?, fecha_nacimiento = ?, sexo = ?, idrol = ? WHERE iduser = ?';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, idrol, iduser], callback);
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

// Funciones de modelo de Productos
const createProducto = async (p_producto, nomprod, clave, descripcion, foto, callback) => {
  try {
    const query = 'INSERT INTO producto (p_producto, nomprod, clave, descripcion, foto) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [p_producto, nomprod, clave, descripcion, foto], callback);
  } catch (err) {
    callback(err, null);
  }
};

const updateProducto = async (idproducto, p_producto, nomprod, clave, descripcion, foto, callback) => {
  try {
    const query = 'UPDATE producto SET p_producto = ?, nomprod = ?, clave = ?, descripcion = ?, foto = ? WHERE idproducto = ?';
    db.query(query, [p_producto, nomprod, clave, descripcion, foto, idproducto], callback);
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


//modelo de compra
const createCompra = (fecha, iduser, idproducto, cantidad, callback) => {
    // Obtener el precio del producto
    const getProductPriceQuery = 'SELECT p_producto FROM producto WHERE idproducto = ?';
    db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
        if (productErr) {
            return callback(productErr, null);
        }
        if (productResults.length === 0) {
            return callback(new Error('Producto no encontrado'), null);
        }

        const total = productResults[0].p_producto * cantidad;

        const query = 'INSERT INTO compra (total, fecha, iduser, idproducto, cantidad) VALUES (?, ?, ?, ?, ?)';
        db.query(query, [total, fecha, iduser, idproducto, cantidad], callback);
    });
};

const updateCompra = (idcompra, fecha, iduser, idproducto, cantidad, callback) => {
    // Obtener el precio del producto
    const getProductPriceQuery = 'SELECT p_producto FROM producto WHERE idproducto = ?';
    db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
        if (productErr) {
            return callback(productErr, null);
        }
        if (productResults.length === 0) {
            return callback(new Error('Producto no encontrado'), null);
        }

        const total = productResults[0].p_producto * cantidad;

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
        const getProductPriceQuery = 'SELECT p_producto FROM producto WHERE idproducto = ?';
        db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
            if (productErr) {
                return callback(productErr, null);
            }
            if (productResults.length === 0) {
                return callback(new Error('Producto no encontrado'), null);
            }

            const total = productResults[0].p_producto * cantidad;

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
            const getProductPriceQuery = 'SELECT p_producto FROM producto WHERE idproducto = ?';
            db.query(getProductPriceQuery, [idproducto], (productErr, productResults) => {
                if (productErr) {
                    return callback(productErr, null);
                }
                if (productResults.length === 0) {
                    return callback(new Error('Producto no encontrado'), null);
                }

                const total = productResults[0].p_producto * cantidad;

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
    const { user, password, email, fecha_nacimiento, sexo } = req.body;
    const idrol = 1; // ID de rol predeterminado
    createUser(user, password, email, fecha_nacimiento, sexo, idrol, (err, results) => {
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
    const { user, password, email, fecha_nacimiento, sexo, idrol } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, idrol, (err, results) => {
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
    const { p_producto, nomprod, clave, descripcion, foto } = req.body;
    createProducto(p_producto, nomprod, clave, descripcion, foto, (err, results) => {
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
  const { p_producto, nomprod, clave, descripcion, foto } = req.body;
  updateProducto(idproducto, p_producto, nomprod, clave, descripcion, foto, (err, results) => {
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
    const query = 'SELECT producto.nomprod AS producto, compra.cantidad, compra.total FROM compra JOIN producto ON compra.idproducto = producto.idproducto WHERE iduser = ?';
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


// Endpoint POST para agregar una compra
app.post('/nueva-compra', (req, res) => {
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



const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor funcionando en el puerto ${port}`);
});
