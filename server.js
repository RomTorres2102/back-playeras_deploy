import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

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
const createUser = async (user, password, email, fecha_nacimiento, sexo, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user, password, email, fecha_nacimiento, sexo) VALUES (?, ?, ?, ?, ?)';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo], callback);
    } catch (err) {
        callback(err, null);
    }
};

const updateUser = async (iduser, user, password, email, fecha_nacimiento, sexo, callback) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'UPDATE users SET user = ?, password = ?, email = ?, fecha_nacimiento = ?, sexo = ? WHERE iduser = ?';
        db.query(query, [user, hashedPassword, email, fecha_nacimiento, sexo, iduser], callback);
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

        callback(null, user);
    });
};

//Funciones de modelo de Productos
const createProducto = async (p_producto, nomprod, clave, descripcion, callback) => {
    try {
        const query = 'INSERT INTO producto (p_producto, nomprod, clave, descripcion) VALUES (?, ?, ?, ?)';
        db.query(query, [p_producto, nomprod, clave, descripcion], callback);
    } catch (err) {
        callback(err, null);
    }
};

const updateProducto = async (idproducto, p_producto, nomprod, clave, descripcion, callback) => {
    try {
        const query = 'UPDATE producto SET p_producto = ?, nomprod = ?, clave = ?, descripcion = ? WHERE idproducto = ?';
        db.query(query, [p_producto, nomprod, clave, descripcion, idproducto], callback);
    } catch (err) {
        callback(err, null);
    }
};

const deleteProducto = (idproducto, callback) => {
    const query = 'DELETE FROM producto WHERE idproducto = ?';
    db.query(query, [idproducto], callback);
};

// Función del modelo de compra
const createCompra = (total, fecha, iduser, idproducto, callback) => {
    const query = 'INSERT INTO compra (total, fecha, iduser, idproducto) VALUES (?, ?, ?, ?)';
    db.query(query, [total, fecha, iduser, idproducto], callback);
};

const updateCompra = async (idcompra, total, fecha, iduser, idproducto, callback) => {
    const checkUserQuery = 'SELECT * FROM users WHERE iduser = ?';
    const checkProductQuery = 'SELECT * FROM producto WHERE idproducto = ?';
    
    db.query(checkUserQuery, [iduser], (err, userResults) => {
        if (err) {
            return callback(err, null);
        }
        if (userResults.length === 0) {
            return callback(new Error('Usuario no encontrado'), null);
        }

        db.query(checkProductQuery, [idproducto], (err, productResults) => {
            if (err) {
                return callback(err, null);
            }
            if (productResults.length === 0) {
                return callback(new Error('Producto no encontrado'), null);
            }

            const query = 'UPDATE compra SET total = ?, fecha = ?, iduser = ?, idproducto = ? WHERE idcompra = ?';
            db.query(query, [total, fecha, iduser, idproducto, idcompra], callback);
        });
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
    createUser(user, password, email, fecha_nacimiento, sexo, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    });
});

// Endpoint PUT para actualizar un usuario
app.put('/actualizar-usuario/:iduser', async (req, res) => {
    const { iduser } = req.params;
    const { user, password, email, fecha_nacimiento, sexo } = req.body;
    updateUser(iduser, user, password, email, fecha_nacimiento, sexo, (err, results) => {
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
        res.status(200).json({ message: 'Login exitoso', user });
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
//Endpoint POST para agregar producto
app.post('/nuevo-producto', async (req, res) => {
    const { p_producto, nomprod, clave, descripcion} = req.body;
    createProducto(p_producto, nomprod, clave, descripcion, (err, results) => {
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
    const { p_producto, nomprod, clave, descripcion } = req.body;
    updateProducto(idproducto, p_producto, nomprod, clave, descripcion, (err, results) => {
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

//Endopoint GET para obtener todas las compras
app.get('/compras', (req, res) => {
    const query = `
        SELECT 
            compra.idcompra, 
            compra.total, 
            compra.fecha, 
            producto.nomprod as producto,
            users.user as usuario
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

// Endpoint POST para agregar una compra
app.post('/nueva-compra', async (req, res) => {
    const { total, fecha, iduser, idproducto } = req.body;

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
            createCompra(total, fecha, iduser, idproducto, (compraErr, compraResults) => {
                if (compraErr) {
                    res.status(500).send(compraErr);
                    return;
                }
                res.status(201).json({ message: 'Compra realizada exitosamente' });
            });
        });
    });
});

// Endpoint PUT para agregar una compra
app.put('/actualizar-compra/:idcompra', (req, res) => {
    const { idcompra } = req.params;
    const { total, fecha, iduser, idproducto } = req.body;
    
    updateCompra(idcompra, total, fecha, iduser, idproducto, (err, results) => {
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


// Endpoint DELETE para agregar una compra

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

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor funcionando en el puerto ${port}`);
});
