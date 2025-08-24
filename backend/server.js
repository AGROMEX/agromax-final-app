// AGROMEX - Motor con Autoinstalaci�n de Base de Datos
// Versi�n Final - Todas las Rutas Implementadas

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // Importar multer
const path = require('path'); // Importar path para manejar rutas de archivos
const cors = require('cors'); // Importar cors

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());
// Middleware para permitir CORS (Cross-Origin Resource Sharing)
app.use(cors());
// Servir archivos est�ticos desde la carpeta 'uploads'
// Esto permite que las im�genes subidas sean accesibles a trav�s de una URL
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- CONFIGURACI�N DE LA BASE DE DATOS ---
// Se asume que DATABASE_URL y JWT_SECRET est�n configuradas como variables de entorno
const connectionString = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET || 'secreto-de-desarrollo-muy-seguro'; // Usar un secreto fuerte en producci�n

const pool = new Pool({
    connectionString: connectionString,
    ssl: {
        rejectUnauthorized: false
    }
});

// --- CONFIGURACI�N DE MULTER PARA SUBIDA DE ARCHIVOS ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Aseg�rate de que la carpeta 'uploads' exista en la ra�z de tu proyecto
        // Render.com o servicios similares pueden requerir una configuraci�n de almacenamiento en la nube (ej. S3)
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        // Genera un nombre de archivo �nico para evitar colisiones
        cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({ storage: storage });

// --- SCRIPT DE CREACI�N DE LA BASE DE DATOS ---
const setupQuery = `
    -- ========= SECCI�N 0: LIMPIEZA PREVIA (TABLA POR TABLA) =========
    DROP TABLE IF EXISTS fotos_vacas CASCADE;
    DROP TABLE IF EXISTS registros_reproduccion CASCADE;
    DROP TABLE IF EXISTS registros_salud CASCADE;
    DROP TABLE IF EXISTS registros_produccion CASCADE;
    DROP TABLE IF EXISTS historial_movimientos CASCADE;
    DROP TABLE IF EXISTS vacas CASCADE;
    DROP TABLE IF EXISTS rodeos CASCADE;
    DROP TABLE IF EXISTS usuario_establecimiento_roles CASCADE;
    DROP TABLE IF EXISTS establecimientos CASCADE;
    DROP TABLE IF EXISTS usuarios CASCADE;

    -- ========= SECCI�N 1: AUTENTICACI�N Y GESTI�N DE ESTABLECIMIENTOS =========
    CREATE TABLE usuarios (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        nombre_completo VARCHAR(150),
        fecha_creacion TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE establecimientos (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(150) NOT NULL,
        numero_oficial VARCHAR(50),
        propietario_id INTEGER NOT NULL REFERENCES usuarios(id),
        fecha_creacion TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE usuario_establecimiento_roles (
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        rol VARCHAR(50) NOT NULL,
        PRIMARY KEY (usuario_id, establecimiento_id)
    );

    -- ========= SECCI�N 2: DATOS ESPEC�FICOS DEL ESTABLECIMIENTO =========
    CREATE TABLE rodeos (
        id SERIAL PRIMARY KEY,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        nombre VARCHAR(100) NOT NULL,
        descripcion TEXT,
        fecha_creacion TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE vacas (
        id SERIAL PRIMARY KEY,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        caravana_senasa VARCHAR(50),
        caravana_interna VARCHAR(50),
        nombre VARCHAR(100),
        raza VARCHAR(50),
        fecha_nacimiento DATE,
        estado_actual VARCHAR(50),
        estado_reproductivo VARCHAR(50),
        rodeo_id INTEGER REFERENCES rodeos(id),
        madre_id INTEGER REFERENCES vacas(id),
        padre_nombre VARCHAR(100),
        fecha_ingreso DATE DEFAULT CURRENT_DATE,
        activa BOOLEAN DEFAULT TRUE,
        UNIQUE (establecimiento_id, caravana_senasa),
        UNIQUE (establecimiento_id, caravana_interna)
    );

    CREATE TABLE historial_movimientos (
        id SERIAL PRIMARY KEY,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        vaca_id INTEGER NOT NULL REFERENCES vacas(id) ON DELETE CASCADE,
        rodeo_origen_id INTEGER REFERENCES rodeos(id),
        rodeo_destino_id INTEGER NOT NULL REFERENCES rodeos(id),
        fecha_movimiento TIMESTAMPTZ DEFAULT NOW(),
        motivo TEXT
    );
    
    CREATE TABLE registros_produccion (
        id SERIAL PRIMARY KEY,
        vaca_id INTEGER NOT NULL REFERENCES vacas(id) ON DELETE CASCADE,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        fecha_registro DATE NOT NULL,
        litros_dia DECIMAL(5, 2) NOT NULL,
        calidad_grasa DECIMAL(4, 2),
        calidad_proteina DECIMAL(4, 2),
        UNIQUE (vaca_id, fecha_registro)
    );

    CREATE TABLE registros_salud (
        id SERIAL PRIMARY KEY,
        vaca_id INTEGER NOT NULL REFERENCES vacas(id) ON DELETE CASCADE,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        fecha_evento DATE NOT NULL,
        tipo_evento VARCHAR(50) NOT NULL,
        descripcion TEXT NOT NULL,
        costo DECIMAL(10, 2),
        observaciones TEXT
    );

    CREATE TABLE registros_reproduccion (
        id SERIAL PRIMARY KEY,
        vaca_id INTEGER NOT NULL REFERENCES vacas(id) ON DELETE CASCADE,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        fecha_evento DATE NOT NULL,
        fecha_es_aproximada BOOLEAN DEFAULT FALSE,
        tipo_evento VARCHAR(50) NOT NULL,
        detalle TEXT,
        inseminador VARCHAR(100),
        cr�a_id_oficial VARCHAR(50)
    );

    CREATE TABLE fotos_vacas (
        id SERIAL PRIMARY KEY,
        vaca_id INTEGER NOT NULL REFERENCES vacas(id) ON DELETE CASCADE,
        establecimiento_id INTEGER NOT NULL REFERENCES establecimientos(id) ON DELETE CASCADE,
        url_foto VARCHAR(255) NOT NULL,
        descripcion TEXT,
        fecha_subida TIMESTAMPTZ DEFAULT NOW()
    );

    -- ========= SECCI�N 3: �NDICES PARA MEJORAR EL RENDIMIENTO =========
    CREATE INDEX idx_vacas_establecimiento ON vacas(establecimiento_id);
    CREATE INDEX idx_rodeos_establecimiento ON rodeos(establecimiento_id);
    CREATE INDEX idx_movimientos_vaca ON historial_movimientos(vaca_id);
    CREATE INDEX idx_produccion_vaca ON registros_produccion(vaca_id);
    CREATE INDEX idx_salud_vaca ON registros_salud(vaca_id);
    CREATE INDEX idx_reproduccion_vaca ON registros_reproduccion(vaca_id);
    CREATE INDEX idx_fotos_vaca ON fotos_vacas(vaca_id);
`;

// --- MIDDLEWARE DE AUTENTICACI�N (EL "GUARDIA DE SEGURIDAD") ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (token == null) return res.status(401).json({ message: 'No se proporcion� token de acceso.' });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token no v�lido o expirado.' });
        req.user = user;
        next();
    });
};

// --- MIDDLEWARE DE AUTORIZACI�N (VERIFICADOR DE PERMISOS DE ESTABLECIMIENTO) ---
const authorizeEstablecimiento = async (req, res, next) => {
    const establecimientoId = req.params.establecimientoId;
    const userId = req.user.userId;
    try {
        const checkAccessQuery = `SELECT * FROM usuario_establecimiento_roles WHERE usuario_id = $1 AND establecimiento_id = $2;`;
        const result = await pool.query(checkAccessQuery, [userId, establecimientoId]);
        if (result.rows.length === 0) {
            return res.status(403).json({ message: 'Acceso denegado a este establecimiento.' });
        }
        next();
    } catch (error) {
        console.error('Error en la autorizaci�n de establecimiento:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
};

// --- MIDDLEWARE DE AUTORIZACI�N PARA SUPERADMINISTRADOR ---
const authorizeAdmin = async (req, res, next) => {
    const userId = req.user.userId;
    try {
        const userQuery = 'SELECT email FROM usuarios WHERE id = $1';
        const result = await pool.query(userQuery, [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        const userEmail = result.rows[0].email;
        if (userEmail !== 'admin@agromex.com') {
            return res.status(403).json({ message: 'Acceso denegado. Se requieren privilegios de administrador.' });
        }
        next();
    } catch (error) {
        console.error('Error en la autorizaci�n de administrador:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
};


async function startServer() {
    let client;
    try {
        console.log('Conectando a la base de datos...');
        client = await pool.connect();
        console.log('Conexi�n exitosa. Verificando si las tablas existen...');
        const checkTable = await client.query("SELECT to_regclass('public.usuarios');");
        if (checkTable.rows[0].to_regclass === null) {
            console.log('Las tablas no existen. Creando la estructura de la base de datos...');
            await client.query(setupQuery);
            console.log('�Base de datos creada y configurada exitosamente!');
        } else {
            console.log('La base de datos ya est� configurada. Saltando la creaci�n de tablas.');
        }
    } catch (err) {
        console.error('Error durante la configuraci�n inicial de la base de datos:', err.stack);
    } finally {
        if (client) client.release();
    }

    // --- RUTAS DE LA API ---
    app.get('/', (req, res) => res.send('�El motor de AGROMEX est� en marcha y conectado a la base de datos!'));

    // --- Rutas de Autenticaci�n (p�blicas) ---
    app.post('/api/auth/register', async (req, res) => {
        const { email, password, nombre_completo } = req.body;
        if (!email || !password || !nombre_completo) {
            return res.status(400).json({ message: 'Todos los campos son requeridos: email, password, nombre_completo.' });
        }
        try {
            const salt = await bcrypt.genSalt(10);
            const password_hash = await bcrypt.hash(password, salt);
            const newUserQuery = `
                INSERT INTO usuarios (email, password_hash, nombre_completo)
                VALUES ($1, $2, $3)
                RETURNING id, email, nombre_completo, fecha_creacion;
            `;
            const result = await pool.query(newUserQuery, [email, password_hash, nombre_completo]);
            res.status(201).json({
                message: 'Usuario registrado exitosamente.',
                user: result.rows[0]
            });
        } catch (error) {
            if (error.code === '23505') {
                return res.status(409).json({ message: 'El email ya est� registrado.' });
            }
            console.error('Error en el registro de usuario:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.post('/api/auth/login', async (req, res) => {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email y password son requeridos.' });
        }
        try {
            const userQuery = 'SELECT * FROM usuarios WHERE email = $1';
            const result = await pool.query(userQuery, [email]);
            if (result.rows.length === 0) {
                return res.status(401).json({ message: 'Credenciales inv�lidas.' });
            }
            const user = result.rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (!isMatch) {
                return res.status(401).json({ message: 'Credenciales inv�lidas.' });
            }
            const payload = {
                userId: user.id,
                email: user.email
            };
            const token = jwt.sign(payload, jwtSecret, { expiresIn: '1d' });
            res.status(200).json({
                message: 'Inicio de sesi�n exitoso.',
                token: token,
                user: {
                    id: user.id,
                    email: user.email,
                    nombre_completo: user.nombre_completo
                }
            });
        } catch (error) {
            console.error('Error en el inicio de sesi�n:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    // --- Rutas de Establecimientos (protegidas) ---
    app.post('/api/establecimientos', authenticateToken, async (req, res) => {
        const { nombre, numero_oficial } = req.body;
        const propietarioId = req.user.userId;
        if (!nombre) {
            return res.status(400).json({ message: 'El nombre del establecimiento es un campo obligatorio.' });
        }
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const newEstablecimientoQuery = `
                INSERT INTO establecimientos (nombre, numero_oficial, propietario_id)
                VALUES ($1, $2, $3)
                RETURNING id, nombre, numero_oficial, fecha_creacion;
            `;
            const result = await pool.query(newEstablecimientoQuery, [nombre, numero_oficial, propietarioId]);
            const nuevoEstablecimiento = result.rows[0];
            const assignRoleQuery = `
                INSERT INTO usuario_establecimiento_roles (usuario_id, establecimiento_id, rol)
                VALUES ($1, $2, 'propietario');
            `;
            await client.query(assignRoleQuery, [propietarioId, nuevoEstablecimiento.id]);
            await client.query('COMMIT');
            res.status(201).json({
                message: 'Establecimiento creado exitosamente.',
                establecimiento: nuevoEstablecimiento
            });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Error al crear un nuevo establecimiento:', error);
            res.status(500).json({ message: 'Error interno del servidor. No se pudo crear el establecimiento.' });
        } finally {
            client.release();
        }
    });

    // --- Rutas de Gesti�n de Rodeos ---
    app.post('/api/establecimientos/:establecimientoId/rodeos', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId } = req.params;
        const { nombre, descripcion } = req.body;
        if (!nombre) {
            return res.status(400).json({ message: 'El nombre del rodeo es obligatorio.' });
        }
        try {
            const newRodeoQuery = `
                INSERT INTO rodeos (establecimiento_id, nombre, descripcion)
                VALUES ($1, $2, $3)
                RETURNING *;
            `;
            const result = await pool.query(newRodeoQuery, [establecimientoId, nombre, descripcion]);
            res.status(201).json({
                message: 'Rodeo creado exitosamente.',
                rodeo: result.rows[0]
            });
        } catch (error) {
            console.error('Error al crear un nuevo rodeo:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/rodeos', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId } = req.params;
        try {
            const rodeosQuery = 'SELECT * FROM rodeos WHERE establecimiento_id = $1 ORDER BY nombre ASC;';
            const result = await pool.query(rodeosQuery, [establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener rodeos:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });
    
    // --- Rutas de Gesti�n de Vacas ---
    app.post('/api/establecimientos/:establecimientoId/vacas', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId } = req.params;
        const { caravana_senasa, caravana_interna, nombre, raza, fecha_nacimiento, estado_actual, estado_reproductivo, rodeo_id, madre_id, padre_nombre } = req.body;
        
        if (!caravana_interna || !estado_actual || !rodeo_id) {
            return res.status(400).json({ message: 'Caravana Interna, Estado Actual y Rodeo son obligatorios.' });
        }

        try {
            const newVacaQuery = `
                INSERT INTO vacas (establecimiento_id, caravana_senasa, caravana_interna, nombre, raza, fecha_nacimiento, estado_actual, estado_reproductivo, rodeo_id, madre_id, padre_nombre)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING *;
            `;
            const result = await pool.query(newVacaQuery, [
                establecimientoId, caravana_senasa, caravana_interna, nombre, raza, fecha_nacimiento, estado_actual, estado_reproductivo, rodeo_id, madre_id, padre_nombre
            ]);
            res.status(201).json({
                message: 'Vaca creada exitosamente.',
                vaca: result.rows[0]
            });
        } catch (error) {
            if (error.code === '23505') { // Unique violation
                return res.status(409).json({ message: 'Ya existe una vaca con la misma caravana SENASA o Interna en este establecimiento.' });
            }
            console.error('Error al crear una nueva vaca:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId } = req.params;
        try {
            const vacasQuery = 'SELECT * FROM vacas WHERE establecimiento_id = $1 AND activa = TRUE ORDER BY caravana_interna ASC;';
            const result = await pool.query(vacasQuery, [establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener vacas:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas/:vacaId', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            const vacaQuery = 'SELECT * FROM vacas WHERE id = $1 AND establecimiento_id = $2;';
            const result = await pool.query(vacaQuery, [vacaId, establecimientoId]);
            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Vaca no encontrada en este establecimiento.' });
            }
            res.status(200).json(result.rows[0]);
        } catch (error) {
            console.error('Error al obtener vaca por ID:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.put('/api/establecimientos/:establecimientoId/vacas/:vacaId', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        const { caravana_senasa, caravana_interna, nombre, raza, fecha_nacimiento, estado_actual, estado_reproductivo, rodeo_id, madre_id, padre_nombre, activa } = req.body;

        try {
            const updateVacaQuery = `
                UPDATE vacas
                SET caravana_senasa = $1, caravana_interna = $2, nombre = $3, raza = $4, fecha_nacimiento = $5, 
                    estado_actual = $6, estado_reproductivo = $7, rodeo_id = $8, madre_id = $9, padre_nombre = $10, activa = $11
                WHERE id = $12 AND establecimiento_id = $13
                RETURNING *;
            `;
            const result = await pool.query(updateVacaQuery, [
                caravana_senasa, caravana_interna, nombre, raza, fecha_nacimiento, estado_actual, estado_reproductivo, rodeo_id, madre_id, padre_nombre, activa, vacaId, establecimientoId
            ]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Vaca no encontrada o no pertenece a este establecimiento.' });
            }
            res.status(200).json({
                message: 'Vaca actualizada exitosamente.',
                vaca: result.rows[0]
            });
        } catch (error) {
            if (error.code === '23505') { // Unique violation
                return res.status(409).json({ message: 'Ya existe otra vaca con la misma caravana SENASA o Interna en este establecimiento.' });
            }
            console.error('Error al actualizar vaca:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.delete('/api/establecimientos/:establecimientoId/vacas/:vacaId', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            // Se recomienda una "eliminaci�n l�gica" (marcar como inactiva) en lugar de f�sica
            const deleteVacaQuery = 'UPDATE vacas SET activa = FALSE WHERE id = $1 AND establecimiento_id = $2 RETURNING *;';
            const result = await pool.query(deleteVacaQuery, [vacaId, establecimientoId]);
            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Vaca no encontrada o no pertenece a este establecimiento.' });
            }
            res.status(200).json({ message: 'Vaca marcada como inactiva exitosamente.' });
        } catch (error) {
            console.error('Error al eliminar vaca:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    // --- Rutas de Historiales ---
    app.post('/api/establecimientos/:establecimientoId/vacas/:vacaId/salud', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        const { fecha_evento, tipo_evento, descripcion, costo, observaciones } = req.body;
        if (!fecha_evento || !tipo_evento || !descripcion) {
            return res.status(400).json({ message: 'Fecha, tipo de evento y descripci�n son obligatorios para el registro de salud.' });
        }
        try {
            const insertSaludQuery = `
                INSERT INTO registros_salud (vaca_id, establecimiento_id, fecha_evento, tipo_evento, descripcion, costo, observaciones)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING *;
            `;
            const result = await pool.query(insertSaludQuery, [vacaId, establecimientoId, fecha_evento, tipo_evento, descripcion, costo, observaciones]);
            res.status(201).json({
                message: 'Registro de salud creado exitosamente.',
                registro: result.rows[0]
            });
        } catch (error) {
            console.error('Error al crear registro de salud:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas/:vacaId/salud', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            const saludQuery = 'SELECT * FROM registros_salud WHERE vaca_id = $1 AND establecimiento_id = $2 ORDER BY fecha_evento DESC;';
            const result = await pool.query(saludQuery, [vacaId, establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener registros de salud:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.post('/api/establecimientos/:establecimientoId/vacas/:vacaId/reproduccion', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        const { fecha_evento, fecha_es_aproximada, tipo_evento, detalle, inseminador, cr�a_id_oficial } = req.body;
        if (!fecha_evento || !tipo_evento) {
            return res.status(400).json({ message: 'Fecha del evento y tipo de evento son obligatorios para el registro de reproducci�n.' });
        }
        try {
            const insertReproduccionQuery = `
                INSERT INTO registros_reproduccion (vaca_id, establecimiento_id, fecha_evento, fecha_es_aproximada, tipo_evento, detalle, inseminador, cr�a_id_oficial)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *;
            `;
            const result = await pool.query(insertReproduccionQuery, [vacaId, establecimientoId, fecha_evento, fecha_es_aproximada, tipo_evento, detalle, inseminador, cr�a_id_oficial]);
            res.status(201).json({
                message: 'Registro de reproducci�n creado exitosamente.',
                registro: result.rows[0]
            });
        } catch (error) {
            console.error('Error al crear registro de reproducci�n:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas/:vacaId/reproduccion', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            const reproduccionQuery = 'SELECT * FROM registros_reproduccion WHERE vaca_id = $1 AND establecimiento_id = $2 ORDER BY fecha_evento DESC;';
            const result = await pool.query(reproduccionQuery, [vacaId, establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener registros de reproducci�n:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.post('/api/establecimientos/:establecimientoId/vacas/:vacaId/produccion', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        const { fecha_registro, litros_dia, calidad_grasa, calidad_proteina } = req.body;
        if (!fecha_registro || litros_dia === undefined || litros_dia === null) {
            return res.status(400).json({ message: 'Fecha de registro y litros/d�a son obligatorios para el registro de producci�n.' });
        }
        try {
            const insertProduccionQuery = `
                INSERT INTO registros_produccion (vaca_id, establecimiento_id, fecha_registro, litros_dia, calidad_grasa, calidad_proteina)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *;
            `;
            const result = await pool.query(insertProduccionQuery, [vacaId, establecimientoId, fecha_registro, litros_dia, calidad_grasa, calidad_proteina]);
            res.status(201).json({
                message: 'Registro de producci�n creado exitosamente.',
                registro: result.rows[0]
            });
        } catch (error) {
            console.error('Error al crear registro de producci�n:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas/:vacaId/produccion', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            const produccionQuery = 'SELECT * FROM registros_produccion WHERE vaca_id = $1 AND establecimiento_id = $2 ORDER BY fecha_registro DESC;';
            const result = await pool.query(produccionQuery, [vacaId, establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener registros de producci�n:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });
    
    // Ruta para subir fotos de vacas (ya implementada)
    app.post('/api/establecimientos/:establecimientoId/vacas/:vacaId/fotos', authenticateToken, authorizeEstablecimiento, upload.single('file'), async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        const { descripcion } = req.body;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ message: 'No se proporcion� ning�n archivo de imagen.' });
        }

        const url_foto = `/uploads/${file.filename}`; 

        try {
            const insertPhotoQuery = `
                INSERT INTO fotos_vacas (vaca_id, establecimiento_id, url_foto, descripcion)
                VALUES ($1, $2, $3, $4)
                RETURNING *;
            `;
            const result = await pool.query(insertPhotoQuery, [vacaId, establecimientoId, url_foto, descripcion]);
            
            res.status(201).json({
                message: 'Foto subida y registrada exitosamente.',
                foto: result.rows[0]
            });

        } catch (error) {
            console.error('Error al subir y registrar la foto:', error);
            res.status(500).json({ message: 'Error interno del servidor al procesar la foto.' });
        }
    });

    app.get('/api/establecimientos/:establecimientoId/vacas/:vacaId/fotos', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId, vacaId } = req.params;
        try {
            const fotosQuery = 'SELECT * FROM fotos_vacas WHERE vaca_id = $1 AND establecimiento_id = $2 ORDER BY fecha_subida DESC;';
            const result = await pool.query(fotosQuery, [vacaId, establecimientoId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener fotos de vaca:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    // --- Ruta de Alertas ---
    app.get('/api/establecimientos/:establecimientoId/alertas', authenticateToken, authorizeEstablecimiento, async (req, res) => {
        const { establecimientoId } = req.params;
        try {
            // Implementaci�n simplificada de alertas:
            // Por ahora, generaremos alertas de "Parto Pr�ximo" para vacas pre�adas
            // cuya fecha de parto estimada (si se calcula) est� en los pr�ximos 45 d�as.
            // Para un sistema real, esto implicar�a l�gica m�s compleja y quiz�s una tabla de alertas dedicada.

            const pre�adasQuery = `
                SELECT v.id, v.caravana_interna, v.nombre, r.fecha_evento as fecha_reproduccion
                FROM vacas v
                JOIN registros_reproduccion r ON v.id = r.vaca_id
                WHERE v.establecimiento_id = $1
                AND v.estado_reproductivo = 'Pre�ada'
                AND r.tipo_evento = 'Palpaci�n' -- O el evento que confirme la pre�ez
                ORDER BY r.fecha_evento DESC;
            `;
            const result = await pool.query(pre�adasQuery, [establecimientoId]);
            
            const alertas = [];
            const hoy = new Date();
            const cuarentaYCincoDias = new Date();
            cuarentaYCincoDias.setDate(hoy.getDate() + 45);

            result.rows.forEach(vaca => {
                // Suponiendo una gestaci�n de 280 d�as desde la palpaci�n/inseminaci�n
                const fechaReproduccion = new Date(vaca.fecha_reproduccion);
                const fechaPartoEstimada = new Date(fechaReproduccion);
                fechaPartoEstimada.setDate(fechaPartaEstimada.getDate() + 280); // 280 d�as de gestaci�n

                if (fechaPartoEstimada >= hoy && fechaPartoEstimada <= cuarentaYCincoDias) {
                    alertas.push({
                        tipo: 'Parto Pr�ximo',
                        mensaje: `Parto estimado para la vaca ${vaca.nombre || vaca.caravana_interna} el ${fechaPartoEstimada.toLocaleDateString('es-AR')}.`,
                        vaca_id: vaca.id,
                        fecha_alerta: new Date().toISOString().split('T')[0]
                    });
                }
            });

            // Podr�as a�adir otras alertas aqu� (ej: vacas con tratamientos pendientes, etc.)

            res.status(200).json(alertas);
        } catch (error) {
            console.error('Error al obtener alertas:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    // --- RUTA DE ADMINISTRACI�N (ya implementada) ---
    app.get('/api/admin/establecimientos', authenticateToken, authorizeAdmin, async (req, res) => {
        try {
            const getEstablecimientosQuery = `
                SELECT e.id, e.nombre, e.numero_oficial, u.email as propietario_email 
                FROM establecimientos e
                JOIN usuarios u ON e.propietario_id = u.id
                ORDER BY e.id ASC;
            `;
            const result = await pool.query(getEstablecimientosQuery);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error al obtener los establecimientos:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    });

    // Encendemos el servidor.
    app.listen(PORT, () => {
        console.log(`Servidor escuchando en el puerto ${PORT}`);
    });
}

startServer();