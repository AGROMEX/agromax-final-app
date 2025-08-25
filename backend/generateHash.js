    const bcrypt = require('bcryptjs');

    const passwordToHash = 'password123'; // ¡Cambia esta contraseña por la que quieras para tu usuario de prueba!
    const saltRounds = 10; // El mismo número de rondas que usas en tu server.js

    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(passwordToHash, salt, function(err, hash) {
            if (err) {
                console.error('Error al generar el hash:', err);
                return;
            }
            console.log('Contraseña original:', passwordToHash);
            console.log('Hash generado:', hash);
            console.log('\n¡Copia este hash y úsalo en tu consulta SQL para insertar el usuario!');
        });
    });
    