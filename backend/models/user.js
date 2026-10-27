// models/user.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_I = 10;
const TOKEN_EXPIRA_EN = '1d';

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true,  //creamos la condicion de que sea unico dentro de la base de datos (mongo)
        match: [/^\S+@\S+\.\S+$/, 'El email no tiene un formato valido']
    },
    password: {
        type: String,
        required: true,
        minlength: 6 //para poder crear una validacion mas facil de la contraseña original antes de la encriptacion
    },
    firstname: {
        type: String,
        trim: true,
        maxlength: 100
    },
    lastname: {
        type: String,
        trim: true,
        maxlength: 100
    },
    token: {
        type: String
    }
});

// El hash y el token no deben salir en las respuestas de la API
userSchema.set('toJSON', {
    transform: function (doc, ret) {
        delete ret.password;
        delete ret.token;
        delete ret.__v;
        return ret;
    }
});

// Encriptar la contrasena antes de guardar el usuario.
// La validacion del esquema (minlength) corre antes de este hook, sobre el texto plano.
userSchema.pre('save', function (next) {
    const user = this;

    if (!user.isModified('password')) return next(); //Solo para reencriptar si sì se modificó, si no dejar el mismo hash

    bcrypt.genSalt(SALT_I, function (err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function (err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

// Metodo para comparar contrasenas en el Login
userSchema.methods.comparepassword = function (candidatePassword, cb) {
    if (!candidatePassword || !this.password) return cb(null, false);

    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

// Generar Token JWT al iniciar sesion
userSchema.methods.generateToken = function (cb) {
    const user = this;

    if (!config.SECRET) return cb(new Error('Falta configurar SECRET'));

    let token;
    try { //Mejor usar un try catch que un callback
        token = jwt.sign(
            { _id: user._id.toHexString() }, //Se utiliza un objeto para buena practica, no solo como texto plano
            config.SECRET,
            { expiresIn: TOKEN_EXPIRA_EN }
        );
    } catch (err) {
        return cb(err);
    }

    user.token = token;
    user.save(function (err, savedUser) {
        if (err) return cb(err);
        cb(null, savedUser);
    });
};

// Metodo estatico para validar un usuario mediante su Token
userSchema.statics.findByToken = function (token, cb) {
    const User = this;

    // Sin token no hay usuario. Si se omite esta validacion, Mongoose descarta
    // los campos undefined y la consulta termina siendo findOne({}), que
    // devuelve al primer usuario de la coleccion.
    if (!token) return cb(null, null);

    jwt.verify(token, config.SECRET, function (err, decoded) {
        // Token invalido o vencido: no es un error del servidor, simplemente no hay usuario
        if (err || !decoded || !decoded._id) return cb(null, null);

        User.findOne({ _id: decoded._id, token: token }, function (err, user) { //Debe coincidir el ID del token guardado, asi un token viejo ya no sirve
            if (err) return cb(err);
            cb(null, user);
        });
    });
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = function (token, cb) {
    const user = this;

    user.updateOne({ $unset: { token: 1 } }, function (err) {
        if (err) return cb(err);

        // Reflejar el cambio tambien en el documento que ya esta en memoria
        user.token = undefined;
        cb(null, user);
    });
};

const User = mongoose.model('User', userSchema);

module.exports = User;
