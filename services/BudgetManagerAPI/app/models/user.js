const mongoose = require('mongoose'),
    bcrypt = require('bcrypt');

const Schema = mongoose.Schema({
    username: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    clients: [{}]
});

Schema.pre('save', async function (next) {
    const user = this;
    if (this.isModified('password') || this.isNew) {
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(user.password, salt);
        user.password = hash;
        next();
    } else {
        return next();
    }
});

Schema.methods.comparePassword = async function (password, callback) {
    let matches = await bcrypt.compare(password, this.password);
    callback(null, matches);
};

mongoose.model('User', Schema);