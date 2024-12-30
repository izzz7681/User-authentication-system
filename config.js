const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/login', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Error connecting to MongoDB:', err.message);
});

const loginSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const collection = mongoose.model('users', loginSchema);

module.exports = collection;
