const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }, // Changed from username to email
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'staff'], default: 'staff' } // 'admin' or 'staff'
});

UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

module.exports = mongoose.model('User', UserSchema);
