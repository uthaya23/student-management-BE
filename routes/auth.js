import express from 'express';
import { Admin } from '../models/Admin.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const router = express.Router();

// Hard-coded secret key (only for development/testing)
const SECRET_KEY = 'your-very-strong-secret-key';

router.post('/login', async (req, res) => {
    const { username, password, role } = req.body;

    if (role === 'admin') {
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(404).json({ message: "Admin not registered" });
        }
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ message: "Wrong password" });
        }
        // Use hard-coded secret key for signing the token
        const token = jwt.sign({ username: admin.username, role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ login: true, role: 'admin', token });
    } else {
        // Handle other roles
    }
});

const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(' ')[1]; // Get token from "Bearer <token>"

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    // Use hard-coded secret key for verifying the token
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Forbidden: Invalid token" });
        }

        req.username = decoded.username;
        req.role = decoded.role;
        next();
    });
};

export { router as AdminRouter, verifyAdmin };
