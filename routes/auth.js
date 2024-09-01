import express from 'express';
import { Admin } from '../models/Admin.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const router = express.Router();

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
        const token = jwt.sign({ username: admin.username, role: 'admin' }, process.env.Admin_Key, { expiresIn: '1h' });
        res.json({ login: true, role: 'admin', token });
    } else {
        // Handle other roles
    }
});

router.get('/total', async (req, res) => {
    try {
        const totalAdmins = await Admin.countDocuments({});
        res.json({ totalAdmins });
    } catch (error) {
        console.error('Error fetching admin count:', error);
        res.status(500).json({ message: 'Server error while fetching admin count' });
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

    jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Forbidden: Invalid token" });
        }

        req.username = decoded.username;
        req.role = decoded.role;
        next();
    });
};

export { router as AdminRouter, verifyAdmin };
