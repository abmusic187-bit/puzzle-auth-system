const express = require('express');
const serverless = require('serverless-http');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const svgCaptcha = require('svg-captcha');

const app = express();
app.use(express.json());

// 1. Schema
const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
}));

// 2. DB Connection (Using Environment Variable for Security)
const connectDB = async () => {
    if (mongoose.connection.readyState >= 1) return;
    await mongoose.connect(process.env.MONGODB_URI);
};

// Store captchas in memory (Note: In serverless, this clears often)
let captchaStore = {};

// 3. Routes
const router = express.Router();

router.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create({ size: 6, noise: 2 });
    const id = Math.random().toString(36).substring(2, 10);
    captchaStore[id] = captcha.text.toLowerCase();
    res.type('svg').set('x-captcha-id', id).send(captcha.data);
});

router.post('/register', async (req, res) => {
    await connectDB();
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ email, password: hashedPassword });
        res.json({ message: "Success! Please login." });
    } catch (e) { res.status(400).json({ error: "Email taken." }); }
});

router.post('/login', async (req, res) => {
    await connectDB();
    const { email, password, captchaId, captchaAnswer } = req.body;
    if (captchaStore[captchaId] !== captchaAnswer?.toLowerCase()) {
        return res.status(403).json({ error: "Captcha Failed" });
    }
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ email: user.email }, "SUPER_SECRET", { expiresIn: '1h' });
        return res.json({ token });
    }
    res.status(401).json({ error: "Invalid login" });
});

app.use('/.netlify/functions/api', router);
module.exports.handler = serverless(app);
