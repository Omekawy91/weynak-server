require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const cors = require("cors");
const asyncHandler = require("express-async-handler");
const { User, Meeting, Participant, Movement } = require("./model");

const app = express();
const port = process.env.PORT || 8900;

// Middleware
app.use(express.json());
app.use(cors()); // السماح بالاتصالات من أي دومين

// الاتصال بقاعدة البيانات MongoDB


mongoose.connect("mongodb://localhost:27017/weynak")
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("Database connection error:", err));

// إعداد nodemailer
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// دالة لإنشاء التوكن
const generateToken = (user) => {
    return jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// ميدل وير للتحقق من التوكن
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Access Denied!" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ message: "Invalid Token" });
    }
};

//  تسجيل مستخدم جديد
app.post("/register", asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "All fields are required!" });

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "Email already registered!" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.json({ message: "User registered successfully!" });
}));

//  تسجيل الدخول
app.post("/login", asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields are required!" });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: "Invalid email or password" });

    const token = generateToken(user);
    res.json({ token });
}));

//  إرسال OTP لإعادة تعيين كلمة المرور
app.post("/forgot-password", asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required!" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const user = await User.findOneAndUpdate({ email }, { otp, otp_expires_at: Date.now() + 15 * 60 * 1000 }, { new: true });
    if (!user) return res.status(404).json({ message: "Email not found!" });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset Code",
        text: `Your password reset code is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) return res.status(500).json({ message: "Error sending email!" });
        res.json({ message: "OTP sent successfully!" });
    });
}));

// إعادة تعيين كلمة المرور باستخدام OTP
app.post("/reset-password", asyncHandler(async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) return res.status(400).json({ message: "All fields are required!" });

    const user = await User.findOne({ email, otp });
    if (!user) return res.status(400).json({ message: "Invalid OTP!" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null;
    await user.save();

    res.json({ message: "Password reset successfully!" });
}));

// تشغيل السيرفر
const server = app.listen(port, () => {
    console.log(` Server running at http://localhost:${port}`);
});

// التعامل مع أخطاء البورت
server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
        console.error(` Port ${port} is already in use`);
        process.exit(1);
    } else {
        console.error(" Server error:", err);
    }
});

