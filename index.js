const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const users = [];
const secretKey = 'your_secret_key'; // Nên lưu trữ trong biến môi trường

// Utility function to generate a mock token
function generateToken(user) {
    return jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
}

// Middleware để xác thực token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // Nếu không có token

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403); // Token không hợp lệ
        req.user = users.find(u => u.id === user.id); // Đính kèm thông tin người dùng vào request
        next(); // Token hợp lệ, tiếp tục xử lý request
    });
}

// API đăng ký
app.post('/api/user/register', async (req, res) => {
    const { fullName, email, phone, gender, dob, address, password } = req.body;

    if (!fullName || !email || !phone || !gender || !dob || !address || !password) {
        return res.status(400).json({
            status: 400,
            message: "Tất cả các trường đều là bắt buộc.",
            data: null
        });
    }

    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(400).json({
            status: 400,
            message: "Email này đã được đăng ký.",
            data: null
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: users.length + 1,
        fullName,
        email,
        phone,
        gender,
        dob,
        address,
        password: hashedPassword,
        roleId: 3,
    };

    users.push(newUser);

    res.status(201).json({
        status: 201,
        message: "Đăng ký thành công.",
        data: {
            id: newUser.id,
            fullName: newUser.fullName,
            email: newUser.email,
            phone: newUser.phone,
            gender: newUser.gender,
            dob: newUser.dob,
            address: newUser.address,
            roleId: newUser.roleId,
        }
    });
});

// API đăng nhập
app.get('/api/user/login', async (req, res) => {
    const { email, password } = req.query;

    if (!email || !password) {
        return res.status(400).json({
            status: 400,
            message: "Email và mật khẩu là bắt buộc.",
            data: null
        });
    }

    const user = users.find(user => user.email === email);
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({
            status: 401,
            message: "Email hoặc mật khẩu không hợp lệ.",
            data: null
        });
    }

    const token = generateToken(user); // Tạo token mới khi đăng nhập

    res.status(200).json({
        status: 200,
        message: "Đăng nhập thành công.",
        data: token
    });
});

// API lấy thông tin người dùng
app.get('/api/user/get-user', authenticateToken, (req, res) => {
    const user = req.user; // Lấy thông tin người dùng từ request
    res.status(200).json({
        status: 200,
        message: "Lấy thông tin người dùng thành công.",
        data: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            phone: user.phone,
            gender: user.gender,
            dob: user.dob,
            address: user.address,
            roleId: user.roleId
        }
    });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`App listening at http://localhost:${PORT}`);
});
