const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;

const app = express();
app.use(bodyParser.json());
app.use(cors());

const secretKey = 'your_secret_key'; // Nên lưu trữ trong biến môi trường

// Utility function to generate a mock token
function generateToken(user) {
    return jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
}

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, async (err, user) => {
        if (err) return res.sendStatus(403);

        const usersData = await readData();
        req.user = usersData.users.find(u => u.id === user.id);
        next();
    });
}

// Helper function to read data from data.json
async function readData() {
    const data = await fs.readFile('./data.json', 'utf-8');
    return JSON.parse(data);
}

// Helper function to write data to data.json
async function writeData(data) {
    await fs.writeFile('./data.json', JSON.stringify(data, null, 2));
}

// API to register a user
app.post('/api/user/register', async (req, res) => {
    const { fullName, email, phone, gender, dob, address, password } = req.body;

    if (!fullName || !email || !phone || !gender || !dob || !address || !password) {
        return res.status(400).json({
            status: 400,
            message: "All fields are required.",
            data: null
        });
    }

    const usersData = await readData();
    const existingUser = usersData.users.find(user => user.email === email);

    if (existingUser) {
        return res.status(400).json({
            status: 400,
            message: "This email is already registered.",
            data: null
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: usersData.users.length + 1,
        fullName,
        email,
        phone,
        gender,
        dob,
        address,
        password: hashedPassword,
        roleId: 3,
    };

    usersData.users.push(newUser);
    await writeData(usersData);

    res.status(201).json({
        status: 201,
        message: "User registered successfully.",
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

// API to login a user
app.get('/api/user/login', async (req, res) => {
    const { email, password } = req.query;

    if (!email || !password) {
        return res.status(400).json({
            status: 400,
            message: "Email and password are required.",
            data: null
        });
    }

    const usersData = await readData();
    const user = usersData.users.find(user => user.email === email);

    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({
            status: 401,
            message: "Invalid email or password.",
            data: null
        });
    }

    const token = generateToken(user);

    res.status(200).json({
        status: 200,
        message: "Login successful.",
        data: token
    });
});

// API to get user info
app.get('/api/user/get-user', authenticateToken, (req, res) => {
    const user = req.user;

    if (!user) {
        return res.status(404).json({
            status: 404,
            message: "User not found.",
            data: null
        });
    }

    res.status(200).json({
        status: 200,
        message: "User info retrieved successfully.",
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
