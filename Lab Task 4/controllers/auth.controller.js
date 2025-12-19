const User = require('../models/user.model');
const jwt = require('jsonwebtoken');

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET || 'your_secret_key', { expiresIn: '7d' });
};

exports.register = async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).render('register-new', { 
                layout: 'navbar-layout',
                title: 'Register',
                message: 'All fields are required',
                user: req.session.user || null
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).render('register-new', { 
                layout: 'navbar-layout',
                title: 'Register',
                message: 'Passwords do not match',
                user: req.session.user || null
            });
        }

        if (password.length < 6) {
            return res.status(400).render('register-new', { 
                layout: 'navbar-layout',
                title: 'Register',
                message: 'Password must be at least 6 characters',
                user: req.session.user || null
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).render('register-new', { 
                layout: 'navbar-layout',
                title: 'Register',
                message: 'Email already registered',
                user: req.session.user || null
            });
        }

        const user = await User.create({ name, email, password });
        const token = generateToken(user._id);

        res.cookie('token', token, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
        req.flash('success', `Welcome ${name}! Your account has been created successfully.`);
        res.status(201).redirect('/');
    } catch (error) {
        res.status(500).render('register-new', { 
            layout: 'navbar-layout',
            title: 'Register',
            message: error.message || 'Registration failed',
            user: req.session.user || null
        });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).render('login-new', { 
                layout: 'navbar-layout',
                title: 'Login',
                message: 'Email and password are required',
                user: req.session.user || null
            });
        }

        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).render('login-new', { 
                layout: 'navbar-layout',
                title: 'Login',
                message: 'Invalid email or password',
                user: req.session.user || null
            });
        }

        const token = generateToken(user._id);
        res.cookie('token', token, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true });
        
        req.flash('success', `Welcome back, ${user.name}!`);
        if (user.role === 'admin') {
            return res.redirect('/admin');
        }
        res.redirect('/');
    } catch (error) {
        res.status(500).render('login-new', { 
            layout: 'navbar-layout',
            title: 'Login',
            message: error.message || 'Login failed',
            user: req.session.user || null
        });
    }
};

exports.logout = (req, res) => {
    res.clearCookie('token');
    req.flash('success', 'You have been logged out successfully.');
    res.redirect('/');
};
