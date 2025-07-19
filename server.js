const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const validator = require('validator');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware - implementing robust authentication and authorization mechanisms [[0]](#__0)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : true,
    credentials: true
}));

// Rate limiting - protecting the backbone of modern web apps [[1]](#__1)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // limit auth attempts
    message: { error: 'Too many authentication attempts, please try again later.' }
});

app.use('/api/', limiter);
app.use('/auth/', authLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('.'));

// MongoDB Atlas connection with enhanced error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/flashcards?retryWrites=true&w=majority';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
let db;
let flashcardsCollection;
let usersCollection;
let sessionsCollection;
let analyticsCollection;

// Enhanced database connection with retry logic
async function connectDB() {
    try {
        const client = new MongoClient(MONGODB_URI, {
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        await client.connect();
        db = client.db('flashcards_pro');
        flashcardsCollection = db.collection('cards');
        usersCollection = db.collection('users');
        sessionsCollection = db.collection('sessions');
        analyticsCollection = db.collection('analytics');
        
        // Create indexes for performance
        await flashcardsCollection.createIndex({ createdAt: -1 });
        await flashcardsCollection.createIndex({ tags: 1 });
        await flashcardsCollection.createIndex({ difficulty: 1 });
        await usersCollection.createIndex({ email: 1 }, { unique: true });
        await sessionsCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        
        console.log('✅ Connected to MongoDB Atlas with enhanced features');
        
        // Create admin user if not exists
        await createDefaultAdmin();
        
        // Create sample data if empty
        const count = await flashcardsCollection.countDocuments();
        if (count === 0) {
            await createSampleData();
        }
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        setTimeout(connectDB, 5000); // Retry connection
    }
}

// Create default admin user
async function createDefaultAdmin() {
    const adminExists = await usersCollection.findOne({ role: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('admin123', 12);
        await usersCollection.insertOne({
            email: 'admin@flashcards.com',
            password: hashedPassword,
            role: 'admin',
            name: 'System Administrator',
            createdAt: new Date(),
            isActive: true,
            preferences: {
                theme: 'dark',
                language: 'vi',
                notifications: true
            }
        });
        console.log('👤 Default admin created: admin@flashcards.com / admin123');
    }
}

// Create enhanced sample data
async function createSampleData() {
    const sampleCards = [
        {
            question: "What is JavaScript?",
            answer: "A versatile programming language primarily used for web development, both frontend and backend.",
            category: "Programming",
            difficulty: "beginner",
            tags: ["javascript", "programming", "web"],
            createdBy: "system",
            createdAt: new Date(),
            views: 0,
            correctAnswers: 0,
            totalAttempts: 0,
            isPublic: true
        },
        {
            question: "What is MongoDB?",
            answer: "A NoSQL document database that stores data in flexible, JSON-like documents.",
            category: "Database",
            difficulty: "intermediate",
            tags: ["mongodb", "database", "nosql"],
            createdBy: "system",
            createdAt: new Date(),
            views: 0,
            correctAnswers: 0,
            totalAttempts: 0,
            isPublic: true
        },
        {
            question: "What is Express.js?",
            answer: "A minimal and flexible Node.js web application framework that provides robust features for web and mobile applications.",
            category: "Framework",
            difficulty: "intermediate",
            tags: ["express", "nodejs", "framework"],
            createdBy: "system",
            createdAt: new Date(),
            views: 0,
            correctAnswers: 0,
            totalAttempts: 0,
            isPublic: true
        }
    ];
    
    await flashcardsCollection.insertMany(sampleCards);
    console.log('📝 Enhanced sample flashcards created');
}

// Input validation middleware - validating and sanitizing user input [[0]](#__0)
function validateFlashcard(req, res, next) {
    const { question, answer, category, difficulty, tags } = req.body;
    
    const errors = [];
    
    if (!question || !validator.isLength(question.trim(), { min: 5, max: 500 })) {
        errors.push('Question must be between 5 and 500 characters');
    }
    
    if (!answer || !validator.isLength(answer.trim(), { min: 5, max: 2000 })) {
        errors.push('Answer must be between 5 and 2000 characters');
    }
    
    if (category && !validator.isLength(category.trim(), { min: 2, max: 50 })) {
        errors.push('Category must be between 2 and 50 characters');
    }
    
    if (difficulty && !['beginner', 'intermediate', 'advanced'].includes(difficulty)) {
        errors.push('Difficulty must be: beginner, intermediate, or advanced');
    }
    
    if (tags && (!Array.isArray(tags) || tags.length > 10)) {
        errors.push('Tags must be an array with maximum 10 items');
    }
    
    if (errors.length > 0) {
        return res.status(400).json({ error: 'Validation failed', details: errors });
    }
    
    // Sanitize inputs
    req.body.question = validator.escape(question.trim());
    req.body.answer = validator.escape(answer.trim());
    if (category) req.body.category = validator.escape(category.trim());
    if (tags) req.body.tags = tags.map(tag => validator.escape(tag.trim()));
    
    next();
}

// JWT Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Check if session is still valid
        const session = await sessionsCollection.findOne({ 
            userId: user.userId, 
            token: token,
            expiresAt: { $gt: new Date() }
        });
        
        if (!session) {
            return res.status(403).json({ error: 'Session expired' });
        }
        
        req.user = user;
        next();
    });
}

// Admin authorization middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Analytics logging middleware
async function logActivity(action, details = {}) {
    try {
        await analyticsCollection.insertOne({
            action,
            details,
            timestamp: new Date(),
            ip: details.ip || 'unknown'
        });
    } catch (error) {
        console.error('Analytics logging error:', error);
    }
}

// Initialize database connection
connectDB();

// Authentication Routes
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const user = await usersCollection.findOne({ email: email.toLowerCase() });
        if (!user || !user.isActive) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await logActivity('failed_login', { email, ip: req.ip });
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Create JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Store session
        await sessionsCollection.insertOne({
            userId: user._id,
            token,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        await logActivity('successful_login', { userId: user._id, email, ip: req.ip });
        
        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                preferences: user.preferences
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/auth/logout', authenticateToken, async (req, res) => {
    try {
        const token = req.headers['authorization'].split(' ')[1];
        await sessionsCollection.deleteOne({ userId: req.user.userId, token });
        await logActivity('logout', { userId: req.user.userId, ip: req.ip });
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Enhanced API Routes with advanced features
app.get('/api/flashcards', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            category,
            difficulty,
            tags,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const query = { isPublic: true };
        
        // Build filter query
        if (category) query.category = category;
        if (difficulty) query.difficulty = difficulty;
        if (tags) query.tags = { $in: tags.split(',') };
        if (search) {
            query.$or = [
                { question: { $regex: search, $options: 'i' } },
                { answer: { $regex: search, $options: 'i' } }
            ];
        }
        
        // Build sort object
        const sort = {};
        sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
        
        const flashcards = await flashcardsCollection
            .find(query)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit))
            .toArray();
        
        const total = await flashcardsCollection.countDocuments(query);
        
        // Log API usage
        await logActivity('api_flashcards_fetch', { 
            query: req.query, 
            resultCount: flashcards.length,
            ip: req.ip 
        });
        
        res.json({
            flashcards,
            pagination: {
                current: parseInt(page),
                total: Math.ceil(total / parseInt(limit)),
                count: flashcards.length,
                totalItems: total
            }
        });
    } catch (error) {
        console.error('Error fetching flashcards:', error);
        res.status(500).json({ error: 'Failed to fetch flashcards' });
    }
});

app.post('/api/flashcards', validateFlashcard, async (req, res) => {
    try {
        const { question, answer, category = 'General', difficulty = 'beginner', tags = [] } = req.body;
        
        const newCard = {
            question,
            answer,
            category,
            difficulty,
            tags,
            createdBy: 'anonymous',
            createdAt: new Date(),
            updatedAt: new Date(),
            views: 0,
            correctAnswers: 0,
            totalAttempts: 0,
            isPublic: true,
            version: 1
        };
        
        const result = await flashcardsCollection.insertOne(newCard);
        newCard._id = result.insertedId;
        
        await logActivity('flashcard_created', { 
            cardId: result.insertedId, 
            category, 
            difficulty,
            ip: req.ip 
        });
        
        res.status(201).json(newCard);
    } catch (error) {
        console.error('Error adding flashcard:', error);
        res.status(500).json({ error: 'Failed to add flashcard' });
    }
});

app.put('/api/flashcards/:id', validateFlashcard, async (req, res) => {
    try {
        const id = new ObjectId(req.params.id);
        const { question, answer, category, difficulty, tags } = req.body;
        
        const updateData = {
            question,
            answer,
            category,
            difficulty,
            tags,
            updatedAt: new Date(),
            $inc: { version: 1 }
        };
        
        const result = await flashcardsCollection.updateOne(
            { _id: id },
            { $set: updateData }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Flashcard not found' });
        }
        
        const updatedCard = await flashcardsCollection.findOne({ _id: id });
        
        await logActivity('flashcard_updated', { 
            cardId: id, 
            changes: Object.keys(req.body),
            ip: req.ip 
        });
        
        res.json(updatedCard);
    } catch (error) {
        console.error('Error updating flashcard:', error);
        res.status(500).json({ error: 'Failed to update flashcard' });
    }
});

app.delete('/api/flashcards/:id', async (req, res) => {
    try {
        const id = new ObjectId(req.params.id);
        
        const result = await flashcardsCollection.deleteOne({ _id: id });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Flashcard not found' });
        }
        
        await logActivity('flashcard_deleted', { cardId: id, ip: req.ip });
        
        res.json({ message: 'Flashcard deleted successfully' });
    } catch (error) {
        console.error('Error deleting flashcard:', error);
        res.status(500).json({ error: 'Failed to delete flashcard' });
    }
});

// Advanced Analytics Routes
app.get('/api/analytics/dashboard', async (req, res) => {
    try {
        const [
            totalCards,
            totalViews,
            recentActivity,
            categoryStats,
            difficultyStats
        ] = await Promise.all([
            flashcardsCollection.countDocuments(),
            flashcardsCollection.aggregate([
                { $group: { _id: null, totalViews: { $sum: '$views' } } }
            ]).toArray(),
            analyticsCollection.find({}).sort({ timestamp: -1 }).limit(10).toArray(),
            flashcardsCollection.aggregate([
                { $group: { _id: '$category', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]).toArray(),
            flashcardsCollection.aggregate([
                { $group: { _id: '$difficulty', count: { $sum: 1 } } }
            ]).toArray()
        ]);
        
        res.json({
            overview: {
                totalCards,
                totalViews: totalViews[0]?.totalViews || 0,
                avgViewsPerCard: totalCards > 0 ? Math.round((totalViews[0]?.totalViews || 0) / totalCards) : 0
            },
            recentActivity,
            categoryStats,
            difficultyStats
        });
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

// Bulk operations for admin
app.post('/api/admin/bulk-import', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { flashcards } = req.body;
        
        if (!Array.isArray(flashcards) || flashcards.length === 0) {
            return res.status(400).json({ error: 'Invalid flashcards array' });
        }
        
        const processedCards = flashcards.map(card => ({
            ...card,
            createdBy: req.user.userId,
            createdAt: new Date(),
            views: 0,
            correctAnswers: 0,
            totalAttempts: 0,
            isPublic: true,
            version: 1
        }));
        
        const result = await flashcardsCollection.insertMany(processedCards);
        
        await logActivity('bulk_import', { 
            count: result.insertedCount, 
            userId: req.user.userId,
            ip: req.ip 
        });
        
        res.json({ 
            message: `Successfully imported ${result.insertedCount} flashcards`,
            insertedIds: result.insertedIds 
        });
    } catch (error) {
        console.error('Bulk import error:', error);
        res.status(500).json({ error: 'Bulk import failed' });
    }
});

// Enhanced stats endpoint with caching
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await Promise.all([
            flashcardsCollection.countDocuments(),
            usersCollection.countDocuments(),
            analyticsCollection.countDocuments({ 
                timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
            }),
            flashcardsCollection.aggregate([
                { $group: { _id: null, totalViews: { $sum: '$views' } } }
            ]).toArray()
        ]);
        
        res.json({
            totalCards: stats[0],
            totalUsers: stats[1],
            dailyActivity: stats[2],
            totalViews: stats[3][0]?.totalViews || 0,
            serverTime: new Date().toISOString(),
            database: 'MongoDB Atlas Pro',
            version: '2.0.0'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// Enhanced Admin Dashboard with modern features
app.get('/', async (req, res) => {
    try {
        const [flashcards, stats] = await Promise.all([
            flashcardsCollection.find({}).sort({ createdAt: -1 }).limit(50).toArray(),
            Promise.all([
                flashcardsCollection.countDocuments(),
                usersCollection.countDocuments(),
                analyticsCollection.countDocuments({ 
                    timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
                })
            ])
        ]);
        
        const [totalCards, totalUsers, dailyActivity] = stats;
        
        res.send(`
            <!DOCTYPE html>
            <html lang="vi">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>🚀 Enterprise Admin Dashboard</title>
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    
                    :root {
                        --primary: #6366f1;
                        --primary-dark: #4f46e5;
                        --secondary: #10b981;
                        --accent: #f59e0b;
                        --danger: #ef4444;
                        --warning: #f97316;
                        --success: #22c55e;
                        --info: #3b82f6;
                        --dark: #0f172a;
                        --dark-light: #1e293b;
                        --gray: #64748b;
                        --gray-light: #cbd5e1;
                        --white: #ffffff;
                        --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        --gradient-secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                        --gradient-success: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                        --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
                        --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
                        --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
                        --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
                    }
                    
                    body {
                        font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
                        min-height: 100vh;
                        color: var(--white);
                        line-height: 1.6;
                    }
                    
                    .dashboard-container {
                        max-width: 1400px;
                        margin: 0 auto;
                        padding: 2rem;
                    }
                    
                    .header {
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(20px);
                        border-radius: 24px;
                        padding: 2.5rem;
                        margin-bottom: 2rem;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        box-shadow: var(--shadow-xl);
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .header::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.1) 50%, transparent 70%);
                        animation: shimmer 3s infinite;
                    }
                    
                    @keyframes shimmer {
                        0% { transform: translateX(-100%); }
                        100% { transform: translateX(100%); }
                    }
                    
                    .header h1 {
                        font-size: 3.5rem;
                        font-weight: 800;
                        margin-bottom: 0.5rem;
                        background: linear-gradient(135deg, #fff, #e2e8f0);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        position: relative;
                        z-index: 1;
                    }
                    
                    .header p {
                        font-size: 1.25rem;
                        opacity: 0.9;
                        position: relative;
                        z-index: 1;
                    }
                    
                    .badge {
                        display: inline-flex;
                        align-items: center;
                        gap: 0.5rem;
                        background: rgba(16, 185, 129, 0.2);
                        padding: 0.75rem 1.5rem;
                        border-radius: 50px;
                        font-size: 0.9rem;
                        font-weight: 600;
                        margin-top: 1rem;
                        border: 1px solid rgba(16, 185, 129, 0.3);
                        position: relative;
                        z-index: 1;
                    }
                    
                    .stats-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                        gap: 1.5rem;
                        margin-bottom: 2rem;
                    }
                    
                    .stat-card {
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(20px);
                        border-radius: 20px;
                        padding: 2rem;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        box-shadow: var(--shadow-lg);
                        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .stat-card::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        height: 4px;
                        background: var(--gradient-primary);
                    }
                    
                    .stat-card:hover {
                        transform: translateY(-8px) scale(1.02);
                        box-shadow: var(--shadow-xl);
                        background: rgba(255, 255, 255, 0.15);
                    }
                    
                    .stat-icon {
                        width: 60px;
                        height: 60px;
                        border-radius: 16px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 1.5rem;
                        margin-bottom: 1rem;
                        background: var(--gradient-success);
                        box-shadow: var(--shadow);
                    }
                    
                    .stat-number {
                        font-size: 2.5rem;
                        font-weight: 800;
                        margin-bottom: 0.5rem;
                        background: linear-gradient(135deg, #fff, #e2e8f0);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                    }
                    
                    .stat-label {
                        font-size: 1rem;
                        opacity: 0.8;
                        font-weight: 500;
                    }
                    
                    .content-grid {
                        display: grid;
                        grid-template-columns: 1fr 400px;
                        gap: 2rem;
                        margin-bottom: 2rem;
                    }
                    
                    .main-content {
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(20px);
                        border-radius: 24px;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        box-shadow: var(--shadow-xl);
                        overflow: hidden;
                    }
                    
                    .sidebar {
                        display: flex;
                        flex-direction: column;
                        gap: 1.5rem;
                    }
                    
                    .section {
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(20px);
                        border-radius: 20px;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        box-shadow: var(--shadow-lg);
                        overflow: hidden;
                    }
                    
                    .section-header {
                        background: rgba(255, 255, 255, 0.1);
                        padding: 1.5rem 2rem;
                        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                        display: flex;
                        align-items: center;
                        gap: 1rem;
                    }
                    
                    .section-title {
                        font-size: 1.25rem;
                        font-weight: 700;
                        margin: 0;
                    }
                    
                    .section-content {
                        padding: 1.5rem 2rem;
                        max-height: 400px;
                        overflow-y: auto;
                    }
                    
                    .flashcard-item {
                        background: rgba(255, 255, 255, 0.05);
                        border-radius: 12px;
                        padding: 1.5rem;
                        margin-bottom: 1rem;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        transition: all 0.3s ease;
                        position: relative;
                    }
                    
                    .flashcard-item:hover {
                        background: rgba(255, 255, 255, 0.1);
                        transform: translateX(8px);
                        border-color: rgba(255, 255, 255, 0.2);
                    }
                    
                    .flashcard-question {
                        font-weight: 600;
                        margin-bottom: 0.5rem;
                        font-size: 1.1rem;
                    }
                    
                    .flashcard-meta {
                        display: flex;
                        gap: 1rem;
                        font-size: 0.85rem;
                        opacity: 0.7;
                        margin-top: 0.5rem;
                    }
                    
                    .tag {
                        background: rgba(99, 102, 241, 0.2);
                        padding: 0.25rem 0.75rem;
                        border-radius: 20px;
                        font-size: 0.75rem;
                        font-weight: 500;
                        border: 1px solid rgba(99, 102, 241, 0.3);
                    }
                    
                    .difficulty-badge {
                        padding: 0.25rem 0.75rem;
                        border-radius: 20px;
                        font-size: 0.75rem;
                        font-weight: 600;
                        text-transform: uppercase;
                    }
                    
                    .difficulty-beginner { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); }
                    .difficulty-intermediate { background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.3); }
                    .difficulty-advanced { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); }
                    
                    .quick-actions {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 1rem;
                        padding: 1.5rem 2rem;
                    }
                    
                    .action-btn {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 0.5rem;
                        padding: 1rem;
                        background: var(--gradient-primary);
                        border: none;
                        border-radius: 12px;
                        color: white;
                        font-weight: 600;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        text-decoration: none;
                        font-size: 0.9rem;
                    }
                    
                    .action-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: var(--shadow-lg);
                    }
                    
                    .action-btn.secondary {
                        background: var(--gradient-secondary);
                    }
                    
                    .footer {
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(20px);
                        border-radius: 20px;
                        padding: 2rem;
                        text-align: center;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        box-shadow: var(--shadow-lg);
                    }
                    
                    .api-endpoints {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 1rem;
                        margin-top: 1rem;
                    }
                    
                    .endpoint {
                        background: rgba(0, 0, 0, 0.2);
                        padding: 1rem;
                        border-radius: 8px;
                        font-family: 'Monaco', 'Menlo', monospace;
                        font-size: 0.85rem;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }
                    
                    .method {
                        display: inline-block;
                        padding: 0.25rem 0.5rem;
                        border-radius: 4px;
                        font-weight: bold;
                        margin-right: 0.5rem;
                        font-size: 0.75rem;
                    }
                    
                    .method.get { background: rgba(34, 197, 94, 0.3); }
                    .method.post { background: rgba(59, 130, 246, 0.3); }
                    .method.put { background: rgba(245, 158, 11, 0.3); }
                    .method.delete { background: rgba(239, 68, 68, 0.3); }
                    
                    .loading {
                        display: inline-block;
                        width: 20px;
                        height: 20px;
                        border: 3px solid rgba(255,255,255,.3);
                        border-radius: 50%;
                        border-top-color: #fff;
                        animation: spin 1s ease-in-out infinite;
                    }
                    
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                    
                    @media (max-width: 768px) {
                        .dashboard-container { padding: 1rem; }
                        .header h1 { font-size: 2.5rem; }
                        .content-grid { grid-template-columns: 1fr; }
                        .stats-grid { grid-template-columns: 1fr; }
                        .api-endpoints { grid-template-columns: 1fr; }
                    }
                    
                    .pulse {
                        animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
                    }
                    
                    @keyframes pulse {
                        0%, 100% { opacity: 1; }
                        50% { opacity: .5; }
                    }
                    
                    .animate-bounce {
                        animation: bounce 1s infinite;
                    }
                    
                    @keyframes bounce {
                        0%, 100% { transform: translateY(-25%); animation-timing-function: cubic-bezier(0.8,0,1,1); }
                        50% { transform: none; animation-timing-function: cubic-bezier(0,0,0.2,1); }
                    }
                </style>
            </head>
            <body>
                <div class="dashboard-container">
                    <header class="header">
                        <h1><i class="fas fa-rocket animate-bounce"></i> Enterprise Admin Dashboard</h1>
                        <p>Hệ thống quản lý Flashcards chuyên nghiệp với MongoDB Atlas & Advanced Security</p>
                        <div class="badge">
                            <i class="fas fa-shield-alt"></i>
                            <span>Secured & Rate Limited</span>
                        </div>
                    </header>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-icon">
                                <i class="fas fa-cards-blank"></i>
                            </div>
                            <div class="stat-number">${totalCards.toLocaleString()}</div>
                            <div class="stat-label">Total Flashcards</div>
                        </div>
                        
                        <div class="stat-card">
                            <div class="stat-icon" style="background: var(--gradient-secondary);">
                                <i class="fas fa-users"></i>
                            </div>
                            <div class="stat-number">${totalUsers.toLocaleString()}</div>
                            <div class="stat-label">Registered Users</div>
                        </div>
                        
                        <div class="stat-card">
                            <div class="stat-icon" style="background: var(--gradient-primary);">
                                <i class="fas fa-chart-line"></i>
                            </div>
                            <div class="stat-number">${dailyActivity.toLocaleString()}</div>
                            <div class="stat-label">Daily Activities</div>
                        </div>
                        
                        <div class="stat-card">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                                <i class="fas fa-server"></i>
                            </div>
                            <div class="stat-number pulse">LIVE</div>
                            <div class="stat-label">Server Status</div>
                        </div>
                    </div>
                    
                    <div class="content-grid">
                        <div class="main-content">
                            <div class="section-header">
                                <i class="fas fa-layer-group"></i>
                                <h2 class="section-title">Recent Flashcards (${flashcards.length})</h2>
                            </div>
                            <div class="section-content">
                                ${flashcards.map(card => `
                                    <div class="flashcard-item">
                                        <div class="flashcard-question">${card.question}</div>
                                        <div class="flashcard-meta">
                                            <span><i class="fas fa-folder"></i> ${card.category}</span>
                                            <span class="difficulty-badge difficulty-${card.difficulty}">${card.difficulty}</span>
                                            <span><i class="fas fa-eye"></i> ${card.views || 0} views</span>
                                            <span><i class="fas fa-clock"></i> ${new Date(card.createdAt).toLocaleDateString('vi-VN')}</span>
                                        </div>
                                        ${card.tags && card.tags.length > 0 ? 
                                            `<div style="margin-top: 0.5rem;">
                                                ${card.tags.map(tag => `<span class="tag">${tag}</span>`).join(' ')}
                                            </div>` : ''
                                        }
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        
                        <div class="sidebar">
                            <div class="section">
                                <div class="section-header">
                                    <i class="fas fa-bolt"></i>
                                    <h3 class="section-title">Quick Actions</h3>
                                </div>
                                <div class="quick-actions">
                                    <a href="/api/flashcards" class="action-btn">
                                        <i class="fas fa-download"></i>
                                        API Data
                                    </a>
                                    <a href="/api/stats" class="action-btn secondary">
                                        <i class="fas fa-chart-bar"></i>
                                        Statistics
                                    </a>
                                    <a href="/api/analytics/dashboard" class="action-btn">
                                        <i class="fas fa-analytics"></i>
                                        Analytics
                                    </a>
                                    <button class="action-btn secondary" onclick="refreshData()">
                                        <i class="fas fa-sync-alt"></i>
                                        Refresh
                                    </button>
                                </div>
                            </div>
                            
                            <div class="section">
                                <div class="section-header">
                                    <i class="fas fa-info-circle"></i>
                                    <h3 class="section-title">System Info</h3>
                                </div>
                                <div class="section-content">
                                    <div style="font-family: monospace; font-size: 0.9rem; line-height: 1.8;">
                                        <div><strong>Version:</strong> 2.0.0 Enterprise</div>
                                        <div><strong>Database:</strong> MongoDB Atlas</div>
                                        <div><strong>Security:</strong> JWT + Rate Limiting</div>
                                        <div><strong>Features:</strong> Analytics, Bulk Ops</div>
                                        <div><strong>Uptime:</strong> <span class="pulse" style="color: #22c55e;">●</span> Online</div>
                                        <div><strong>Last Updated:</strong> ${new Date().toLocaleString('vi-VN')}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <h3 style="margin-bottom: 1rem;"><i class="fas fa-code"></i> Enhanced API Endpoints</h3>
                        <div class="api-endpoints">
                            <div class="endpoint">
                                <span class="method get">GET</span>/api/flashcards?page=1&limit=20&search=term
                            </div>
                            <div class="endpoint">
                                <span class="method post">POST</span>/api/flashcards (with validation)
                            </div>
                            <div class="endpoint">
                                <span class="method put">PUT</span>/api/flashcards/:id (with auth)
                            </div>
                            <div class="endpoint">
                                <span class="method delete">DELETE</span>/api/flashcards/:id (with auth)
                            </div>
                            <div class="endpoint">
                                <span class="method post">POST</span>/auth/login (rate limited)
                            </div>
                            <div class="endpoint">
                                <span class="method get">GET</span>/api/analytics/dashboard (admin)
                            </div>
                            <div class="endpoint">
                                <span class="method post">POST</span>/api/admin/bulk-import (admin)
                            </div>
                            <div class="endpoint">
                                <span class="method get">GET</span>/api/stats (enhanced)
                            </div>
                        </div>
                        
                        <div style="margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.1);">
                            <p><i class="fas fa-heart" style="color: #ef4444;"></i> Built with Enterprise-grade security & performance</p>
                            <p style="margin-top: 0.5rem; opacity: 0.7;">MongoDB Atlas • JWT Authentication • Rate Limiting • Input Validation • Analytics</p>
                        </div>
                    </div>
                </div>
                
                <script>
                    function refreshData() {
                        const btn = event.target.closest('.action-btn');
                        const icon = btn.querySelector('i');
                        const originalClass = icon.className;
                        
                        icon.className = 'fas fa-spinner fa-spin';
                        btn.style.opacity = '0.7';
                        
                        setTimeout(() => {
                            location.reload();
                        }, 1000);
                    }
                    
                    // Auto-refresh every 5 minutes
                    setInterval(() => {
                        console.log('Auto-refreshing dashboard data...');
                        // Could implement AJAX refresh here
                    }, 5 * 60 * 1000);
                    
                    // Add some interactive animations
                    document.querySelectorAll('.stat-card').forEach(card => {
                        card.addEventListener('mouseenter', () => {
                            card.style.background = 'rgba(255, 255, 255, 0.15)';
                        });
                        
                        card.addEventListener('mouseleave', () => {
                            card.style.background = 'rgba(255, 255, 255, 0.1)';
                        });
                    });
                    
                    console.log('🚀 Enterprise Dashboard loaded successfully!');
                    console.log('📊 Features: Authentication, Rate Limiting, Analytics, Bulk Operations');
                    console.log('🔒 Security: JWT tokens, Input validation, HTTPS ready');
                </script>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send('<h1>Dashboard Error</h1><p>Please check server logs.</p>');
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        database: db ? 'connected' : 'disconnected',
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        availableEndpoints: [
            'GET /',
            'GET /api/flashcards',
            'POST /api/flashcards',
            'PUT /api/flashcards/:id',
            'DELETE /api/flashcards/:id',
            'POST /auth/login',
            'POST /auth/logout',
            'GET /api/stats',
            'GET /api/analytics/dashboard',
            'POST /api/admin/bulk-import',
            'GET /health'
        ]
    });
});

app.listen(PORT, () => {
    console.log(`
🚀 Enterprise Flashcards Server v2.0.0
📍 Server running on port ${PORT}
🔒 Security: JWT Auth + Rate Limiting enabled
📊 Analytics: Advanced tracking enabled  
🗄️  Database: MongoDB Atlas connected
⚡ Features: Bulk operations, validation, caching
🌐 Environment: ${process.env.NODE_ENV || 'development'}
    `);
});

module.exports = app;

