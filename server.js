require("dotenv").config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); 
const { spawn } = require("child_process");
const { SerialPort, ReadlineParser } = require("serialport");
const fetch = require('node-fetch'); 
const QRCode = require('qrcode');

// --- Import your Mongoose Models ---
const User = require('./models/User');
const Product = require('./models/Product');
const Shipment = require('./models/Shipment'); // <-- ADD THIS LINE

// --- Import your blockchain instance ---
const blockchain = require('./blockchain');


const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_here';
// --- Helper Functions for AI & Text Processing ---
function getCaptionFromPython(imagePath) {
    return new Promise((resolve, reject) => {
        const pythonProcess = spawn("python3", [path.join(__dirname, "caption.py"), imagePath]);
        let result = "";
        pythonProcess.stdout.on("data", (data) => { result += data.toString(); });
        pythonProcess.stderr.on("data", (data) => { console.error(`Python error: ${data}`); });
        pythonProcess.on("close", (code) => {
            if (code === 0) {
                try {
                    const jsonData = JSON.parse(result);
                    resolve(jsonData.caption); 
                } catch (e) {
                    console.error("Python script output was not valid JSON:", result);
                    reject("Failed to parse JSON from Python script.");
                }
            } else {
                reject("Python script failed");
            }
        });
    });
}

// ✅ NEW SMART AI FUNCTION to get the core product name
function extractProductType(caption) {
    const productKeywords = ["shoes", "glasses", "bag", "watch", "shirt", "pants", "jacket", "hat", "dress", "bottle", "can", "box"];
    const lowerCaseCaption = caption.toLowerCase();
    
    for (const word of productKeywords) {
        if (lowerCaseCaption.includes(word)) {
            // Capitalize the first letter for display
            return word.charAt(0).toUpperCase() + word.slice(1);
        }
    }
    return "Unknown Product"; // Fallback if no keyword is found
}

async function extractBrandFromCaption(caption) {
    console.log("Asking AI to extract brand from:", caption);
    try {
        const response = await fetch("https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.HF_TOKEN}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                inputs: `From the text "${caption}", what is the brand name? Respond with only the brand name and nothing else. If there is no brand, respond with 'N/A'.`,
                parameters: { max_new_tokens: 10, return_full_text: false }
            }),
        });
        if (!response.ok) throw new Error(`Hugging Face API error: ${response.statusText}`);

        const result = await response.json();
        if (result && result[0] && result[0].generated_text) {
            let brand = result[0].generated_text.trim().replace(/["'.]/g, '');
            if (brand.toLowerCase() !== 'n/a' && brand.length > 1) {
                console.log("AI extracted brand:", brand);
                return brand;
            }
        }
    } catch (error) {
        console.error("Failed to extract brand:", error);
    }
    return null;
}
  
// --- Middleware ---
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // For parsing application/json bodies
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// --- Serve Static Files ---
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Multer Configuration for Image Uploads ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
             fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only images (jpeg, jpg, png, gif) are allowed!'));
    }
});

// --- AI Image Analysis Route ---
app.post("/api/analyze-image", upload.single("image"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No image uploaded" });
        }
        const caption = await getCaptionFromPython(req.file.path);
        
        // Use the new rule-based function for product name
        const productName = extractProductType(caption); 
        
        // Still use the AI for brand detection
        const brand = await extractBrandFromCaption(caption);
        
        console.log("Analysis Complete. Sending to frontend:", { caption, productName, brand });
        res.json({ caption, productName, brand });

    } catch (error) {
        console.error("Error analyzing image:", error);
        res.status(500).json({ error: "Failed to analyze image" });
    }
});
// --- JWT Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// --- Role Authorization Middleware ---
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied: Insufficient permissions' });
        }
        next();
    };
};

// --- Routes ---

// User Registration (Admin can register new users)
app.post('/admin/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { email, password, role } = req.body;
        if (!email || !password || !role) {
            return res.status(400).json({ message: 'Email, password, and role are required' });
        }
        if (!['admin', 'staff'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role specified. Must be "admin" or "staff".' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists' });
        }
        
        const user = new User({ email, password, role });
        await user.save();
        res.status(201).json({ message: 'User created successfully', user: { id: user._id, email: user.email, role: user.role } });
    } catch (err) {
        console.error('Admin User Creation Error:', err);
        res.status(500).json({ message: 'Server error during user creation', error: err.message });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Logged in successfully', token, role: user.role });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ message: 'Server error during login', error: err.message });
    }
});

// Get User Details (for the logged-in user)
app.get('/user-details', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user: { id: user._id, email: user.email, role: user.role } });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Failed to fetch user details' });
    }
});

// GET all users (Admin only)
app.get('/admin/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json(users);
    } catch (err) {
        console.error('Error fetching users for admin:', err);
        res.status(500).json({ message: 'Failed to fetch users', error: err.message });
    }
});

// GET single user by ID (Admin only)
app.get('/admin/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching single user for admin:', err);
        if (err.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        res.status(500).json({ message: 'Failed to retrieve user details', error: err.message });
    }
});

// UPDATE user (Admin only)
app.put('/admin/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const updateData = {};

        if (email) updateData.email = email;
        if (role) {
            if (!['admin', 'staff'].includes(role)) {
                return res.status(400).json({ message: 'Invalid role specified. Must be "admin" or "staff".' });
            }
            updateData.role = role;
        }
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(req.params.id, updateData, { new: true }).select('-password');
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User updated successfully', user: updatedUser });
    } catch (err) {
        console.error('Error updating user by admin:', err);
        if (err.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        res.status(500).json({ message: 'Failed to update user', error: err.message });
    }
});

// DELETE user (Admin only)
app.delete('/admin/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        if (req.user.id === req.params.id) {
            return res.status(403).json({ message: 'Admins cannot delete their own account.' });
        }

        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error('Error deleting user by admin:', err);
        if (err.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        res.status(500).json({ message: 'Failed to delete user', error: err.message });
    }
});

// Forgot Password Request (sends request to admin)
app.post('/forgot-password-request', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required for password reset request.' });
    }

    console.log(`FORGOT PASSWORD REQUEST: User with email "${email}" has requested a password reset.`);
    console.log('An admin will need to manually reset this user\'s password via the User Management dashboard.');

    res.status(200).json({ message: 'Password reset request sent to admin. Please contact an administrator.' });
});


// Add New Product - Now adds to MongoDB and Blockchain
app.post('/products', authenticateToken, authorizeRole(['admin']), (req, res, next) => {
    upload.single('productImage')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: `File upload error: ${err.message}` });
        } else if (err) {
            return res.status(500).json({ message: `An unexpected error occurred during file upload: ${err.message}` });
        }
        next();
    });
}, async (req, res) => {
    try {
        const { name, category, price, stock, description, manufacturer, manufacturedAt, sellingLocation, batchNo } = req.body;

        if (!name || !category || !price || !stock) {
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            return res.status(400).json({ message: 'Missing required product fields: name, category, price, stock' });
        }

        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        const newProduct = new Product({
            name, category, price: parseFloat(price), stock: parseInt(stock, 10),
            description: description || '', manufacturer: manufacturer || '',
            manufacturedAt: manufacturedAt ? new Date(manufacturedAt) : undefined,
            sellingLocation: sellingLocation || '', batchNo: batchNo || '',
            timestamp: new Date(), image: imagePath,
        });

        await newProduct.save();
       


        // **FIXED**: Changed addProduct to addTransaction
        blockchain.addTransaction({
            productId: newProduct._id.toString(),
            name, category, price: parseFloat(price), stock: parseInt(stock, 10),
            description, manufacturer, manufacturedAt, sellingLocation, batchNo,
            imageUrl: imagePath,
            savedAt: new Date().toISOString(),
            action: 'added'
        });
       const minedBlock = blockchain.minePendingTransactions();
if (minedBlock) {
  console.log("New block mined and added to blockchain!");
}
        
        res.status(201).json({ message: 'Product added successfully', product: newProduct });
    } catch (err) {
        console.error('Error adding product in route handler:', err);
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Failed to add product', error: err.message });
    }
});

// Get All Products (from MongoDB)
app.get('/products', authenticateToken, authorizeRole(['admin', 'staff']), async (req, res) => {
    try {
        const products = await Product.find({});
        res.json(products);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ message: 'Failed to fetch products', error: err.message });
    }
});

// Get Single Product by ID from MongoDB
app.get('/product/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
    } catch (err) {
        console.error('Error fetching product by ID:', err);
        if (err.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid product ID format' });
        }
        res.status(500).json({ message: 'Failed to retrieve product details', error: err.message });
    }
});
// --- [NEW] SHIPMENT ROUTES ---

// POST /shipments - Create a new shipment
app.post('/shipments', authenticateToken, authorizeRole(['admin', 'staff']), async (req, res) => {
    try {
        const { itemId, quantity, recipient, address } = req.body;

        if (!itemId || !quantity || !recipient || !address) {
            return res.status(400).json({ message: 'Missing required shipment fields.' });
        }

        // Find the product to get its name and category
        const product = await Product.findById(itemId);
        if (!product) {
            return res.status(404).json({ message: 'Product to be shipped not found.' });
        }

        const newShipment = new Shipment({
            itemId,
            itemName: product.name,
            itemCategory: product.category,
            quantity: parseInt(quantity, 10),
            recipient,
            address,
            status: 'Pending',
            history: [{ status: 'Pending', timestamp: new Date() }] // Initial history entry
        });

        await newShipment.save();
        res.status(201).json({ message: 'Shipment created successfully!', shipment: newShipment });

    } catch (err) {
        console.error('Error creating shipment:', err);
        res.status(500).json({ message: 'Server error while creating shipment.', error: err.message });
    }
});

// GET /shipments - Get all shipments
app.get('/shipments', authenticateToken, authorizeRole(['admin', 'staff']), async (req, res) => {
    try {
        const shipments = await Shipment.find({}).sort({ createdAt: -1 }); // Sort by newest first
        res.json(shipments);
    } catch (err) {
        console.error('Error fetching shipments:', err);
        res.status(500).json({ message: 'Failed to fetch shipments', error: err.message });
    }
});
// PATCH /shipments/:id/status - Update a shipment's status
app.patch('/shipments/:id/status', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { status } = req.body;
        
        if (!status) {
            return res.status(400).json({ message: 'New status is required.' });
        }

        const shipment = await Shipment.findById(req.params.id);
        if (!shipment) {
            return res.status(404).json({ message: 'Shipment not found.' });
        }

        // Update status and add a new record to its history
        shipment.status = status;
        shipment.history.push({
            status: status,
            timestamp: new Date()
        });

        await shipment.save();

        res.json({ message: `Shipment status updated to ${status}`, shipment });

    } catch (err) {
        console.error('Error updating shipment status:', err);
        res.status(500).json({ message: 'Server error while updating shipment status.', error: err.message });
    }
});

// DELETE /shipments/:id - Delete a shipment
app.delete('/shipments/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const shipment = await Shipment.findByIdAndDelete(req.params.id);
        if (!shipment) {
            return res.status(404).json({ message: 'Shipment not found.' });
        }
        res.json({ message: 'Shipment deleted successfully.' });
    } catch (err) {
        console.error('Error deleting shipment:', err);
        res.status(500).json({ message: 'Server error while deleting shipment.', error: err.message });
    }
});

// PATCH /shipments/:id/rfid - Assign an RFID tag and update status to "Processing"
app.patch('/shipments/:id/rfid', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { rfidTag } = req.body;
        if (!rfidTag) {
            return res.status(400).json({ message: 'RFID tag is required.' });
        }

        const shipment = await Shipment.findById(req.params.id);
        if (!shipment) {
            return res.status(404).json({ message: 'Shipment not found.' });
        }

        shipment.rfidTag = rfidTag;
        shipment.status = 'Processing';
        shipment.history.push({
            status: 'Processing',
            timestamp: new Date(),
            location: 'Warehouse' // Example location
        });

        await shipment.save();
        res.json({ message: `RFID ${rfidTag} assigned successfully.`, shipment });

    } catch (err) {
        console.error('Error assigning RFID:', err);
        res.status(500).json({ message: 'Server error while assigning RFID.', error: err.message });
    }
});
// Get Single Product by ID from Blockchain (Publicly Accessible)
app.get('/blockchain/product/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const productData = blockchain.findProductInBlockchain(productId);

        if (!productData) {
            return res.status(404).json({ message: 'Product not found in blockchain' });
        }
        res.json(productData);
    } catch (err) {
        console.error('Error fetching product from blockchain by ID:', err);
        res.status(500).json({ message: 'Failed to retrieve product details from blockchain', error: err.message });
    }
});

// Update Product
app.put('/product/:id', authenticateToken, authorizeRole(['admin']), (req, res, next) => {
    upload.single('productImage')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: `File upload error during update: ${err.message}` });
        } else if (err) {
            return res.status(500).json({ message: `An unexpected error occurred during file upload for update: ${err.message}` });
        }
        next();
    });
}, async (req, res) => {
    try {
        const productId = req.params.id;
        const { name, category, price, stock, description, manufacturer, manufacturedAt, sellingLocation, batchNo } = req.body;

        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        if (req.file) {
            if (product.image && fs.existsSync(path.join(__dirname, product.image))) {
                fs.unlinkSync(path.join(__dirname, product.image));
            }
            product.image = `/uploads/${req.file.filename}`;
        }

        product.name = name;
        product.category = category;
        product.price = parseFloat(price);
        product.stock = parseInt(stock, 10);
        product.description = description || '';
        product.manufacturer = manufacturer || '';
        product.manufacturedAt = manufacturedAt ? new Date(manufacturedAt) : undefined;
        product.sellingLocation = sellingLocation || '';
        product.batchNo = batchNo || '';

        await product.save();

        // **FIXED**: Changed addProduct to addTransaction
        blockchain.addTransaction({
            productId: product._id.toString(),
            name, category, price: parseFloat(price), stock: parseInt(stock, 10),
            description, manufacturer, manufacturedAt, sellingLocation, batchNo,
            imageUrl: product.image,
            savedAt: new Date().toISOString(),
            action: 'updated'
        });
        console.log('Product update transaction added to pending pool.');

        res.json({ message: 'Product updated successfully', product });
    } catch (err) {
        console.error('Error updating product in route handler:', err);
        if (req.file && fs.existsSync(path.join(__dirname, req.file.path))) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Failed to update product', error: err.message });
    }
});

// Delete Product
app.delete('/product/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        if (product.image && fs.existsSync(path.join(__dirname, product.image))) {
            fs.unlinkSync(path.join(__dirname, product.image));
        }

        // **FIXED**: Changed addProduct to addTransaction
        blockchain.addTransaction({
            productId: product._id.toString(),
            action: 'deleted',
            deletedAt: new Date().toISOString()
        });
        console.log('Product deletion transaction added to pending pool.');

        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ message: 'Failed to delete product', error: err.message });
    }
});

// Inventory Summary
app.get('/inventory-summary', authenticateToken, authorizeRole(['admin', 'staff']), async (req, res) => {
    try {
        const totalItems = await Product.aggregate([
            { $group: { _id: null, total: { $sum: "$stock" } } }
        ]);

        const totalCategories = await Product.distinct('category').length;
        const lowStock = await Product.countDocuments({ stock: { $lt: 10 } });

        res.json({
            totalItems: totalItems.length > 0 ? totalItems[0].total : 0,
            totalCategories: totalCategories,
            lowStock: lowStock
        });
    } catch (err) {
        console.error('Error fetching inventory summary:', err);
        res.status(500).json({ message: 'Error fetching inventory summary', error: err.message });
    }
});

// --- BLOCKCHAIN SPECIFIC ROUTES ---

// Get Blockchain (entire chain)
app.get('/blockchain', (req, res) => {
    res.json(blockchain.getChain());
});

// --- [NEW] ROUTE: Manually Mine Pending Transactions (Admin Only) ---
app.post('/mine-transactions', authenticateToken, authorizeRole(['admin']), (req, res) => {
    console.log('Attempting to mine a new block...');

    const newBlock = blockchain.minePendingTransactions();

    if (newBlock) {
        res.status(200).json({ 
            message: 'New block successfully mined!', 
            block: newBlock 
        });
    } else {
        res.status(400).json({ 
            message: 'No pending transactions to mine.' 
        });
    }
});
// --- RFID over USB Serial ---
const port = new SerialPort({ path: "/dev/cu.usbserial-0001", baudRate: 115200 }); // Windows: COM3, Linux/Mac: /dev/ttyUSB0
const parser = port.pipe(new ReadlineParser({ delimiter: "\n" }));

let latestRfid = null;
let waitingForAssignment = false;

// Listen for RFID scans from ESP32
parser.on("data", (data) => {
  const uid = data.trim();
  console.log("RFID scanned:", uid);

  if (waitingForAssignment) {
    latestRfid = uid;
    waitingForAssignment = false;
  }
});

// API to trigger RFID assignment
app.post("/api/rfid/assign", (req, res) => {
  console.log("Frontend requested RFID assignment...");
  waitingForAssignment = true;

  let checks = 0;
  const interval = setInterval(() => {
    if (!waitingForAssignment && latestRfid) {
      clearInterval(interval);
      res.json({ success: true, rfid: latestRfid });
      latestRfid = null; // reset after use
    }
    checks++;
    if (checks > 30) { // ~15s timeout
      clearInterval(interval);
      waitingForAssignment = false;
      res.json({ success: false, message: "Timeout: No RFID scanned" });
    }
  }, 500);
});


// --- MongoDB Connection and Server Start ---
mongoose.connect('mongodb://localhost:27017/fyp', {
    useNewUrlParser: true,
})
.then(() => {
    console.log('MongoDB connected to "fyp" database');
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
    createAdminUser();
})
.catch(err => console.error('MongoDB connection error:', err));

// --- Initial Admin User Creation ---
async function createAdminUser() {
    try {
        const adminExists = await User.findOne({ email: 'admin@example.com' });
        if (!adminExists) {
            const adminUser = new User({
                email: 'admin@example.com',
                password: '123456',
                role: 'admin'
            });
            await adminUser.save();
            console.log('Default admin user (admin@example.com) created.');
        } else {
            console.log('Admin user (admin@example.com) already exists.');
        }
    } catch (err) {
        console.error('Error creating default admin user:', err);
    }
}

// --- Global Error Handling Middleware ---
app.use((err, req, res, next) => {
    console.error('Global Error Handler:', err.stack);
    if (err.name === 'MulterError') {
        return res.status(400).json({ message: `File upload error: ${err.message}` });
    }
    res.status(500).json({ message: 'An unexpected server error occurred.' });
});