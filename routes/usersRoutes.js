const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/users');

// Generate JWT tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId, role: 'user' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  
  const refreshToken = jwt.sign(
    { id: userId, role: 'user' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  
  return { accessToken, refreshToken };
};

// @route   POST /api/users/signup
// @desc    Register a new user
// @access  Public
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, type } = req.body;
    
    // Validation
    if (!username || !email || !password || !type) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields'
      });
    }
    
    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }
    
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must contain uppercase, lowercase, number, and special character'
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }
    
    // Create user (encryption key will be set later in profile)
    const user = await User.create({
      username,
      email,
      password,
      type
    });
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          type: user.type,
          role: user.role
        },
        accessToken,
        refreshToken
      }
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
      error: error.message
    });
  }
});

// @route   POST /api/users/login
// @desc    Login user
// @access  Public
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }
    
    // Find user and include password field
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been deactivated. Please contact admin.'
      });
    }
    
    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          type: user.type,
          role: user.role
        },
        accessToken,
        refreshToken
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: error.message
    });
  }
});

// Middleware
const { verifyToken } = require('../middleware/auth');

// @route   GET /api/users/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+encryptionKey');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    let decryptedKey = null;
    
    // Decrypt the encryption key if it exists
    if (user.encryptionKey) {
      try {
        const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
        const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
        const encryptedKeyBuffer = Buffer.from(user.encryptionKey, 'hex');
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
        let decrypted = decipher.update(encryptedKeyBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        decryptedKey = decrypted.toString('hex');
      } catch (decryptError) {
        console.error('Decryption error:', decryptError);
      }
    }
    
    res.status(200).json({
      success: true,
      data: {
        id: user._id,
        username: user.username,
        email: user.email,
        type: user.type,
        role: user.role,
        hasEncryptionKey: !!user.encryptionKey,
        encryptionKeySet: user.encryptionKey ? true : false,
        encryptionKey: decryptedKey,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// @route   PUT /api/users/profile/encryption-key
// @desc    Set or update user encryption key
// @access  Private
router.put('/profile/encryption-key', verifyToken, async (req, res) => {
  try {
    const { encryptionKey } = req.body;
    
    if (!encryptionKey) {
      return res.status(400).json({
        success: false,
        message: 'Encryption key is required'
      });
    }
    
    // Validate encryption key format (should be 64 hex characters for 32 bytes)
    if (!/^[a-fA-F0-9]{64}$/.test(encryptionKey)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid encryption key format. Must be 64 hexadecimal characters.'
      });
    }
    
    const user = await User.findById(req.user.id).select('+encryptionKey');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Encrypt the user's encryption key with master key and IV
    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
    const userKeyBuffer = Buffer.from(encryptionKey, 'hex');
    
    const cipher = crypto.createCipheriv('aes-256-cbc', masterKey, iv);
    let encryptedKey = cipher.update(userKeyBuffer);
    encryptedKey = Buffer.concat([encryptedKey, cipher.final()]);
    
    user.encryptionKey = encryptedKey.toString('hex');
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Encryption key updated successfully',
      data: {
        encryptionKeySet: true
      }
    });
  } catch (error) {
    console.error('Update encryption key error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// @route   POST /api/users/profile/generate-key
// @desc    Generate a new encryption key for user
// @access  Private
router.post('/profile/generate-key', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+encryptionKey');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Generate new random 32-byte key
    const newUserKey = crypto.randomBytes(32);
    
    // Encrypt with master key and IV
    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
    
    const cipher = crypto.createCipheriv('aes-256-cbc', masterKey, iv);
    let encryptedKey = cipher.update(newUserKey);
    encryptedKey = Buffer.concat([encryptedKey, cipher.final()]);
    
    user.encryptionKey = encryptedKey.toString('hex');
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'New encryption key generated successfully',
      data: {
        generatedKey: newUserKey.toString('hex'),
        note: 'Save this key securely. You will need it for file encryption/decryption.'
      }
    });
  } catch (error) {
    console.error('Generate key error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});


module.exports = router;


// Encrypted Search Routes
const encryptedSearch = require('../utils/encryptedSearch');
const File = require('../models/files');

// @route   POST /api/users/search/files
// @desc    Search files using encrypted indexing with boolean queries
// @access  Private
router.post('/search/files', verifyToken, async (req, res) => {
  try {
    const { query, searchIn } = req.body;
    
    if (!query || !query.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    // Get user's encryption key
    const user = await User.findById(req.user.id).select('+encryptionKey');
    
    if (!user || !user.encryptionKey) {
      return res.status(400).json({
        success: false,
        message: 'Encryption key not set. Please generate an encryption key first.'
      });
    }

    // Decrypt user's encryption key
    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
    const encryptedKeyBuffer = Buffer.from(user.encryptionKey, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
    let decrypted = decipher.update(encryptedKeyBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const userKey = decrypted;

    // Parse the boolean query
    const parsedQuery = encryptedSearch.parseQuery(query);

    // Determine which files to search
    let fileFilter = {};
    if (searchIn === 'received') {
      fileFilter = { recipientId: req.user.id };
    } else if (searchIn === 'uploaded') {
      fileFilter = { senderId: req.user.id };
    } else {
      // Search both
      fileFilter = {
        $or: [
          { senderId: req.user.id },
          { recipientId: req.user.id }
        ]
      };
    }

    // Get files with encrypted index
    const files = await File.find(fileFilter)
      .select('+encryptedIndex')
      .populate('senderId', 'username email type')
      .populate('recipientId', 'username email type');

    // Search through encrypted indexes
    const matchedFiles = files.filter(file => {
      if (!file.encryptedIndex || file.encryptedIndex.length === 0) {
        // Fallback: create index on the fly if not exists
        file.encryptedIndex = encryptedSearch.createEncryptedIndex(
          file.originalFileName,
          userKey
        );
      }
      
      return encryptedSearch.searchIndex(
        file.encryptedIndex,
        parsedQuery,
        userKey
      );
    });

    // Format results
    const results = matchedFiles.map(file => ({
      id: file._id,
      originalFileName: file.originalFileName,
      fileSize: file.fileSize,
      mimeType: file.mimeType,
      sender: file.senderId ? {
        username: file.senderId.username,
        email: file.senderId.email,
        type: file.senderId.type
      } : null,
      recipient: file.recipientId ? {
        username: file.recipientId.username,
        email: file.recipientId.email,
        type: file.recipientId.type
      } : { email: file.recipientEmail },
      downloadRequestStatus: file.downloadRequestStatus,
      uploadedAt: file.uploadedAt,
      downloadRequestedAt: file.downloadRequestedAt,
      approvedAt: file.approvedAt
    }));

    res.status(200).json({
      success: true,
      query: query,
      parsedQuery: parsedQuery,
      count: results.length,
      data: results
    });

  } catch (error) {
    console.error('Search files error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search files',
      error: error.message
    });
  }
});
