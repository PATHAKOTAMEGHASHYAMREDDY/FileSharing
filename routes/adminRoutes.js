const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const Admin = require("../models/admin");

// Generate JWT tokens for admin
const generateTokens = (adminId) => {
  const accessToken = jwt.sign(
    { id: adminId, role: "admin" },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  const refreshToken = jwt.sign(
    { id: adminId, role: "admin" },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  return { accessToken, refreshToken };
};

// @route   POST /api/admin/signup
// @desc    Register a new admin
// @access  Public (should be protected in production)
router.post("/signup", async (req, res) => {
  try {
    const { username, email, password, organization } = req.body;

    // Validation
    if (!username || !email || !password || !organization) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required fields",
      });
    }

    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long",
      });
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must contain uppercase, lowercase, number, and special character",
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({
      $or: [{ email }, { username }],
    });
    if (existingAdmin) {
      return res.status(400).json({
        success: false,
        message: "Admin with this email or username already exists",
      });
    }

    // Create admin
    const admin = await Admin.create({
      username,
      email,
      password,
      organization,
    });

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(admin._id);

    res.status(201).json({
      success: true,
      message: "Admin registered successfully",
      data: {
        admin: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          organization: admin.organization,
          role: admin.role,
        },
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Admin signup error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during registration",
      error: error.message,
    });
  }
});

// @route   POST /api/admin/login
// @desc    Login admin
// @access  Public
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide email and password",
      });
    }

    // Find admin and include password field
    const admin = await Admin.findOne({ email }).select("+password");

    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if admin is active
    if (!admin.isActive) {
      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Please contact support.",
      });
    }

    // Verify password
    const isPasswordValid = await admin.comparePassword(password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Update last login
    admin.lastLogin = Date.now();
    await admin.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(admin._id);

    res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        admin: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          organization: admin.organization,
          role: admin.role,
        },
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during login",
      error: error.message,
    });
  }
});

// @route   GET /api/admin/health
// @desc    Admin health check
// @access  Public
router.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Admin routes are working",
  });
});

module.exports = router;

// Middleware
const { verifyAdminToken } = require("../middleware/auth");

// @route   GET /api/admin/profile
// @desc    Get admin profile
// @access  Private (Admin only)
router.get("/profile", verifyAdminToken, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id);

    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    res.status(200).json({
      success: true,
      data: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        organization: admin.organization,
        role: admin.role,
        createdAt: admin.createdAt,
        lastLogin: admin.lastLogin,
      },
    });
  } catch (error) {
    console.error("Get admin profile error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
});

const File = require("../models/files");
const User = require("../models/users");
const AuditLog = require("../models/auditLog");

// Create audit log helper
const createAuditLog = async (
  actor,
  actorModel,
  actorEmail,
  action,
  details,
  targetFile = null,
  req = null
) => {
  await AuditLog.create({
    actor,
    actorModel,
    actorEmail,
    action,
    targetFile,
    details,
    ipAddress: req?.ip || req?.connection?.remoteAddress,
    userAgent: req?.headers["user-agent"],
  });
};

// @route   GET /api/admin/files/download-requests
// @desc    Get all pending download requests from recipients
// @access  Private (Admin only)
router.get("/files/download-requests", verifyAdminToken, async (req, res) => {
  try {
    const pendingRequests = await File.find({
      downloadRequestStatus: "pending",
    })
      .populate("senderId", "username email type")
      .populate("recipientId", "username email type")
      .sort({ downloadRequestedAt: -1 });

    res.status(200).json({
      success: true,
      count: pendingRequests.length,
      data: pendingRequests.map((f) => ({
        id: f._id,
        originalFileName: f.originalFileName,
        fileSize: f.fileSize,
        mimeType: f.mimeType,
        sender: {
          id: f.senderId._id,
          username: f.senderId.username,
          email: f.senderId.email,
          type: f.senderId.type,
        },
        recipient: {
          id: f.recipientId?._id,
          email: f.recipientEmail,
          username: f.recipientId?.username || "Not registered",
          type: f.recipientId?.type || "N/A",
        },
        uploadedAt: f.uploadedAt,
        downloadRequestedAt: f.downloadRequestedAt,
      })),
    });
  } catch (error) {
    console.error("Get download requests error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch download requests",
      error: error.message,
    });
  }
});

// @route   GET /api/admin/files/all
// @desc    Get all files with filters
// @access  Private (Admin only)
router.get("/files/all", verifyAdminToken, async (req, res) => {
  try {
    const { downloadRequestStatus } = req.query;
    const filter = downloadRequestStatus ? { downloadRequestStatus } : {};

    const files = await File.find(filter)
      .populate("senderId", "username email type")
      .populate("recipientId", "username email type")
      .populate("approvedBy", "username email")
      .sort({ uploadedAt: -1 });

    res.status(200).json({
      success: true,
      count: files.length,
      data: files.map((f) => ({
        id: f._id,
        originalFileName: f.originalFileName,
        fileSize: f.fileSize,
        mimeType: f.mimeType,
        sender: {
          username: f.senderId.username,
          email: f.senderId.email,
          type: f.senderId.type,
        },
        recipient: {
          email: f.recipientEmail,
          username: f.recipientId?.username || "Not registered",
          type: f.recipientId?.type || "N/A",
        },
        uploadStatus: f.uploadStatus,
        downloadRequestStatus: f.downloadRequestStatus,
        uploadedAt: f.uploadedAt,
        downloadRequestedAt: f.downloadRequestedAt,
        approvedAt: f.approvedAt,
        approvedBy: f.approvedBy
          ? {
              username: f.approvedBy.username,
              email: f.approvedBy.email,
            }
          : null,
        rejectionReason: f.rejectionReason,
      })),
    });
  } catch (error) {
    console.error("Get all files error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch files",
      error: error.message,
    });
  }
});

// @route   PUT /api/admin/files/approve-download/:fileId
// @desc    Approve download request from recipient
// @access  Private (Admin only)
router.put(
  "/files/approve-download/:fileId",
  verifyAdminToken,
  async (req, res) => {
    try {
      const file = await File.findById(req.params.fileId)
        .populate("senderId", "username email")
        .populate("recipientId", "username email");

      if (!file) {
        return res.status(404).json({
          success: false,
          message: "File not found",
        });
      }

      if (file.downloadRequestStatus !== "pending") {
        return res.status(400).json({
          success: false,
          message: `Download request is ${file.downloadRequestStatus}. Only pending requests can be approved.`,
        });
      }

      file.downloadRequestStatus = "approved";
      file.approvedBy = req.admin.id;
      file.approvedAt = Date.now();
      await file.save();

      // Create audit log
      await createAuditLog(
        req.admin.id,
        "Admin",
        req.admin.email,
        "approve",
        `Approved download request for file "${file.originalFileName}" from ${file.senderEmail} to ${file.recipientEmail}`,
        file._id,
        req
      );

      res.status(200).json({
        success: true,
        message:
          "Download request approved. Recipient can now download the file.",
        data: {
          fileId: file._id,
          originalFileName: file.originalFileName,
          downloadRequestStatus: file.downloadRequestStatus,
          approvedAt: file.approvedAt,
        },
      });
    } catch (error) {
      console.error("Approve download error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to approve download",
        error: error.message,
      });
    }
  }
);

// @route   PUT /api/admin/files/reject-download/:fileId
// @desc    Reject download request from recipient
// @access  Private (Admin only)
router.put(
  "/files/reject-download/:fileId",
  verifyAdminToken,
  async (req, res) => {
    try {
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason is required",
        });
      }

      const file = await File.findById(req.params.fileId)
        .populate("senderId", "username email")
        .populate("recipientId", "username email");

      if (!file) {
        return res.status(404).json({
          success: false,
          message: "File not found",
        });
      }

      if (file.downloadRequestStatus !== "pending") {
        return res.status(400).json({
          success: false,
          message: `Download request is ${file.downloadRequestStatus}. Only pending requests can be rejected.`,
        });
      }

      file.downloadRequestStatus = "rejected";
      file.approvedBy = req.admin.id;
      file.rejectionReason = reason;
      await file.save();

      // Create audit log
      await createAuditLog(
        req.admin.id,
        "Admin",
        req.admin.email,
        "reject",
        `Rejected download request for file "${file.originalFileName}" from ${file.senderEmail} to ${file.recipientEmail}. Reason: ${reason}`,
        file._id,
        req
      );

      res.status(200).json({
        success: true,
        message: "Download request rejected",
        data: {
          fileId: file._id,
          originalFileName: file.originalFileName,
          downloadRequestStatus: file.downloadRequestStatus,
          rejectionReason: file.rejectionReason,
        },
      });
    } catch (error) {
      console.error("Reject download error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to reject download",
        error: error.message,
      });
    }
  }
);

// @route   GET /api/admin/audit-logs
// @desc    Get audit logs with filters
// @access  Private (Admin only)
router.get("/audit-logs", verifyAdminToken, async (req, res) => {
  try {
    const { action, actorEmail, limit = 50 } = req.query;

    const filter = {};
    if (action) filter.action = action;
    if (actorEmail) filter.actorEmail = actorEmail;

    const logs = await AuditLog.find(filter)
      .populate("actor", "username email")
      .populate("targetFile", "originalFileName")
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    res.status(200).json({
      success: true,
      count: logs.length,
      data: logs.map((log) => ({
        id: log._id,
        actor: {
          email: log.actorEmail,
          username: log.actor?.username,
        },
        actorModel: log.actorModel,
        action: log.action,
        targetFile: log.targetFile?.originalFileName,
        details: log.details,
        ipAddress: log.ipAddress,
        timestamp: log.timestamp,
      })),
    });
  } catch (error) {
    console.error("Get audit logs error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch audit logs",
      error: error.message,
    });
  }
});

// @route   GET /api/admin/users
// @desc    Get all users
// @access  Private (Admin only)
router.get("/users", verifyAdminToken, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: users.length,
      data: users.map((u) => ({
        id: u._id,
        username: u.username,
        email: u.email,
        type: u.type,
        isActive: u.isActive,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin,
      })),
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch users",
      error: error.message,
    });
  }
});

// @route   PUT /api/admin/users/:userId/toggle-status
// @desc    Activate or deactivate user
// @access  Private (Admin only)
router.put(
  "/users/:userId/toggle-status",
  verifyAdminToken,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      user.isActive = !user.isActive;
      await user.save();

      res.status(200).json({
        success: true,
        message: `User ${
          user.isActive ? "activated" : "deactivated"
        } successfully`,
        data: {
          userId: user._id,
          username: user.username,
          isActive: user.isActive,
        },
      });
    } catch (error) {
      console.error("Toggle user status error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to toggle user status",
        error: error.message,
      });
    }
  }
);


// Encrypted Search for Admin
const encryptedSearch = require('../utils/encryptedSearch');
const crypto = require('crypto');

// @route   POST /api/admin/search/files
// @desc    Search all files using encrypted indexing (admin needs user keys)
// @access  Private (Admin only)
router.post('/search/files', verifyAdminToken, async (req, res) => {
  try {
    const { query } = req.body;
    
    if (!query || !query.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    // Parse the boolean query
    const parsedQuery = encryptedSearch.parseQuery(query);

    // Get all files with their encrypted indexes and sender info
    const files = await File.find({})
      .select('+encryptedIndex')
      .populate({
        path: 'senderId',
        select: '+encryptionKey username email type'
      })
      .populate('recipientId', 'username email type')
      .populate('approvedBy', 'username email')
      .sort({ uploadedAt: -1 });

    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');

    // Search through encrypted indexes
    const matchedFiles = [];
    
    for (const file of files) {
      try {
        // Get sender's encryption key
        if (!file.senderId || !file.senderId.encryptionKey) {
          continue;
        }

        // Decrypt sender's encryption key
        const encryptedKeyBuffer = Buffer.from(file.senderId.encryptionKey, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
        let decrypted = decipher.update(encryptedKeyBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        const userKey = decrypted;

        // Create index if not exists
        if (!file.encryptedIndex || file.encryptedIndex.length === 0) {
          file.encryptedIndex = encryptedSearch.createEncryptedIndex(
            file.originalFileName,
            userKey
          );
        }

        // Search the encrypted index
        const matches = encryptedSearch.searchIndex(
          file.encryptedIndex,
          parsedQuery,
          userKey
        );

        if (matches) {
          matchedFiles.push(file);
        }
      } catch (error) {
        // Skip files with decryption errors
        console.error(`Error searching file ${file._id}:`, error.message);
        continue;
      }
    }

    // Format results
    const results = matchedFiles.map(file => ({
      id: file._id,
      originalFileName: file.originalFileName,
      fileSize: file.fileSize,
      mimeType: file.mimeType,
      sender: {
        username: file.senderId.username,
        email: file.senderId.email,
        type: file.senderId.type
      },
      recipient: {
        email: file.recipientEmail,
        username: file.recipientId?.username || 'Not registered',
        type: file.recipientId?.type || 'N/A'
      },
      uploadStatus: file.uploadStatus,
      downloadRequestStatus: file.downloadRequestStatus,
      uploadedAt: file.uploadedAt,
      downloadRequestedAt: file.downloadRequestedAt,
      approvedAt: file.approvedAt,
      approvedBy: file.approvedBy ? {
        username: file.approvedBy.username,
        email: file.approvedBy.email
      } : null,
      rejectionReason: file.rejectionReason
    }));

    res.status(200).json({
      success: true,
      query: query,
      parsedQuery: parsedQuery,
      count: results.length,
      data: results
    });

  } catch (error) {
    console.error('Admin search files error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search files',
      error: error.message
    });
  }
});

// @route   GET /api/admin/search/users
// @desc    Search users by username or email
// @access  Private (Admin only)
router.get('/search/users', verifyAdminToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query || !query.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    const searchRegex = new RegExp(query, 'i');
    
    const users = await User.find({
      $or: [
        { username: searchRegex },
        { email: searchRegex }
      ]
    }).select('-password').sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      query: query,
      count: users.length,
      data: users.map(u => ({
        id: u._id,
        username: u.username,
        email: u.email,
        type: u.type,
        isActive: u.isActive,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin
      }))
    });

  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search users',
      error: error.message
    });
  }
});
