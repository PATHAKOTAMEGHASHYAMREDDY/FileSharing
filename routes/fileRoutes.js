const express = require('express');
const router = express.Router();
const multer = require('multer');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const User = require('../models/users');
const File = require('../models/files');
const AuditLog = require('../models/auditLog');
const { verifyToken } = require('../middleware/auth');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 2 // Max 2 files
  }
});

// Encryption function using user's key and universal IV
const encryptBuffer = (buffer, userKey) => {
  const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
  const key = Buffer.from(userKey, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

// Decryption function
const decryptBuffer = (encryptedBuffer, userKey) => {
  const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
  const key = Buffer.from(userKey, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
};

// Create audit log
const createAuditLog = async (actor, actorModel, actorEmail, action, details, targetFile = null, req = null) => {
  await AuditLog.create({
    actor,
    actorModel,
    actorEmail,
    action,
    targetFile,
    details,
    ipAddress: req?.ip || req?.connection?.remoteAddress,
    userAgent: req?.headers['user-agent']
  });
};

// @route   POST /api/files/upload
// @desc    Upload encrypted files (max 2) to share with another user
// @access  Private (User only)
router.post('/upload', verifyToken, upload.array('files', 2), async (req, res) => {
  try {
    const { recipientEmail } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please upload at least one file'
      });
    }
    
    if (files.length > 2) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 2 files allowed per upload'
      });
    }
    
    if (!recipientEmail) {
      return res.status(400).json({
        success: false,
        message: 'Recipient email is required'
      });
    }
    
    // Get sender details
    const sender = await User.findById(req.user.id).select('+encryptionKey');
    
    if (!sender) {
      return res.status(404).json({
        success: false,
        message: 'Sender not found'
      });
    }
    
    if (!sender.encryptionKey) {
      return res.status(400).json({
        success: false,
        message: 'Please set your encryption key first in your profile'
      });
    }
    
    // Check if recipient exists
    const recipient = await User.findOne({ email: recipientEmail });
    
    // Decrypt sender's encryption key
    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
    const encryptedKeyBuffer = Buffer.from(sender.encryptionKey, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
    let senderKey = decipher.update(encryptedKeyBuffer);
    senderKey = Buffer.concat([senderKey, decipher.final()]);
    const senderKeyHex = senderKey.toString('hex');
    
    const uploadedFiles = [];
    
    // Upload each file
    for (const file of files) {
      // Encrypt file with sender's key
      const encryptedBuffer = encryptBuffer(file.buffer, senderKeyHex);
      const encryptedFileName = `${Date.now()}_${file.originalname}.enc`;
      
      // Upload to Cloudinary
      const uploadPromise = new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            resource_type: 'raw',
            folder: 'secure_file_sharing',
            public_id: encryptedFileName
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        streamifier.createReadStream(encryptedBuffer).pipe(uploadStream);
      });
      
      const cloudinaryResult = await uploadPromise;
      
      // Create encrypted index for searchability
      const encryptedSearch = require('../utils/encryptedSearch');
      const encryptedIndex = encryptedSearch.createEncryptedIndex(
        file.originalname,
        senderKey
      );
      
      // Save file metadata to database
      const newFile = await File.create({
        fileName: encryptedFileName,
        originalFileName: file.originalname,
        fileUrl: cloudinaryResult.secure_url,
        fileSize: file.size,
        mimeType: file.mimetype,
        senderId: sender._id,
        senderEmail: sender.email,
        recipientEmail: recipientEmail,
        recipientId: recipient ? recipient._id : null,
        encryptedWithKey: sender.encryptionKey,
        encryptedIndex: encryptedIndex,
        uploadStatus: 'uploaded',
        downloadRequestStatus: 'not_requested'
      });
      
      uploadedFiles.push(newFile);
      
      // Create audit log
      await createAuditLog(
        sender._id,
        'User',
        sender.email,
        'upload',
        `Uploaded file "${file.originalname}" for ${recipientEmail}`,
        newFile._id,
        req
      );
    }
    
    res.status(201).json({
      success: true,
      message: `${uploadedFiles.length} file(s) uploaded successfully and shared with ${recipientEmail}.`,
      data: {
        files: uploadedFiles.map(f => ({
          id: f._id,
          originalFileName: f.originalFileName,
          recipientEmail: f.recipientEmail,
          uploadStatus: f.uploadStatus,
          downloadRequestStatus: f.downloadRequestStatus,
          uploadedAt: f.uploadedAt
        }))
      }
    });
    
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({
      success: false,
      message: 'File upload failed',
      error: error.message
    });
  }
});

// @route   GET /api/files/my-uploads
// @desc    Get files uploaded by current user
// @access  Private (User only)
router.get('/my-uploads', verifyToken, async (req, res) => {
  try {
    const files = await File.find({ senderId: req.user.id })
      .populate('recipientId', 'username email')
      .sort({ uploadedAt: -1 });
    
    res.status(200).json({
      success: true,
      count: files.length,
      data: files.map(f => ({
        id: f._id,
        originalFileName: f.originalFileName,
        recipientEmail: f.recipientEmail,
        recipientUsername: f.recipientId?.username || 'Not registered',
        uploadStatus: f.uploadStatus,
        downloadRequestStatus: f.downloadRequestStatus,
        uploadedAt: f.uploadedAt,
        approvedAt: f.approvedAt,
        rejectionReason: f.rejectionReason
      }))
    });
  } catch (error) {
    console.error('Get uploads error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch uploads',
      error: error.message
    });
  }
});

// @route   GET /api/files/received
// @desc    Get files received by current user
// @access  Private (User only)
router.get('/received', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    const files = await File.find({ recipientEmail: user.email })
      .populate('senderId', 'username email')
      .sort({ uploadedAt: -1 });
    
    res.status(200).json({
      success: true,
      count: files.length,
      data: files.map(f => ({
        id: f._id,
        originalFileName: f.originalFileName,
        senderUsername: f.senderId?.username,
        senderEmail: f.senderEmail,
        fileSize: f.fileSize,
        uploadedAt: f.uploadedAt,
        downloadRequestStatus: f.downloadRequestStatus,
        downloadRequestedAt: f.downloadRequestedAt,
        approvedAt: f.approvedAt,
        rejectionReason: f.rejectionReason,
        canRequestDownload: f.downloadRequestStatus === 'not_requested',
        canDownload: f.downloadRequestStatus === 'approved'
      }))
    });
  } catch (error) {
    console.error('Get received files error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch received files',
      error: error.message
    });
  }
});

// @route   POST /api/files/request-download/:fileId
// @desc    Request download permission from admin
// @access  Private (User only - Recipient)
router.post('/request-download/:fileId', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const file = await File.findById(req.params.fileId)
      .populate('senderId', 'username email');
    
    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }
    
    // Check if user is the recipient
    if (file.recipientEmail !== user.email) {
      return res.status(403).json({
        success: false,
        message: 'You are not authorized to request this file'
      });
    }
    
    // Check if already requested
    if (file.downloadRequestStatus === 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Download request already pending with admin'
      });
    }
    
    // Check if already approved
    if (file.downloadRequestStatus === 'approved') {
      return res.status(400).json({
        success: false,
        message: 'Download already approved. You can download the file now.'
      });
    }
    
    // Update status to pending
    file.downloadRequestStatus = 'pending';
    file.downloadRequestedAt = Date.now();
    await file.save();
    
    // Create audit log
    await createAuditLog(
      user._id,
      'User',
      user.email,
      'download',
      `Requested download permission for file "${file.originalFileName}" from ${file.senderEmail}`,
      file._id,
      req
    );
    
    res.status(200).json({
      success: true,
      message: 'Download request sent to admin for approval',
      data: {
        fileId: file._id,
        originalFileName: file.originalFileName,
        downloadRequestStatus: file.downloadRequestStatus,
        downloadRequestedAt: file.downloadRequestedAt
      }
    });
    
  } catch (error) {
    console.error('Request download error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to request download',
      error: error.message
    });
  }
});

// @route   GET /api/files/download/:fileId
// @desc    Download approved file
// @access  Private (User only)
router.get('/download/:fileId', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const file = await File.findById(req.params.fileId)
      .populate('senderId')
      .select('+encryptedWithKey');
    
    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }
    
    // Check if user is the recipient
    if (file.recipientEmail !== user.email) {
      return res.status(403).json({
        success: false,
        message: 'You are not authorized to download this file'
      });
    }
    
    // Check if download is approved
    if (file.downloadRequestStatus !== 'approved') {
      return res.status(403).json({
        success: false,
        message: 'File download not approved by admin yet. Please request download permission first.'
      });
    }
    
    // Fetch encrypted file from Cloudinary
    const response = await fetch(file.fileUrl);
    if (!response.ok) {
      throw new Error('Failed to fetch file from Cloudinary');
    }
    
    const encryptedBuffer = Buffer.from(await response.arrayBuffer());
    
    // Decrypt sender's encryption key
    const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
    const encryptedKeyBuffer = Buffer.from(file.encryptedWithKey, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
    let senderKey = decipher.update(encryptedKeyBuffer);
    senderKey = Buffer.concat([senderKey, decipher.final()]);
    const senderKeyHex = senderKey.toString('hex');
    
    // Decrypt file
    const decryptedBuffer = decryptBuffer(encryptedBuffer, senderKeyHex);
    
    // Create audit log
    await createAuditLog(
      user._id,
      'User',
      user.email,
      'download',
      `Downloaded file "${file.originalFileName}" from ${file.senderEmail}`,
      file._id,
      req
    );
    
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalFileName}"`);
    res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
    res.send(decryptedBuffer);
    
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({
      success: false,
      message: 'File download failed',
      error: error.message
    });
  }
});

module.exports = router;
