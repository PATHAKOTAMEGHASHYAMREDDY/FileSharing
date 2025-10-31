const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  actor: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'actorModel',
    required: true
  },
  actorModel: {
    type: String,
    required: true,
    enum: ['User', 'Admin']
  },
  actorEmail: {
    type: String,
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: ['upload', 'download', 'approve', 'reject', 'delete', 'key_generate', 'key_update']
  },
  targetFile: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    default: null
  },
  targetUser: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  details: {
    type: String,
    default: null
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
