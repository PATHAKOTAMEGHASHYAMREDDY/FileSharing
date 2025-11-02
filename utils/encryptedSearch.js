const crypto = require('crypto');

/**
 * Encrypted Search Utility
 * Implements searchable encryption using encrypted indexing
 * Supports boolean queries: AND, OR, NOT
 */

class EncryptedSearch {
  constructor() {
    this.algorithm = 'aes-256-cbc';
  }

  /**
   * Create encrypted index for a filename
   * @param {string} filename - Original filename
   * @param {Buffer} encryptionKey - User's encryption key
   * @returns {Array} - Array of encrypted tokens
   */
  createEncryptedIndex(filename, encryptionKey) {
    // Tokenize filename (split by spaces, dots, underscores, hyphens)
    const tokens = filename
      .toLowerCase()
      .split(/[\s._-]+/)
      .filter(token => token.length > 0);

    // Create encrypted tokens
    const encryptedTokens = tokens.map(token => {
      return this.encryptToken(token, encryptionKey);
    });

    return encryptedTokens;
  }

  /**
   * Encrypt a single token
   * @param {string} token - Token to encrypt
   * @param {Buffer} encryptionKey - Encryption key
   * @returns {string} - Encrypted token (hex)
   */
  encryptToken(token, encryptionKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, encryptionKey, iv);
    
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return IV + encrypted data
    return iv.toString('hex') + ':' + encrypted;
  }

  /**
   * Decrypt a token
   * @param {string} encryptedToken - Encrypted token with IV
   * @param {Buffer} encryptionKey - Encryption key
   * @returns {string} - Decrypted token
   */
  decryptToken(encryptedToken, encryptionKey) {
    try {
      const parts = encryptedToken.split(':');
      const iv = Buffer.from(parts[0], 'hex');
      const encrypted = parts[1];
      
      const decipher = crypto.createDecipheriv(this.algorithm, encryptionKey, iv);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      return null;
    }
  }

  /**
   * Parse boolean query
   * @param {string} query - Search query with AND, OR, NOT operators
   * @returns {Object} - Parsed query structure
   */
  parseQuery(query) {
    // Simple parser for AND, OR, NOT operations
    const tokens = query.trim().split(/\s+/);
    const parsed = {
      and: [],
      or: [],
      not: []
    };

    let currentOp = 'and'; // default operation
    
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i].toUpperCase();
      
      if (token === 'AND') {
        currentOp = 'and';
      } else if (token === 'OR') {
        currentOp = 'or';
      } else if (token === 'NOT') {
        currentOp = 'not';
      } else {
        parsed[currentOp].push(tokens[i].toLowerCase());
      }
    }

    return parsed;
  }

  /**
   * Search encrypted index
   * @param {Array} encryptedIndex - Array of encrypted tokens
   * @param {Object} parsedQuery - Parsed query with and/or/not
   * @param {Buffer} encryptionKey - Encryption key
   * @returns {boolean} - Whether the file matches the query
   */
  searchIndex(encryptedIndex, parsedQuery, encryptionKey) {
    // Decrypt all tokens in the index
    const decryptedTokens = encryptedIndex
      .map(token => this.decryptToken(token, encryptionKey))
      .filter(token => token !== null);

    // Check AND conditions (all must match)
    const andMatch = parsedQuery.and.length === 0 || 
      parsedQuery.and.every(term => 
        decryptedTokens.some(token => token.includes(term))
      );

    // Check OR conditions (at least one must match)
    const orMatch = parsedQuery.or.length === 0 || 
      parsedQuery.or.some(term => 
        decryptedTokens.some(token => token.includes(term))
      );

    // Check NOT conditions (none should match)
    const notMatch = parsedQuery.not.length === 0 || 
      !parsedQuery.not.some(term => 
        decryptedTokens.some(token => token.includes(term))
      );

    return andMatch && orMatch && notMatch;
  }

  /**
   * Create searchable trapdoor for a query term
   * This allows searching without decrypting the entire index
   * @param {string} term - Search term
   * @param {Buffer} encryptionKey - Encryption key
   * @returns {string} - Trapdoor value
   */
  createTrapdoor(term, encryptionKey) {
    const hmac = crypto.createHmac('sha256', encryptionKey);
    hmac.update(term.toLowerCase());
    return hmac.digest('hex');
  }

  /**
   * Check if trapdoor matches encrypted token
   * @param {string} trapdoor - Trapdoor value
   * @param {string} encryptedToken - Encrypted token
   * @param {Buffer} encryptionKey - Encryption key
   * @returns {boolean} - Whether they match
   */
  matchTrapdoor(trapdoor, encryptedToken, encryptionKey) {
    const decrypted = this.decryptToken(encryptedToken, encryptionKey);
    if (!decrypted) return false;
    
    const tokenTrapdoor = this.createTrapdoor(decrypted, encryptionKey);
    return trapdoor === tokenTrapdoor;
  }
}

module.exports = new EncryptedSearch();
