const jwt = require('jsonwebtoken');
require('dotenv').config();

const authMiddleware = (req, res, next) => {
  // Allow OPTIONS requests (CORS preflight)
  if (req.method === 'OPTIONS') return next();

  // Get the token from the Authorization header or cookies
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    // Verify the token using the secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach the decoded user ID to the request object for use in other routes
    req.userId = decoded.userId;
    next(); // Pass control to the next middleware or route handler
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports = authMiddleware;
