import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => { 
  let token = req.cookies.token;
  if (!token && req.headers.authorization) {
    token = req.headers.authorization.replace('Bearer ', '');
  }
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: "Access denied. No token provided." 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ 
      success: false,
      message: "Invalid or expired token." 
    });
  }
};

export const requireAuth = authMiddleware;