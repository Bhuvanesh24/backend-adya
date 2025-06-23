import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Helper function for cookie options
const getCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    httpOnly: true,
    secure: isProduction, // Only secure in production (HTTPS required)
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-origin in production
    maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days
    // Add domain if your frontend and backend are on different subdomains
    ...(isProduction && process.env.COOKIE_DOMAIN && { domain: process.env.COOKIE_DOMAIN })
  };
};

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Input validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "All fields are required" 
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: "User already exists" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      skills: [],
      resumes: [],
      coverLetters: [],
    });

    await newUser.save();

    // Create token and set cookie for immediate login after signup
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "15d"
    });

    res.cookie("token", token, getCookieOptions());

    res.status(201).json({
      success: true,
      message: "Signup successful",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email
      },
      token // Include token in response for debugging
    });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ 
      success: false,
      message: "Internal server error" 
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15d"
    });

    res.cookie("token", token, getCookieOptions());

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      token // Include token in response for debugging
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ 
      success: false,
      message: "Internal server error" 
    });
  }
};

export const logout = async (req, res) => {
  try {
    const cookieOptions = {
      ...getCookieOptions(),
      expires: new Date(0), // Expire immediately
      maxAge: 0
    };

    res.cookie("token", "", cookieOptions);

    res.status(200).json({
      success: true,
      message: "Logout successful"
    });

  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ 
      success: false,
      message: "Internal server error" 
    });
  }
};

export const checkAuth = async (req, res) => {
  try {
    const token = req.cookies.token;
    console.log(token);
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "No token provided" 
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      console.error("JWT verification failed:", jwtError);
      return res.status(401).json({ 
        success: false,
        message: "Invalid or expired token" 
      });
    }

    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User not found" 
      });
    }

    res.status(200).json({
      success: true,
      message: "Authenticated",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    console.error("Auth check error:", err);
    res.status(401).json({ 
      success: false,
      message: "Invalid or expired token" 
    });
  }
};