import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

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

    res.status(201).json({
      success: true,
      message: "Signup successful",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email
      }
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


    const cookieOptions = {
      httpOnly: true,
      secure: true, 
      sameSite: 'none',
      maxAge: 15 * 24 * 60 * 60 * 1000, 
      domain: process.env.COOKIE_DOMAIN || undefined
    };

    res.cookie("token", token, cookieOptions);

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      token
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
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      expires: new Date(0)
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
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "No token provided" 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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