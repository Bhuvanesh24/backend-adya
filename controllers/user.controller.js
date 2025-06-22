//profile management
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";


// Get user profile
export const getUserProfile = async (req, res) => {
    try {
        
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ success: true, user });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update basic personal information
export const updatePersonalInfo = async (req, res) => {
    try {
        const { name, email, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already exists' });
            }
            user.email = email;
        }

        if (name) user.name = name;

        // Handle password change
        if (currentPassword && newPassword) {
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Current password is incorrect' });
            }
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(newPassword, salt);
        }

        await user.save();
        res.json({ success: true, message: 'Personal information updated successfully' });
    } catch (error) {
        console.error('Update personal info error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update professional summary
export const updateProfessionalSummary = async (req, res) => {
    try {
        const { professionalSummary } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { professionalSummary },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Professional summary updated successfully', user });
    } catch (error) {
        console.error('Update professional summary error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update skills
export const updateSkills = async (req, res) => {
    try {
        const { skills } = req.body;
        
        if (!Array.isArray(skills)) {
            return res.status(400).json({ message: 'Skills must be an array' });
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { skills },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Skills updated successfully', user });
    } catch (error) {
        console.error('Update skills error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Add single skill
export const addSkill = async (req, res) => {
    try {
        const { skill } = req.body;
        
        if (!skill || typeof skill !== 'string') {
            return res.status(400).json({ message: 'Valid skill is required' });
        }

        const user = await User.findById(req.user.id);
        if (!user.skills.includes(skill)) {
            user.skills.push(skill);
            await user.save();
        }

        res.json({ success: true, message: 'Skill added successfully', skills: user.skills });
    } catch (error) {
        console.error('Add skill error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Remove single skill
export const removeSkill = async (req, res) => {
    try {
        const { skill } = req.body;
        
        const user = await User.findById(req.user.id);
        user.skills = user.skills.filter(s => s !== skill);
        await user.save();

        res.json({ success: true, message: 'Skill removed successfully', skills: user.skills });
    } catch (error) {
        console.error('Remove skill error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update experience
export const updateExperience = async (req, res) => {
    try {
        const { experience } = req.body;
        
        if (!Array.isArray(experience)) {
            return res.status(400).json({ message: 'Experience must be an array' });
        }

        // Validate each experience entry
        for (let exp of experience) {
            if (!exp.jobTitle) {
                return res.status(400).json({ message: 'Job title is required for each experience' });
            }
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { experience },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Experience updated successfully', user });
    } catch (error) {
        console.error('Update experience error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Add single experience
export const addExperience = async (req, res) => {
    try {
        const { jobTitle, company, yearsOfExperience, description } = req.body;
        
        if (!jobTitle) {
            return res.status(400).json({ message: 'Job title is required' });
        }

        const newExperience = {
            jobTitle,
            company: company || '',
            yearsOfExperience: yearsOfExperience || 0,
            description: description || ''
        };

        const user = await User.findById(req.user.id);
        user.experience.push(newExperience);
        await user.save();

        res.json({ success: true, message: 'Experience added successfully', experience: user.experience });
    } catch (error) {
        console.error('Add experience error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Remove experience by index
export const removeExperience = async (req, res) => {
    try {
        const { index } = req.params;
        
        const user = await User.findById(req.user.id);
        if (index >= 0 && index < user.experience.length) {
            user.experience.splice(index, 1);
            await user.save();
        }

        res.json({ success: true, message: 'Experience removed successfully', experience: user.experience });
    } catch (error) {
        console.error('Remove experience error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update job preferences
export const updateJobPreferences = async (req, res) => {
    try {
        const { jobPreferences } = req.body;
        
       
        const validPreferences = {};
        if (jobPreferences.titles && Array.isArray(jobPreferences.titles)) {
            validPreferences.titles = jobPreferences.titles;
        }
        if (jobPreferences.locations && Array.isArray(jobPreferences.locations)) {
            validPreferences.locations = jobPreferences.locations;
        }
        if (jobPreferences.jobType) {
            validPreferences.jobType = jobPreferences.jobType;
        }
        if (jobPreferences.industries && Array.isArray(jobPreferences.industries)) {
            validPreferences.industries = jobPreferences.industries;
        }
        if (jobPreferences.expectedSalary) {
            validPreferences.expectedSalary = jobPreferences.expectedSalary;
        }
        if (jobPreferences.workMode) {
            validPreferences.workMode = jobPreferences.workMode;
        }
        if (typeof jobPreferences.relocate === 'boolean') {
            validPreferences.relocate = jobPreferences.relocate;
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { jobPreferences: validPreferences },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Job preferences updated successfully', user });
    } catch (error) {
        console.error('Update job preferences error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Update job goals
export const updateJobGoals = async (req, res) => {
    try {
        const { weeklyTarget, currentWeekCount } = req.body;
        
        const updates = {};
        if (typeof weeklyTarget === 'number') updates['jobGoals.weeklyTarget'] = weeklyTarget;
        if (typeof currentWeekCount === 'number') updates['jobGoals.currentWeekCount'] = currentWeekCount;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            updates,
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Job goals updated successfully', user });
    } catch (error) {
        console.error('Update job goals error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Reset weekly job goal count
export const resetWeeklyJobGoals = async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { 
                'jobGoals.currentWeekCount': 0,
                'jobGoals.lastReset': new Date()
            },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ success: true, message: 'Weekly job goals reset successfully', user });
    } catch (error) {
        console.error('Reset job goals error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Upload resume
export const uploadResume = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const filePath = `/uploads/${req.user.id}/${req.file.filename}`;
        
        const user = await User.findById(req.user.id);
        user.resumes.push(filePath);
        await user.save();

        res.json({ 
            success: true, 
            message: 'Resume uploaded successfully',
            filePath,
            fileName: req.file.originalname,
            resumes: user.resumes
        });
    } catch (error) {
        console.error('Upload resume error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Upload cover letter
export const uploadCoverLetter = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const filePath = `/uploads/${req.user.id}/${req.file.filename}`;
        
        const user = await User.findById(req.user.id);
        user.coverLetters.push(filePath);
        await user.save();

        res.json({ 
            success: true, 
            message: 'Cover letter uploaded successfully',
            filePath,
            fileName: req.file.originalname,
            coverLetters: user.coverLetters
        });
    } catch (error) {
        console.error('Upload cover letter error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Delete resume
export const deleteResume = async (req, res) => {
    try {
        const { filePath } = req.body;
        
        const user = await User.findById(req.user.id);
        user.resumes = user.resumes.filter(resume => resume !== filePath);
        await user.save();

        // Delete file from filesystem
        const fullPath = path.join(process.cwd(), filePath);
        if (fs.existsSync(fullPath)) {
            fs.unlinkSync(fullPath);
        }

        res.json({ 
            success: true, 
            message: 'Resume deleted successfully',
            resumes: user.resumes
        });
    } catch (error) {
        console.error('Delete resume error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Delete cover letter
export const deleteCoverLetter = async (req, res) => {
    try {
        const { filePath } = req.body;
        
        const user = await User.findById(req.user.id);
        user.coverLetters = user.coverLetters.filter(coverLetter => coverLetter !== filePath);
        await user.save();

        // Delete file from filesystem
        const fullPath = path.join(process.cwd(), filePath);
        if (fs.existsSync(fullPath)) {
            fs.unlinkSync(fullPath);
        }

        res.json({ 
            success: true, 
            message: 'Cover letter deleted successfully',
            coverLetters: user.coverLetters
        });
    } catch (error) {
        console.error('Delete cover letter error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Get user documents (resumes and cover letters)
export const getUserDocuments = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('resumes coverLetters');
        
        // Add file metadata
        const resumesWithMetadata = user.resumes.map(filePath => {
            const fullPath = path.join(process.cwd(), filePath);
            let metadata = { filePath, exists: false };
            
            if (fs.existsSync(fullPath)) {
                const stats = fs.statSync(fullPath);
                metadata = {
                    filePath,
                    fileName: path.basename(filePath),
                    size: stats.size,
                    uploadedAt: stats.birthtime,
                    exists: true
                };
            }
            return metadata;
        });

        const coverLettersWithMetadata = user.coverLetters.map(filePath => {
            const fullPath = path.join(process.cwd(), filePath);
            let metadata = { filePath, exists: false };
            
            if (fs.existsSync(fullPath)) {
                const stats = fs.statSync(fullPath);
                metadata = {
                    filePath,
                    fileName: path.basename(filePath),
                    size: stats.size,
                    uploadedAt: stats.birthtime,
                    exists: true
                };
            }
            return metadata;
        });

        res.json({ 
            success: true, 
            resumes: resumesWithMetadata,
            coverLetters: coverLettersWithMetadata
        });
    } catch (error) {
        console.error('Get documents error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Download file
export const downloadFile = async (req, res) => {
    try {
        const { filePath } = req.body;
        const fullPath = path.join(process.cwd(), filePath);
        
        // Verify the file belongs to the user
        if (!filePath.includes(req.user.id)) {
            return res.status(403).json({ message: 'Access denied' });
        }

        if (!fs.existsSync(fullPath)) {
            return res.status(404).json({ message: 'File not found' });
        }

        const fileName = path.basename(fullPath);
        res.download(fullPath, fileName);
    } catch (error) {
        console.error('Download file error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Add notification
export const addNotification = async (req, res) => {
    try {
        const { message, type } = req.body;
        
        const notification = {
            message,
            type: type || 'info',
            createdAt: new Date(),
            isRead: false
        };

        const user = await User.findById(req.user.id);
        user.notifications.push(notification);
        await user.save();

        res.json({ 
            success: true, 
            message: 'Notification added successfully',
            notifications: user.notifications
        });
    } catch (error) {
        console.error('Add notification error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Mark notification as read
export const markNotificationRead = async (req, res) => {
    try {
        const { notificationId } = req.body;
        
        const user = await User.findById(req.user.id);
        const notification = user.notifications.id(notificationId);
        
        if (notification) {
            notification.isRead = true;
            await user.save();
        }

        res.json({ 
            success: true, 
            message: 'Notification marked as read',
            notifications: user.notifications
        });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Get unread notifications count
export const getUnreadNotificationsCount = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('notifications');
        const unreadCount = user.notifications.filter(n => !n.isRead).length;
        
        res.json({ 
            success: true, 
            unreadCount
        });
    } catch (error) {
        console.error('Get unread notifications error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};