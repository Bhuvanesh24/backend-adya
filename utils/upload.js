// utils/upload.js
import multer from 'multer';
import fs from 'fs';
import path from 'path';

// Base uploads directory
const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}


const getMulterStorage = () => {
    return multer.diskStorage({
        destination: (req, file, cb) => {
            const userId = req.user?.id || 'general'; 
            const userUploadPath = path.join(uploadsDir, userId);
            if (!fs.existsSync(userUploadPath)) {
                fs.mkdirSync(userUploadPath, { recursive: true });
            }
            cb(null, userUploadPath);
        },
        filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
        }
    });
};

const fileFilter = (req, file, cb) => {
    const isPdf = file.mimetype === 'application/pdf' && path.extname(file.originalname).toLowerCase() === '.pdf';
    if (isPdf) {
        cb(null, true);
    } else {
        cb(new Error('Only PDF files are allowed'));
    }
};

// Final multer instance
export  const upload = multer({
    storage: getMulterStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
});
