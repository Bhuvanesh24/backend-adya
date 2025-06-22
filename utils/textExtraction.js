// utils/textExtraction.js - Node.js compatible PDF extractor

import fs from "fs";
import path from "path";

class TextExtractor {
  
  // PDF extraction using pdfjs-dist legacy build
  static async extractFromPDF(filePath) {
    try {
      // Check if file exists first
      if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
      }

      // Set up Node.js environment for pdfjs-dist
      if (typeof globalThis !== 'undefined') {
        // Add required polyfills for Node.js
        if (!globalThis.DOMMatrix) {
          globalThis.DOMMatrix = class DOMMatrix {
            constructor(init) {
              if (typeof init === 'string') {
                // Simple matrix string parsing (basic implementation)
                this.a = 1; this.b = 0; this.c = 0; this.d = 1; this.e = 0; this.f = 0;
              } else if (Array.isArray(init)) {
                [this.a, this.b, this.c, this.d, this.e, this.f] = init;
              } else {
                this.a = 1; this.b = 0; this.c = 0; this.d = 1; this.e = 0; this.f = 0;
              }
            }
            
            multiply(other) {
              return new DOMMatrix([
                this.a * other.a + this.c * other.b,
                this.b * other.a + this.d * other.b,
                this.a * other.c + this.c * other.d, 
                this.b * other.c + this.d * other.d,
                this.a * other.e + this.c * other.f + this.e,
                this.b * other.e + this.d * other.f + this.f
              ]);
            }
            
            translate(x, y) {
              return new DOMMatrix([this.a, this.b, this.c, this.d, this.e + x, this.f + y]);
            }
          };
        }
        
        if (!globalThis.Path2D) {
          globalThis.Path2D = class Path2D {
            constructor() {}
            moveTo() {}
            lineTo() {}
            bezierCurveTo() {}
            closePath() {}
          };
        }
      }

      // Import pdfjs-dist legacy build
      const pdfjsLib = await import('pdfjs-dist/legacy/build/pdf.js');
      const pdfjs = pdfjsLib.default || pdfjsLib;
      
      // Read file as Buffer first
      const dataBuffer = fs.readFileSync(filePath);
      
      // Convert Buffer to Uint8Array - this is the key fix!
      const uint8Array = new Uint8Array(dataBuffer);
      
      // Create loading task with Node.js friendly options
      const loadingTask = pdfjs.getDocument({
        data: uint8Array, // Use Uint8Array instead of Buffer
        useSystemFonts: true,
        isEvalSupported: false,
        useWorkerFetch: false
      });
      
      const pdf = await loadingTask.promise;
      
      let fullText = '';
      const numPages = pdf.numPages;
      
      // Extract text from each page
      for (let pageNumber = 1; pageNumber <= numPages; pageNumber++) {
        try {
          const page = await pdf.getPage(pageNumber);
          const textContent = await page.getTextContent();
          
          // Sort text items by position (top to bottom, left to right)
          const sortedItems = textContent.items.sort((a, b) => {
            // Sort by Y position first (top to bottom)
            const yDiff = Math.abs(b.transform[5] - a.transform[5]);
            if (yDiff > 5) return b.transform[5] - a.transform[5];
            // Then by X position (left to right)
            return a.transform[4] - b.transform[4];
          });
          
          // Group items by lines based on Y position
          const lines = [];
          let currentLine = [];
          let currentY = null;
          
          for (const item of sortedItems) {
            const itemY = Math.round(item.transform[5]);
            
            if (currentY === null || Math.abs(currentY - itemY) <= 5) {
              currentLine.push(item);
              currentY = itemY;
            } else {
              if (currentLine.length > 0) {
                lines.push(currentLine.map(i => i.str).join(' '));
              }
              currentLine = [item];
              currentY = itemY;
            }
          }
          
          // Add the last line
          if (currentLine.length > 0) {
            lines.push(currentLine.map(i => i.str).join(' '));
          }
          
          const pageText = lines.join('\n');
          
          if (pageText.trim()) {
            fullText += pageText + '\n\n';
          }
          
        } catch (pageError) {
          console.warn(`Error extracting text from page ${pageNumber}:`, pageError.message);
          // Continue with other pages
        }
      }
      
      // Clean up PDF document
      await pdf.destroy();
      
      return {
        success: true,
        text: fullText.trim(),
        pages: numPages,
        metadata: { 
          pages: numPages,
          extractedAt: new Date().toISOString()
        }
      };
      
    } catch (error) {
      console.error('PDF extraction error:', error);
      return {
        success: false,
        error: 'Failed to extract text from PDF',
        details: error.message
      };
    }
  }

  // Main extraction method - only handles PDF files
  static async extractText(filePath) {
    try {
      // Check if file exists first
      if (!fs.existsSync(filePath)) {
        return {
          success: false,
          error: 'File not found',
          details: `No file found at path: ${filePath}`
        };
      }

      const fileExtension = path.extname(filePath).toLowerCase();
      const fileStats = fs.statSync(filePath);
      
      if (!fileStats.isFile()) {
        return {
          success: false,
          error: 'Invalid file path - not a file',
          details: 'The provided path does not point to a valid file'
        };
      }

      // Only accept PDF files
      if (fileExtension !== '.pdf') {
        return {
          success: false,
          error: 'Only PDF files are supported',
          supportedFormats: ['.pdf'],
          receivedFormat: fileExtension || 'unknown'
        };
      }

      // Validate file size (prevent huge files)
      const maxFileSize = 50 * 1024 * 1024; // 50MB
      if (fileStats.size > maxFileSize) {
        return {
          success: false,
          error: 'File too large',
          details: `File size ${Math.round(fileStats.size / 1024 / 1024)}MB exceeds maximum allowed size of ${maxFileSize / 1024 / 1024}MB`
        };
      }

      const result = await this.extractFromPDF(filePath);

      // Clean up and enhance the extracted text
      if (result.success && result.text) {
        result.text = this.cleanText(result.text);
        
        // Only add stats if text was successfully extracted
        if (result.text.length > 0) {
          result.wordCount = result.text.split(/\s+/).filter(word => word.length > 0).length;
          result.characterCount = result.text.length;
          result.fileInfo = {
            size: fileStats.size,
            sizeFormatted: `${Math.round(fileStats.size / 1024)}KB`
          };
        }
      }

      return result;

    } catch (error) {
      console.error('Text extraction error:', error);
      return {
        success: false,
        error: 'Failed to extract text from file',
        details: error.message
      };
    }
  }

  // Clean and normalize extracted text
  static cleanText(text) {
    if (!text) return '';
    
    return text
      // Normalize whitespace
      .replace(/\s+/g, ' ')
      // Remove control characters
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      // Clean up excessive line breaks but preserve paragraph structure
      .replace(/\n\s*\n\s*\n+/g, '\n\n')
      // Remove leading/trailing whitespace
      .trim();
  }

  // Validate if extracted text looks like a resume
  static validateResumeContent(text) {
    if (!text || text.length < 50) {
      return {
        isValid: false,
        reason: 'Extracted text is too short to be a meaningful resume',
        extractedLength: text ? text.length : 0
      };
    }

    // Common resume keywords/sections
    const resumeKeywords = [
      'experience', 'education', 'skills', 'work', 'employment',
      'university', 'college', 'degree', 'certification', 'project',
      'email', 'phone', 'address', 'linkedin', 'github', 'resume',
      'objective', 'summary', 'achievements', 'responsibilities',
      'career', 'professional', 'qualification', 'internship'
    ];

    const textLower = text.toLowerCase();
    const foundKeywords = resumeKeywords.filter(keyword => 
      textLower.includes(keyword)
    );

    const minKeywords = 3;
    if (foundKeywords.length < minKeywords) {
      return {
        isValid: false,
        reason: `Content does not appear to be a resume (found ${foundKeywords.length}/${minKeywords} resume keywords)`,
        suggestion: 'Please ensure the file contains resume content with sections like experience, education, skills, etc.',
        foundKeywords: foundKeywords
      };
    }

    return {
      isValid: true,
      confidence: Math.min((foundKeywords.length / resumeKeywords.length) * 100, 100),
      foundKeywords: foundKeywords,
      keywordCount: foundKeywords.length
    };
  }

  // Utility method to check if file exists and is accessible
  static async validateFile(filePath) {
    try {
      const stats = fs.statSync(filePath);
      return {
        exists: true,
        isFile: stats.isFile(),
        size: stats.size,
        sizeFormatted: `${Math.round(stats.size / 1024)}KB`,
        extension: path.extname(filePath).toLowerCase(),
        isPDF: path.extname(filePath).toLowerCase() === '.pdf'
      };
    } catch (error) {
      return {
        exists: false,
        error: error.message
      };
    }
  }
}

export default TextExtractor;