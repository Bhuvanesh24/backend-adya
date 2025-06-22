// controllers/aiController.js (Enhanced Dynamic Version)
import { HfInference } from '@huggingface/inference';
import TextExtractor from '../utils/textExtraction.js';
import fs from "fs";
import { InferenceClient } from "@huggingface/inference";
import dotenv from 'dotenv';

dotenv.config();

const hf = new HfInference(process.env.HF_API_KEY);
const useHuggingFaceAPI = !!process.env.HF_API_KEY;

// Dynamic content generators
class ContentAnalyzer {
  static extractKeywords(text) {
    const keywords = new Set();
    const patterns = [
      /\b(?:JavaScript|Python|Java|React|Node\.js|SQL|AWS|Docker|Git|HTML|CSS)\b/gi,
      /\b(?:machine learning|data science|AI|ML|analytics|automation)\b/gi,
      /\b(?:project management|agile|scrum|leadership|communication)\b/gi,
      /\b(?:problem solving|analytical|creative|innovative|strategic)\b/gi
    ];

    patterns.forEach(pattern => {
      const matches = text.match(pattern) || [];
      matches.forEach(match => keywords.add(match.toLowerCase()));
    });

    return Array.from(keywords);
  }

  static calculateSkillMatch(resumeText, jobDescription) {
    const jobKeywords = this.extractKeywords(jobDescription);
    const resumeKeywords = this.extractKeywords(resumeText);
    
    const matched = jobKeywords.filter(keyword => 
      resumeKeywords.includes(keyword)
    );

    return {
      totalRequired: jobKeywords.length,
      matched: matched.length,
      percentage: jobKeywords.length > 0 ? 
        Math.round((matched.length / jobKeywords.length) * 100) : 0,
      matchedSkills: matched,
      missingSkills: jobKeywords.filter(keyword => !matched.includes(keyword))
    };
  }

  static extractCompanyInfo(companyName, jobDescription) {
    const info = {
      industry: 'technology',
      size: 'medium',
      values: [],
      benefits: []
    };

    // Industry detection
    if (/healthcare|medical|pharma/i.test(jobDescription)) info.industry = 'healthcare';
    else if (/finance|banking|fintech/i.test(jobDescription)) info.industry = 'finance';
    else if (/education|learning|academic/i.test(jobDescription)) info.industry = 'education';
    else if (/retail|ecommerce|shopping/i.test(jobDescription)) info.industry = 'retail';

    // Values extraction
    const valueKeywords = jobDescription.match(/\b(?:innovation|collaboration|integrity|excellence|diversity|sustainability|growth|customer|quality)\b/gi) || [];
    info.values = [...new Set(valueKeywords.map(v => v.toLowerCase()))].slice(0, 3);

    return info;
  }

  static generateDynamicScore(resumeText, jobDescription, additionalFactors = {}) {
    const skillMatch = this.calculateSkillMatch(resumeText, jobDescription);
    const hasQuantifiableResults = /\d+%|\$\d+|increased|improved|reduced|achieved/i.test(resumeText);
    const resumeLength = resumeText.split(/\s+/).length;
    const experienceYears = parseInt(additionalFactors.experienceYears) || 0;

    let score = 0;
    score += skillMatch.percentage * 0.4; // 40% weight on skill match
    score += hasQuantifiableResults ? 20 : 5; // Quantifiable achievements
    score += resumeLength > 300 ? 15 : 5; // Content depth
    score += Math.min(experienceYears * 3, 20); // Experience (max 20 points)

    return Math.min(Math.round(score), 100);
  }
}

class PromptBuilder {
  static buildResumeAnalysisPrompt(resumeText, jobDescription) {
    return `As an expert resume analyst, provide a detailed analysis of this resume against the job requirements.

RESUME CONTENT:
${resumeText.substring(0, 2000)}

JOB REQUIREMENTS:
${jobDescription.substring(0, 1000)}

Analyze and provide:
1. Overall compatibility score (0-100)
2. Top 3 specific strengths with examples from the resume
3. Top 3 improvement areas with actionable suggestions
4. Missing keywords that should be incorporated
5. ATS optimization recommendations

Focus on specific, actionable feedback rather than generic advice.`;
  }

  static buildCoverLetterPrompt(jobTitle, companyName, jobDescription, userProfile) {
    return `Write a personalized cover letter for this specific role:

POSITION: ${jobTitle} at ${companyName}
JOB DESCRIPTION: ${jobDescription.substring(0, 800)}

CANDIDATE PROFILE:
Name: ${userProfile.name || '[Your Name]'}
Skills: ${userProfile.skills || 'Professional skills and experience'}
Experience: ${userProfile.experience || 'Relevant professional background'}

Create a compelling, personalized cover letter that:
1. Opens with genuine enthusiasm for this specific role and company
2. Highlights 2-3 most relevant qualifications with specific examples
3. Shows knowledge of the company/role requirements
4. Closes with a confident call to action

Make it professional yet personable, and avoid generic phrases.`;
  }

  static buildInterviewQuestionsPrompt(jobTitle, companyName, jobDescription, experienceLevel) {
    return `Generate tailored interview questions for: ${jobTitle} at ${companyName}

JOB DESCRIPTION: ${jobDescription?.substring(0, 600) || 'Standard role requirements'}
CANDIDATE LEVEL: ${experienceLevel || 'Mid-level'}

Create specific questions in these categories:

TECHNICAL QUESTIONS (5):
- Role-specific technical skills and knowledge
- Problem-solving scenarios relevant to the position

BEHAVIORAL QUESTIONS (5):
- Past experience examples using STAR method
- Situation-based questions for this role level

COMPANY/ROLE FIT QUESTIONS (5):
- Motivation and company alignment
- Career goals and role expectations

For each question, briefly explain what the interviewer is assessing.`;
  }

  static buildSuccessAnalysisPrompt(candidateProfile, jobDescription, jobTitle, companyName) {
    return `Analyze this candidate's success probability for the specific role:

ROLE: ${jobTitle} at ${companyName}
JOB REQUIREMENTS: ${jobDescription.substring(0, 800)}

CANDIDATE:
Resume: ${candidateProfile.resume?.substring(0, 1500) || 'Not provided'}
Skills: ${candidateProfile.skills || 'Not specified'}
Experience: ${candidateProfile.experienceYears || 'Not specified'} years
Education: ${candidateProfile.education || 'Not specified'}

Provide detailed assessment:
1. Success probability percentage with reasoning
2. Skill match analysis (technical and soft skills)
3. Experience relevance evaluation
4. Top 3 competitive strengths
5. Top 3 areas needing improvement
6. Specific action items to increase success rate

Be realistic and provide actionable insights.`;
  }
}

// Enhanced AI text generation with working models and fallback
const generateDynamicText = async (prompt, maxTokens = 1000) => {
  if (!useHuggingFaceAPI) {
    return generateIntelligentFallback(prompt);
  }
    const client = new InferenceClient(process.env.HF_API_KEY);
    try {
      const chatCompletion = await client.chatCompletion({
        provider: "novita",
        model: "deepseek-ai/DeepSeek-V3-0324",
        messages: [
          {
            role: "user",
            content: prompt,
          },
        ],
        max_tokens: Math.min(maxTokens, 800),
        temperature: 0.7,
        top_p: 0.9
      });

      const result = chatCompletion.choices[0]?.message?.content;
      if (result && result.trim().length > 30) {
        console.log("Got");
        return result.trim();
      }
    } catch (error) {
      console.warn(`Model ${model} failed:`, error.message);
      
    }
  

  console.warn('All HF models failed, using intelligent fallback');
  return generateIntelligentFallback(prompt);
};

// Intelligent fallback system that generates dynamic content without AI
const generateIntelligentFallback = (prompt) => {
  const promptLower = prompt.toLowerCase();
  
  // Extract key information from prompt
  const extractInfo = () => {
    const jobTitleMatch = prompt.match(/(?:position|role|job):\s*([^\n]+)/i);
    const companyMatch = prompt.match(/(?:company|at)\s+([^\n\s,]+)/i);
    const skillsMatch = prompt.match(/skills?:\s*([^\n]+)/i);
    const experienceMatch = prompt.match(/experience:\s*([^\n]+)/i);
    
    return {
      jobTitle: jobTitleMatch?.[1]?.trim() || 'the position',
      company: companyMatch?.[1]?.trim() || 'your company',
      skills: skillsMatch?.[1]?.trim() || 'professional skills',
      experience: experienceMatch?.[1]?.trim() || 'relevant experience'
    };
  };

  const info = extractInfo();

  // Cover Letter Generation
  if (promptLower.includes('cover letter')) {
    return `Dear Hiring Manager,

I am excited to apply for the ${info.jobTitle} position at ${info.company}. After reviewing the role requirements, I am confident that my background and skills make me an ideal candidate for this opportunity.

In my professional experience, I have developed strong expertise in ${info.skills}. My ${info.experience} has equipped me with the practical knowledge and problem-solving abilities that directly align with what you're seeking. I am particularly drawn to ${info.company} because of your reputation for innovation and commitment to excellence.

What sets me apart is my ability to combine technical proficiency with strong collaborative skills. I thrive in dynamic environments where I can contribute to meaningful projects while continuing to grow professionally. I am eager to bring my passion and dedication to your team.

I would welcome the opportunity to discuss how my background and enthusiasm can contribute to ${info.company}'s continued success. Thank you for considering my application.

Best regards,
${info.experience.includes('Name') ? info.experience : '[Your Name]'}`;
  }

  // Resume Analysis
  if (promptLower.includes('resume') && promptLower.includes('analyze')) {
    const skillKeywords = ContentAnalyzer.extractKeywords(prompt);
    const hasQuantifiable = /\d+%|\$\d+|increased|improved|reduced|achieved/i.test(prompt);
    
    return `RESUME ANALYSIS REPORT

OVERALL ASSESSMENT: ${hasQuantifiable ? '78' : '65'}/100
Your resume shows ${hasQuantifiable ? 'strong' : 'good'} potential for this role with several areas for optimization.

KEY STRENGTHS:
• Professional experience demonstrates relevant background in required areas
• ${skillKeywords.length > 3 ? 'Strong technical skill alignment with job requirements' : 'Solid foundation of core competencies'}
• ${hasQuantifiable ? 'Includes quantifiable achievements that demonstrate impact' : 'Clear presentation of work history and responsibilities'}

AREAS FOR IMPROVEMENT:
• ${skillKeywords.length < 5 ? 'Incorporate more industry-specific keywords from the job description' : 'Further optimize keyword density for ATS systems'}
• ${!hasQuantifiable ? 'Add quantifiable results and metrics to strengthen impact statements' : 'Expand on current achievements with additional context'}
• Enhance alignment between experience descriptions and specific job requirements

MISSING KEYWORDS TO CONSIDER:
${skillKeywords.slice(0, 5).join(', ')}

RECOMMENDATIONS:
1. Tailor your professional summary to mirror the job description language
2. Add 2-3 specific examples of measurable achievements
3. Optimize section headers for ATS compatibility
4. Include relevant certifications or training mentioned in the job posting

ATS OPTIMIZATION SCORE: ${hasQuantifiable ? 'Good' : 'Needs Improvement'}
Focus on standard formatting, relevant keywords, and quantifiable achievements to improve ATS performance.`;
  }

  // Interview Questions
  if (promptLower.includes('interview questions')) {
    return `INTERVIEW PREPARATION FOR ${info.jobTitle.toUpperCase()}

TECHNICAL QUESTIONS:
1. How would you approach [specific challenge mentioned in job description]?
2. What experience do you have with ${info.skills}?
3. Can you walk me through your process for handling complex projects?
4. What tools and methodologies do you prefer for this type of work?
5. How do you stay current with industry trends and best practices?

BEHAVIORAL QUESTIONS (Use STAR Method):
1. Tell me about a time you overcame a significant professional challenge
2. Describe a situation where you had to collaborate with a difficult team member
3. Give an example of when you had to learn a new skill quickly for a project
4. Tell me about a project you're particularly proud of and why
5. Describe how you handle competing priorities and tight deadlines

COMPANY/ROLE SPECIFIC:
1. Why are you interested in working for ${info.company}?
2. How do you see yourself contributing to our team's goals?
3. Where do you see your career progressing in this role?
4. What attracts you most about this particular position?
5. What questions do you have about our company culture and team?

PREPARATION TIPS:
• Research ${info.company}'s recent projects, news, and company values
• Prepare specific examples using the STAR method (Situation, Task, Action, Result)
• Practice explaining your experience with ${info.skills}
• Have thoughtful questions ready about the role and company
• Review the job description thoroughly and align your responses`;
  }

  // Success Probability Analysis
  if (promptLower.includes('success probability') || promptLower.includes('candidate')) {
    const expYears = prompt.match(/(\d+)\s*years?/i);
    const years = expYears ? parseInt(expYears[1]) : 3;
    const probability = Math.min(50 + (years * 8) + (skillKeywords.length * 5), 85);

    return `JOB APPLICATION SUCCESS ANALYSIS

SUCCESS PROBABILITY: ${probability}%
Based on your profile analysis, you have a ${probability >= 70 ? 'strong' : 'moderate'} chance of success with targeted preparation.

SCORE BREAKDOWN:
• Skills Alignment: ${Math.min(60 + (skillKeywords.length * 8), 90)}% - ${skillKeywords.length > 3 ? 'Good match with role requirements' : 'Core skills present with room for growth'}
• Experience Relevance: ${Math.min(40 + (years * 10), 85)}% - ${years >= 3 ? 'Solid experience level' : 'Growing experience base'}
• Profile Strength: ${probability}% - Overall competitive positioning

COMPETITIVE ADVANTAGES:
• ${info.skills} experience aligns with role requirements
• Professional background demonstrates career progression
• ${years >= 5 ? 'Senior-level experience brings valuable perspective' : 'Adaptability and eagerness to learn new technologies'}

KEY IMPROVEMENT AREAS:
• Strengthen expertise in specific tools mentioned in job posting
• Build portfolio examples that demonstrate relevant capabilities
• Develop deeper knowledge of ${info.company}'s industry and challenges
• Practice articulating value proposition clearly

RECOMMENDED ACTIONS:
1. Focus on highlighting your most relevant ${skillKeywords.slice(0, 3).join(', ')} experience
2. Research ${info.company}'s recent projects and industry positioning
3. Prepare compelling stories that demonstrate problem-solving abilities
4. Network with current employees to gain insider insights
5. Consider relevant online courses or certifications to fill skill gaps

MARKET INSIGHTS:
Industry demand for this role type is currently moderate to high, giving you good opportunities with proper preparation.`;
  }

  // Generic professional response
  return `Based on the information provided, here is a comprehensive analysis tailored to your specific situation.

KEY FINDINGS:
Your profile shows strong potential for ${info.jobTitle} opportunities, particularly given your background in ${info.skills}. The combination of your ${info.experience} and professional capabilities creates a solid foundation for success.

STRATEGIC RECOMMENDATIONS:
1. Focus on highlighting transferable skills that directly relate to the role requirements
2. Quantify your achievements wherever possible to demonstrate concrete value
3. Research ${info.company} thoroughly to understand their specific needs and culture
4. Prepare examples that showcase both technical abilities and soft skills
5. Practice articulating your unique value proposition clearly and confidently

NEXT STEPS:
Continue to refine your approach based on specific job requirements, and consider additional skill development in areas that would strengthen your competitive position.

This analysis provides a foundation for your professional development strategy moving forward.`;
};
const cleanupFile = (filePath) => {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (error) {
    console.error('File cleanup error:', error);
  }
};

const extractTextFromFile = async (file) => {
  const extractionResult = await TextExtractor.extractText(file.path);
  
  if (!extractionResult.success) {
    throw new Error(`Failed to extract text: ${extractionResult.error}`);
  }

  const validation = TextExtractor.validateResumeContent(extractionResult.text);
  if (!validation.isValid) {
    throw new Error(`Invalid content: ${validation.reason}`);
  }

  return extractionResult.text;
};

// Main controller functions

export const analyzeResume = async (req, res) => {
  let filePath = null;

  try {
    const { jobDescription } = req.body;
    let resumeText = req.body.resume;

    if (!jobDescription?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Job description is required'
      });
    }

    // Handle file upload
    if (req.file) {
      filePath = req.file.path;
      resumeText = await extractTextFromFile(req.file);
    }

    if (!resumeText?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Resume content or file is required'
      });
    }

    // Generate dynamic analysis
    const prompt = PromptBuilder.buildResumeAnalysisPrompt(resumeText, jobDescription);
    const aiAnalysis = await generateDynamicText(prompt, 1500);

    // Calculate dynamic metrics
    const skillMatch = ContentAnalyzer.calculateSkillMatch(resumeText, jobDescription);
    const overallScore = ContentAnalyzer.generateDynamicScore(resumeText, jobDescription);

    // Parse AI response for structured data
    const parseStrengths = (text) => {
      const strengthsMatch = text.match(/strengths?:?\s*(.*?)(?=weaknesses?|improvements?|areas|missing|\n\n|$)/is);
      if (!strengthsMatch) return ['Professional experience aligns with role requirements'];
      
      return strengthsMatch[1]
        .split(/[•\-\*\n]/)
        .filter(item => item.trim().length > 10)
        .map(item => item.trim().replace(/^\d+\.?\s*/, ''))
        .slice(0, 3);
    };

    const parseImprovements = (text) => {
      const improvementsMatch = text.match(/(?:improvement|weakness|areas?)[\s\S]*?:(.*?)(?=recommendation|keyword|ats|\n\n|$)/is);
      if (!improvementsMatch) return ['Add more specific examples of achievements'];
      
      return improvementsMatch[1]
        .split(/[•\-\*\n]/)
        .filter(item => item.trim().length > 10)
        .map(item => item.trim().replace(/^\d+\.?\s*/, ''))
        .slice(0, 3);
    };

    const analysis = {
      summary: {
        overallScore,
        matchLevel: overallScore >= 80 ? "Excellent" : 
                   overallScore >= 65 ? "Good" : 
                   overallScore >= 50 ? "Fair" : "Needs Improvement",
        keyMessage: skillMatch.percentage >= 70 
          ? `Strong match with ${skillMatch.percentage}% of required skills present`
          : `Good foundation with opportunities to strengthen skill alignment`,
        skillMatchPercentage: skillMatch.percentage
      },

      skillAnalysis: {
        totalKeywordsFound: skillMatch.totalRequired,
        matchedKeywords: skillMatch.matchedSkills,
        missingKeywords: skillMatch.missingSkills.slice(0, 8),
        matchPercentage: skillMatch.percentage
      },

      strengths: parseStrengths(aiAnalysis),
      improvementAreas: parseImprovements(aiAnalysis),

      recommendations: [
        {
          category: "Skill Enhancement",
          priority: skillMatch.percentage < 60 ? "High" : "Medium",
          items: skillMatch.missingSkills.slice(0, 3).map(skill => 
            `Incorporate "${skill}" into your experience descriptions`)
        },
        {
          category: "Content Optimization",
          priority: "High",
          items: [
            "Add quantifiable achievements (numbers, percentages, results)",
            "Use stronger action verbs to start bullet points",
            "Tailor content to mirror job description language"
          ]
        }
      ],

      rawAnalysis: aiAnalysis
    };

    res.json({
      success: true,
      message: "Dynamic resume analysis completed",
      data: analysis
    });

  } catch (error) {
    console.error('Resume analysis error:', error);
    res.status(500).json({
      success: false,
      message: 'Error analyzing resume',
      error: error.message
    });
  } finally {
    if (filePath) cleanupFile(filePath);
  }
};

export const generateCoverLetter = async (req, res) => {
  try {
    const { jobTitle, jobDescription, companyName, userName, userSkills, userExperience } = req.body;

    if (!jobTitle?.trim() || !jobDescription?.trim() || !companyName?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Job title, job description, and company name are required'
      });
    }

    const userProfile = {
      name: userName || '[Your Name]',
      skills: userSkills || 'relevant professional skills',
      experience: userExperience || 'professional experience'
    };

    const prompt = PromptBuilder.buildCoverLetterPrompt(jobTitle, companyName, jobDescription, userProfile);
    const coverLetterText = await generateDynamicText(prompt, 800);

    // Extract company insights
    const companyInfo = ContentAnalyzer.extractCompanyInfo(companyName, jobDescription);
    const skillMatch = ContentAnalyzer.extractKeywords(jobDescription);

    const analysis = {
      coverLetter: coverLetterText,
      
      keyHighlights: [
        `Tailored specifically for ${jobTitle} at ${companyName}`,
        `Emphasizes relevant skills: ${skillMatch.slice(0, 3).join(', ')}`,
        `Addresses ${companyInfo.industry} industry requirements`,
        "Professional tone with personalized content"
      ],

      customizationTips: [
        `Research ${companyName}'s recent projects or company news to mention`,
        "Replace placeholder examples with your specific achievements",
        "Add metrics or numbers to quantify your accomplishments",
        companyInfo.values.length > 0 ? 
          `Mention alignment with company values: ${companyInfo.values.join(', ')}` :
          "Research company values and incorporate them naturally"
      ],

      companyInsights: {
        industry: companyInfo.industry,
        detectedValues: companyInfo.values,
        recommendedFocus: skillMatch.slice(0, 5)
      }
    };

    res.json({
      success: true,
      message: "Personalized cover letter generated successfully",
      data: analysis
    });

  } catch (error) {
    console.error('Cover letter generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Error generating cover letter',
      error: error.message
    });
  }
};

export const generateInterviewQuestions = async (req, res) => {
  try {
    const { companyName, jobTitle, jobDescription, experienceLevel } = req.body;

    if (!companyName?.trim() || !jobTitle?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Company name and job title are required'
      });
    }

    const prompt = PromptBuilder.buildInterviewQuestionsPrompt(
      jobTitle, companyName, jobDescription, experienceLevel
    );
    
    const questionsText = await generateDynamicText(prompt, 1500);

    // Extract relevant skills for technical questions
    const technicalSkills = ContentAnalyzer.extractKeywords(jobDescription || '');
    const companyInfo = ContentAnalyzer.extractCompanyInfo(companyName, jobDescription || '');

    const analysis = {
      interviewQuestions: questionsText,
      
      preparationFocus: {
        technicalAreas: technicalSkills.slice(0, 5),
        industryContext: companyInfo.industry,
        experienceLevel: experienceLevel || 'mid-level',
        companyValues: companyInfo.values
      },

      preparationTips: [
        `Research ${companyName}'s recent news, products, and company culture`,
        `Prepare STAR method examples for ${experienceLevel || 'your'} level experience`,
        `Practice explaining your experience with: ${technicalSkills.slice(0, 3).join(', ')}`,
        `Prepare thoughtful questions about the ${jobTitle} role and team structure`
      ],

      companySpecificAdvice: [
        `Study ${companyName}'s mission and values`,
        companyInfo.industry !== 'technology' ? 
          `Understand ${companyInfo.industry} industry trends and challenges` :
          'Stay updated on latest technology trends',
        'Connect with current employees on LinkedIn if possible',
        'Prepare examples that demonstrate cultural fit'
      ]
    };

    res.json({
      success: true,
      message: `Interview preparation generated for ${jobTitle} at ${companyName}`,
      data: analysis
    });

  } catch (error) {
    console.error('Interview questions generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Error generating interview questions',
      error: error.message
    });
  }
};

export const analyzeSuccessProbability = async (req, res) => {
  let filePath = null;

  try {
    const {
      jobDescription, userSkills, experienceYears, 
      education, jobTitle, companyName
    } = req.body;

    let userResume = req.body.userResume;

    if (!jobDescription?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Job description is required'
      });
    }

    // Handle file upload
    if (req.file) {
      filePath = req.file.path;
      userResume = await extractTextFromFile(req.file);
    }

    if (!userResume?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Resume content or file is required'
      });
    }

    const candidateProfile = {
      resume: userResume,
      skills: userSkills,
      experienceYears,
      education
    };

    const prompt = PromptBuilder.buildSuccessAnalysisPrompt(
      candidateProfile, jobDescription, jobTitle, companyName
    );

    const analysisText = await generateDynamicText(prompt, 1500);

    // Calculate dynamic success probability
    const skillMatch = ContentAnalyzer.calculateSkillMatch(userResume, jobDescription);
    const overallScore = ContentAnalyzer.generateDynamicScore(
      userResume, jobDescription, { experienceYears }
    );

    const successProbability = Math.min(
      Math.round((overallScore + skillMatch.percentage) / 2), 
      95
    );

    const analysis = {
      successProbability: `${successProbability}%`,
      confidenceLevel: successProbability >= 80 ? "High" : 
                      successProbability >= 60 ? "Medium" : "Low",

      scoreBreakdown: {
        skillsMatch: `${skillMatch.percentage}%`,
        experienceRelevance: `${Math.min(parseInt(experienceYears) * 15, 100) || 50}%`,
        overallFit: `${overallScore}%`,
        educationAlignment: education ? "Good" : "Not specified"
      },

      keyStrengths: skillMatch.matchedSkills.slice(0, 5),
      improvementAreas: skillMatch.missingSkills.slice(0, 5),

      recommendedActions: [
        skillMatch.percentage < 70 ? 
          `Develop skills in: ${skillMatch.missingSkills.slice(0, 3).join(', ')}` :
          "Continue strengthening your existing skill set",
        
        "Gain specific experience mentioned in the job description",
        `Network with professionals at ${companyName || 'the target company'}`,
        "Prepare compelling examples that demonstrate your value proposition"
      ],

      detailedAnalysis: analysisText
    };

    res.json({
      success: true,
      message: "Success probability analysis completed",
      data: analysis
    });

  } catch (error) {
    console.error('Success probability analysis error:', error);
    res.status(500).json({
      success: false,
      message: 'Error analyzing success probability',
      error: error.message
    });
  } finally {
    if (filePath) cleanupFile(filePath);
  }
};