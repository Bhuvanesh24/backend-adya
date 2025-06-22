import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const HUGGINGFACE_API_URL = process.env.HF_API_URL; // e.g. "https://api-inference.huggingface.co/models/tiiuae/falcon-7b"
const HUGGINGFACE_API_KEY = process.env.HF_API_KEY;

export const callHuggingFaceModel = async (prompt) => {
  try {
    const response = await axios.post(
      HUGGINGFACE_API_URL,
      {
        inputs: prompt,
        parameters: {
          max_new_tokens: 1024,
          temperature: 0.7,
          top_p: 0.9,
          return_full_text: false
        }
      },
      {
        headers: {
          Authorization: `Bearer ${HUGGINGFACE_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const result = response.data;

    if (Array.isArray(result) && result.length > 0 && result[0].generated_text) {
      return {
        success: true,
        output: result[0].generated_text
      };
    } else {
      return {
        success: false,
        error: 'No valid response from Hugging Face model'
      };
    }

  } catch (error) {
    console.error('Hugging Face API error:', error.response?.data || error.message);
    return {
      success: false,
      error: 'Failed to call Hugging Face API',
      details: error.response?.data || error.message
    };
  }
};
