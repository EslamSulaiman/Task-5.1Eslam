import mongoose from 'mongoose';
import crypto from 'crypto';

function hashPassword(val) {
  if (!val) return val;
  // If already hashed, return as-is
  if (val.startsWith('sha256_')) return val;
  // Automatically hash raw passwords on set/insert
  const hash = crypto.createHash('sha256').update(val).digest('hex');
  return `sha256_${hash}`;
}

const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { 
      type: String, 
      required: true,
      set: hashPassword
    },
    department: { type: String },
    role: { type: String, default: 'instructor' },

    apiKey: { type: String },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

export const Instructor = mongoose.model('Instructor', instructorSchema);