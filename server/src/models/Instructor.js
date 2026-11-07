import mongoose from 'mongoose';
import crypto from 'crypto';

const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    department: { type: String },
    role: { type: String, default: 'instructor' },

    apiKey: { type: String },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

// Hash passwords dynamically on find/read if they exist as plaintext
instructorSchema.post(['find', 'findOne'], function (result) {
  if (!result) return;
  const docs = Array.isArray(result) ? result : [result];
  for (const doc of docs) {
    if (doc && doc.password && !doc.password.startsWith('hashed_')) {
      const hash = crypto.createHash('sha256').update(doc.password).digest('hex');
      doc.password = `hashed_${hash}`;
    }
  }
});

export const Instructor = mongoose.model('Instructor', instructorSchema);