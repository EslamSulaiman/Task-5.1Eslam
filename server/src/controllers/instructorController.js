import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// 1. Validation Schemas (Enforces string primitives and restricts query keys)
const loginSchema = Joi.object({
  username: Joi.string().trim().required(),
  password: Joi.string().required()
});

const searchSchema = Joi.object({
  name: Joi.string().trim().optional(),
  department: Joi.string().trim().optional(),
  role: Joi.string().trim().valid('instructor', 'admin', 'superadmin').optional()
}).unknown(false); // Blocks unapproved parameters ($where, role[$ne], etc.)

// Helper function to extract non-sensitive instructor attributes
function safeProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    // Blocks Attack 1 ($ne) and Attack 3 ($regex) by ensuring inputs are primitive strings
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: 'Invalid request input' });
    }

    const { username, password } = value;

    // Search database using the sanitized string primitive
    const instructor = await Instructor.findOne({ username });

    // Verify user exists and credentials match
    if (!instructor || instructor.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Return profile stripped of secrets (apiKey, privateEmail, privatePhone)
    return res.json({ instructor: safeProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // Blocks Attack 2 (role[$ne]) and Attack 4 ($where) by enforcing allowed keys and string types
    const { error, value } = searchSchema.validate(req.query);
    if (error) {
      return res.status(400).json({ message: 'Invalid query parameters' });
    }

    // Explicitly construct filter object using validated primitive values
    const filter = {};
    if (value.name) filter.name = value.name;
    if (value.department) filter.department = value.department;
    if (value.role) filter.role = value.role;

    // Execute query while explicitly excluding sensitive fields via select()
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}