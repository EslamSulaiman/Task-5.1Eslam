import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// 1. Validation Schema for Login
const loginSchema = Joi.object({
  username: Joi.string().trim().required(),
  password: Joi.string().required()
});

// Helper to project non-sensitive instructor attributes
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
    // Validates inputs to enforce string primitives (blocks Object/Operator injection & Regex extraction)
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: 'Invalid request input' });
    }

    const { username, password } = value;
    const instructor = await Instructor.findOne({ username });

    if (!instructor || instructor.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

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
    const query = req.query || {};
    const filter = {};

    // Safely extract string parameters only (ignores operator objects like $ne and $where)
    if (typeof query.name === 'string') filter.name = query.name.trim();
    if (typeof query.department === 'string') filter.department = query.department.trim();
    if (typeof query.role === 'string') filter.role = query.role.trim();

    // Query database and project non-sensitive fields
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    res.status(200).json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}