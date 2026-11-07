import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Validation Schemas
const loginSchema = Joi.object({
  username: Joi.string().trim().required(),
  password: Joi.string().required()
});

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
    // Enforce string primitives (Blocks Attack 1 & Attack 3)
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

    // Safely extract string parameters only (Ignores objects, $ne, $where, etc.)
    if (typeof query.name === 'string') filter.name = query.name.trim();
    if (typeof query.department === 'string') filter.department = query.department.trim();
    if (typeof query.role === 'string') filter.role = query.role.trim();

    // Query database and project non-sensitive fields
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    // Return 200 OK as expected by Attack 2 & Attack 4 test suites
    res.status(200).json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}