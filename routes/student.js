import express from 'express';
import { Student } from '../models/StudentModel.js'; // Ensure this path is correct
import { verifyAdmin } from './auth.js';
const router = express.Router();

// Route to add a student
router.post('/add', verifyAdmin, async (req, res) => {
    console.log("added")
    const { Student_id, Student_name, Student_age, Student_address, Student_mobileNo, Student_disease } = req.body;

    try {
        const existingStudent = await Student.findOne({ Student_id });
        if (existingStudent) {
            return res.status(400).json({ message: 'Student ID already exists' });
        }

        const newStudent = new Student({
            Student_id,
            Student_name,
            Student_age,
            Student_address,
            Student_mobileNo,
            Student_disease,
        });

        await newStudent.save();
        res.status(201).json({ message: 'Student added successfully', student: newStudent });
    } catch (error) {
        console.error('Error adding student:', error);
        res.status(500).json({ message: 'Server error while adding student' });
    }
});

router.get('/total', verifyAdmin, async (req, res) => {
    try {
        const totalStudents = await Student.countDocuments({});
        res.json({ totalStudents });
    } catch (error) {
        console.error('Error fetching student count:', error);
        res.status(500).json({ message: 'Server error while fetching student count' });
    }
});

// Route to get all students
router.get('/all', async (req, res) => {
    try {
        const students = await Student.find({});
        res.json(students);
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to update a student by ID
// Route to update a student by ID
router.put('/:id', verifyAdmin, async (req, res) => {
    const studentId = req.params.id;
    const updatedData = req.body; // Data to update
  
    try {
      const updatedStudent = await Student.findOneAndUpdate({ Student_id: studentId }, updatedData, { new: true });
      
      if (!updatedStudent) {
        return res.status(404).json({ message: 'Student not found' });
      }
  
      res.json({ message: 'Student updated successfully', student: updatedStudent });
    } catch (error) {
      console.error('Error updating student:', error);
      res.status(500).json({ message: 'Server error' });
    }
});

// Route to get a student by ID
router.get('/:id',verifyAdmin, async (req, res) => {
    console.log(`Fetching student with ID: ${req.params.id}`);
    try {
        const student = await Student.findOne({ Student_id: req.params.id });
        if (!student) {
            console.log('Student not found');
            return res.status(404).json({ message: 'Student not found' });
        }
        console.log('Student found:', student);
        res.json(student);
    } catch (error) {
        console.error('Error fetching student:', error);
        res.status(500).json({ message: 'Error fetching student details' });
    }
});

// Route to get a student by ID
router.delete('/:id', verifyAdmin, async (req, res) => {
    const studentId = req.params.id;

    try {
        const result = await Student.findOneAndDelete({ Student_id: studentId });

        if (!result) {
            return res.status(404).json({ message: 'Student not found' });
        }

        res.json({ message: 'Student deleted successfully' });
    } catch (error) {
        console.error('Error deleting student:', error);
        res.status(500).json({ message: 'Server error while deleting student' });
    }
});


export { router as StudentRouter };
