import mongoose from "mongoose"
const studentSchema = new mongoose.Schema(
    {
        Student_id:{
            type:String,
            required:true,
            unique:true
        },
         Student_name:{
            type:String,
            required:true,
         },
         Student_age:{
            type:Number,
            required:true,
         },
         Student_address:{
            type:String,
            required:true,},
         Student_mobileNo:{
            type:Number,
            required:true,},
        Student_disease:{
            type:String,
            required:true,},
         }
)
const studentModel=mongoose.model('Student',studentSchema)
export {studentModel as Student}