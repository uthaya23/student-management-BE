import express from 'express'
import dotenv from 'dotenv'
import'./db.js'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { AdminRouter } from './routes/auth.js'
import { StudentRouter } from './routes/student.js'

const app=express()
app.use(express.json())
app.use(cors())
app.use(cookieParser())
const cors = require('cors');
const corsOptions ={
    origin:'http://localhost:3000', 
    credentials:true,            //access-control-allow-credentials:true
    optionSuccessStatus:200
}
app.use(cors(corsOptions));
dotenv.config()
app.use('/auth',AdminRouter)
app.use('/student', StudentRouter)

app.listen(process.env.PORT,()=>{
    console.log("server is running")
})
