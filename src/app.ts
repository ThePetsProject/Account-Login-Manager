import express from 'express'
import cors from 'cors'
import { routesArray } from './routes'

const app = express()
const router = express.Router()

app.use(cors())
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.use('/api/v1/account/login', routesArray(router))

export default app
