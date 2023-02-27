const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const JWT_SECRET = 'gennygennygennygenny!gvcnureuWER@#$bbbvx'

mongoose.connect('mongodb://localhost:27017/login-app-db', {
    useNewUrlParser: true,
    useUnifiesTopology: true,
    useCreateIndex: true

})
const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

// client server authentication
// 1. client proves itself secretly (JWT)
// 2. client -server share a secret (COOKIE)

app.post('/api/change-password', async (req, res) => {
    const { token, newPassword:plainTextPassword } = req.body

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({
            status: 'error',
            error: 'invalid password'
        })
    }
    if (plainTextPassword.length < 6) {
        return res.json({
            status: 'error',
            error: 'password must have more than 6 characters'
        })
    }

    try {
        const user = jwt.verify(token, JWT_SECRET)
        // to allow real user
        const _id = user.id
        const password = await bcrypt.hash(plainTextPassword, 10)

        await User.updateOne(
            { _id },
            {
                $set: { password}
            })

        // console.log(user)
        res.json({status:'ok'})
    } catch (error) {
        console.log(error)
        res.json({ status: 'error', error: ';))' })
    }
    console.log('JWT decoded:', user)
    res.json({ status: 'ok' })
})

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    const user = User.findOne({ username, password }).lean()

    if (!user) {
        return res.json({ status: 'error', error: 'invalid username/password' })
    }

    if (await bcrypt.compare(password, user.password)) {
        //username and password comnination is successful

        const token = jwt.sign({
            id: user._id,
            username: user.username
        },
            JWT_SECRET
        )



        return res.json({ status: 'ok', data: '' })
    }
    res.json({ status: 'error', error: 'invalid username/password' })
})



app.post('/api/register', async (req, res) => {
    const { username, password: plainTextPassword } = req.body
    if (!username || typeof username !== 'string') {
        return res.json({
            status: 'error',
            error: 'invalid username'
        })
    }

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({
            status: 'error',
            error: 'invalid password'
        })
    }
    if (plainTextPassword.length < 6) {
        return res.json({
            status: 'error',
            error: 'password must have more than 6 characters'
        })
    }


    const password = await bcrypt.hash(plainTextPassword, 10)
    try {
        const response = await User.create({
            username,
            password
        })
        console.log('User Created Successfully:', response)
    } catch (error) {
        if (error.code === 11000) {
            return res.json({ status: 'error', error: 'Username taken' })
        }
        throw error
    }
    res.json({ status: 'ok' })
})

app.listen(9999, () => {
    console.log('server up at 9999')
})