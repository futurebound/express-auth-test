const dotenv = require('dotenv')
dotenv.config()

const path = require('node:path')
const { Pool } = require('pg')
const express = require('express')
const session = require('express-session')
const passport = require('passport')
const { dot } = require('node:test/reporters')
const LocalStrategy = require('passport-local').Strategy

const pool = new Pool({
  connectionString: process.env.DB_URI,
})

const app = express()
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(session({ secret: 'cats', resave: false, saveUninitialized: false }))
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

app.get('/', (req, res) => res.render('index'))

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`)
})
