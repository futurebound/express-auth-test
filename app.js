const bcrypt = require('bcryptjs')
const dotenv = require('dotenv')
dotenv.config()

const path = require('node:path')
const express = require('express')
const passport = require('passport')
const { dot } = require('node:test/reporters')
const LocalStrategy = require('passport-local').Strategy

const app = express()
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

/* ======= Setup PostgreSQL database connection ======= */
const { Pool } = require('pg')
const expressSession = require('express-session')
const pgSession = require('connect-pg-simple')(expressSession)

const pool = new Pool({
  connectionString: process.env.DB_URI,
})

app.use(
  expressSession({
    store: new pgSession({
      pool: pool, // Connection pool
      tableName: 'user_sessions', // Use another table-name than the default "session" one
      // connect-pg-simple options
      createTableIfMissing: true,
    }),
    secret: process.env.COOKIE_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
    // 1000ms = 1s, 60s = 1m, 60m = 1hr, 24hr = 1day
  }),
)

/* =========== Passport Setup ============ */

app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username],
      )
      const user = rows[0]

      if (!user) {
        return done(null, false, { message: 'Incorrect username' })
      }
      const match = await bcrypt.compare(password, user.password)
      if (!match) {
        return done(null, false, { message: 'Incorrect password' })
      }
      return done(null, user)
    } catch (err) {
      return done(err)
    }
  }),
)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id])
    const user = rows[0]

    done(null, user)
  } catch (err) {
    done(err)
  }
})

/* =========== VIEWS ============ */

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

/* =========== ROUTES =========== */

app.get('/', (req, res) => {
  res.render('index', { user: req.user })
})

app.get('/sign-up', (req, res) => res.render('sign-up-form'))
app.post('/sign-up', async (req, res, next) => {
  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err)
      }
    })
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
      req.body.username,
      req.body.password,
    ])
    res.redirect('/')
  } catch (err) {
    return next(err)
  }
})

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  }),
)

app.get('/log-out', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

/**
 *  ---------------- SERVER ---------------
 */
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`)
})
