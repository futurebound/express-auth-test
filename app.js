const dotenv = require('dotenv')
dotenv.config()

const bcrypt = require('bcryptjs')
const path = require('node:path')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

/**
 * Express app setup
 */
const express = require('express')
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

/* ======= Setup PostgreSQL database connection ======= */
const { Pool } = require('pg')
const expressSession = require('express-session')
const pgSession = require('connect-pg-simple')(expressSession)

const pool = new Pool({
  connectionString: process.env.DB_URI,
})

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err)
  } else {
    console.log('Database connected successfully')
  }
})

const sessionStore = new pgSession({
  pool: pool, // Connection pool
  tableName: 'session', // Use another table-name than the default "session" one
  // connect-pg-simple options
  createTableIfMissing: true,
})

sessionStore.on('error', (error) => {
  console.error('Session store error:', error)
})

app.use(
  expressSession({
    store: sessionStore,
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      // 1000ms = 1s, 60s = 1m, 60m = 1hr, 24hr = 1day
      maxAge: 1000 * 60 * 60 * 24,
      secure: false,
    }, // 1 day
  }),
)

// logging middleware to verify session created
app.use((req, res, next) => {
  console.log('Session ID:', req.sessionID)
  console.log('Session:', req.session)
  next()
})

/* =========== Passport Setup ============ */
app.use(passport.initialize())
app.use(passport.session())

app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        const { rows } = await pool.query(
          'SELECT * FROM users WHERE email = $1',
          [email],
        )
        const user = rows[0]

        if (!user) {
          return done(null, false, { message: 'Incorrect email' })
        }
        const match = await bcrypt.compare(password, user.password)
        if (!match) {
          return done(null, false, { message: 'Incorrect password' })
        }
        return done(null, user)
      } catch (err) {
        return done(err)
      }
    },
  ),
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
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [
      req.body.email,
      req.body.password,
    ])
    res.redirect('/')
  } catch (err) {
    return next(err)
  }
})

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  }),
  (req, res) => {
    // Force session save
    req.session.save((err) => {
      if (err) console.error('Session save error:', err)
    })
  },
)

app.get('/logout', (req, res, next) => {
  // req.logout(() => {
  //   res.json({ message: 'Logged out successfully' })
  // })
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
