# Auth Testing with PassportJS

Playground to explore authentication methods for Express projects with Passport.

## Installation

```bash
pnpm install
```

## Setup

```bash
pnpm add bcrypt express express-session pg passport passport-local ejs
```

Create a `users` table in PostgreSQL:

```SQL
CREATE TABLE users (
  id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  username VARCHAR ( 255 ),
  password VARCHAR ( 255 )
);
```
