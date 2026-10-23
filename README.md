# Learning Organizer API

An API that lets users add their own learning resources — articles, videos,
courses, whatever. It exists to cut down on the chaos of having too many
things to study at once.

The idea is simple: you can only have a few things "current" at any time,
so you actually finish what you start instead of hoarding tabs.

## Statuses

Every resource has one of three statuses, each with a cap:

- **Current** — what you're studying right now. Limit: 3. This is the whole
  point of the project: a hard cap that forces you to prioritize.
- **Library** — saved for later. Limit: 10.
- **Finished** — what you're done with. Limit: 100.

Each resource has a `name`, `link`, and `status`, and all three can be updated.

## Stack

- Node.js + Express
- SQLite via `better-sqlite3` (parameterized queries throughout)
- JWT access tokens + refresh tokens in HTTP-only cookies
- Token blacklist for logout
- Role-based access (`user`, `admin`)
- Jest + Supertest for integration tests

## API

All `/resources` routes require a `Bearer` token.

| Method | Path              | Auth | Role        | Description                    |
|--------|-------------------|------|-------------|--------------------------------|
| POST   | `/signup`         | no   | —           | Create a user                  |
| POST   | `/login`          | no   | —           | Returns access token, sets refresh cookie |
| POST   | `/refresh`        | no   | —           | Issues a new access token from the refresh cookie |
| DELETE | `/logout`         | yes  | user, admin | Blacklists the current token   |
| PUT    | `/profile`        | yes  | user, admin | Update username / email        |
| GET    | `/resources/`     | yes  | user, admin | List the user's resources      |
| POST   | `/resources/`     | yes  | user, admin | Add a resource (respects status caps) |
| GET    | `/resources/:id/` | yes  | user, admin | Get one resource               |
| PUT    | `/resources/:id/` | yes  | user, admin | Update a resource              |
| DELETE | `/resources/:id/` | yes  | user, admin | Delete a resource              |

## Running it

```bash
npm install
cp .env.example .env      # fill in SECRET_KEY and REFRESH_TOKEN_SECRET
npm start