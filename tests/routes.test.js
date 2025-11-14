const app = require('../server');
const request = require('supertest');
const DataBase = require('better-sqlite3');

// Connecting the dataBase
const db = DataBase('database2.db');

// Testing units file

describe("sign up tests", () => {

    describe("no missing arguments test", () => {
            
        const data = {
            'username': 'testusername',
            'email': 'testemail@test.com',
            'password': 'password',
            'passwordConfirmation': 'password'
        };

        beforeEach(() => {
            const stmt = db.prepare(`
                INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
            stmt.run(data['username'], data['email'], data['password']);
        });

        afterEach(() => {
            const stmt = db.prepare(`
                DELETE FROM users`);
            stmt.run();
        });

        it("create a user if they doesn't exist", async () =>{
            const newUser = {
                'username': 'newtest',
                'email': 'newtest@test.com',
                'password': 'password',
                'passwordConfirmation': 'password'
            };

            const response = await request(app).post('/signup').send(newUser);
            expect(response.statusCode).toBe(201);
        });

        it("reject adding a user if they exists", async () => {
            const existingUser = {
                'username': 'test',
                'email': 'test@test.com',
                'password': 'password',
                'passwordConfirmation': 'password'
            }
            const addUser = await db.prepare(`
                INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
            addUser.run(existingUser['username'], existingUser['email'], existingUser['password']);

            const response = await request(app).post('/signup').send(existingUser);

            expect(response.statusCode).toBe(409);
        });
    })

    it("wrong password when signup", async () => {
        const data = {
            'username': 'testusername',
            'email': 'testemail@test.com',
            'password': 'password',
            'passwordConfirmation': 'Password'
        }
        const response = await request(app).post('/signup').send(data);
        expect(response.statusCode).toBe(400);
    });

    it('missing information when signup', async () => {
        const data = {
            'username': 'testusername'
        }
        const response = await request(app).post('/signup').send(data);
        expect(response.statusCode).toBe(400);
    });

});

describe("Login tests", () => {
    const data = {
        'username': 'testusername',
        'email': 'testemail@test.com',
        'password': 'password',
    };
        
    beforeEach(() => {
        // Adding a user to the database to login..
        const signedUser = db.prepare(`
            INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
        signedUser.run(data['username'], data['email'], data['password']);
    });
    afterEach(() => {
        // Free the user from the database..
        const deleteUser = db.prepare(`
            DELETE FROM users WHERE email LIKE ?`);
        deleteUser.run(data['email']);
    });

    it('successful user login', async () => {
        const response = await request(app).post('/login').send(data);
        expect(response.statusCode).toBe(200);
    });

    it('check if the token exists in the headers', async () => {
        const loginResponse = await request(app).post('/login').send(data);
        expect(loginResponse.body.token).toBeDefined();

        // Logout 
        const logoutResponse = await request(app).delete('/logout');
        expect(logoutResponse.body.token).toBeUndefined();

    });

    it('test if missing information will create a token', async () => {
        const missingData = {
            'username': 'testusername'
        }
        const response = await request(app).post('/login').send(missingData);
        expect(response.body.token).toBeUndefined();
    })
})