const app = require('../server');
const request = require('supertest');
const DataBase = require('better-sqlite3');

// Connecting the dataBase
const db = DataBase('database2.db');

// Testing units file

describe("sign up tests", ()=>{

    // test if the user data is valid in signup route
    it("create a user if they don't exist", async () =>{
        const time = new Date();

        const data = {
            "username": `test${time.getMilliseconds()}`,
            "email": `test${time.getMilliseconds()}@test.com`,
            "password": 'password',
            "passwordConfirmation": 'password'
        };
        const response = await request(app).post('/signup').send(data);

        expect(response.statusCode).toBe(201);
    });

    it("reject adding a user if they exists", async () => {
        const data = {
            'username': 'test',
            'email': 'test@test.com',
            'password': 'password',
            'passwordConfirmation': 'password'
        }
        const addUser = await db.prepare(`
            INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
        addUser.run(data['username'], data['email'], data['password']);

        const response = await request(app).post('/signup').send(data);

        expect(response.statusCode).toBe(409);

        const deleteUser = db.prepare(`
            DELETE FROM users WHERE email LIKE ?`);
        deleteUser.run(data['email']);
    });

});