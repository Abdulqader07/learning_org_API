const app = require('../server');
const request = require('supertest');

// Testing units file

describe("authorization and authentication unit tests", ()=>{
    const time = new Date();

    // test if the user data is valid in signup route
    it("signup tokens are created", async () =>{
        const data = {
            "username": `test${time.getMilliseconds()}`,
            "email": `test${time.getMilliseconds()}@test.com`,
            "password": 'password',
            "passwordConfirmation": 'password'
        };
        const response = await request(app).post('/signup').send(data);

        expect(response.statusCode).toBe(201);
    })

});