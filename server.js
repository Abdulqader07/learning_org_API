const express = require('express');
const DataBase = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');

const PORT = 3030;
const app = express();

dotenv.config();

const db = DataBase('database2.db');
app.use(express.json());
app.use(cookieParser());

// in testing this error will appear 'app.address is not function' if you don't write the following line..
module.exports = app;

// Enabling foreign keys in better-sqlite3
db.exec(`PRAGMA foreign_keys = ON;`)

// This is our database table for main work..

db.exec(`
    CREATE TABLE IF NOT EXISTS users(
        userid INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
        )
    `);

db.exec(`
    CREATE TABLE IF NOT EXISTS resources(
        resourceid INTEGER PRIMARY KEY AUTOINCREMENT,
        link TEXT NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL,
        userId INTEGER NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(userid)
        )
    `);


// API routes are below this line lol..

app.post('/login', (req, res)=>{
    const {username, password} = req.body;

    if(!username || !password){
        return res.status(400).json({
            message: "There's Data Missing! Please Make Sure You Filled All Data."
        })
    }
    const stmt = db.prepare(`
        SELECT COUNT(*) FROM users WHERE username = ?`);
    const userExsits = stmt.get(username);

    if(userExsits['COUNT(*)'] > 0){
        const getUserStmt = db.prepare(`
            SELECT * FROM users WHERE username = ?`);
        const userName = getUserStmt.get(username);
        
        if(password === userName.password){
            const token = jwt.sign( {userid: userName.userid, role: 'user'} , process.env.SECRET_KEY,
                { expiresIn: '10m' }
            );

            const refreshToken = jwt.sign({userid: userName.userid, role: 'user'}, 
                process.env.REFRESH_TOKEN_SECRET, {expiresIn: '1d'}
            );
            
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true, 
                secure: true,
                sameSite: 'lax'
            });

            res.status(200).json({
                message: `Welcome Back ${username}!`,
                token: token
            });
        }
        else{
            return res.status(400).json({
                message: 'Password Is Invalid.'
            })
        }
    }
    return res.status(404).json({
        message: `There's No User Called ${username}.`
    });
});

app.put('/profile', authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userId = req.user.userid;
    const {username, email} = req.body;

    if(email || username){
        const stmt = db.prepare(`SELECT COUNT(*) FROM resources WHERE email = ? AND userId != ?`);
        const stmtUser = db.prepare(`SELECT COUNT(*) FROM resources WHERE username = ? AND userId != ?`);
        const getStmtEmail = stmt.get(email, userId);
        const getStmtUsername = stmtUser.get(username, userId);

        if(getStmtEmail['COUNT(*)'] === 0){
            const stmtUpdateEmail = db.prepare(`UPDATE resources SET email = ? WHERE userId = ?`);
            stmtUpdateEmail.run(email, userId);
        }
        else{
            res.status(400).json({
                message: 'This Email Is Already Taken'
            });
        }
        if(getStmtUsername['COUNT(*)'] === 0){
            const stmtUpdateUsername = db.prepare(`UPDATE resources SET username = ? WHERE userId = ?`);
            stmtUpdateUsername.run(username, userId);
        }
        else{
            res.status(400).json({
                message: 'This Username Is Already Taken.'
            });
        }

        return res.json({
            update: {
                username: username,
                email: email
            }
        });
        
    }
    return res.status(400).json({
        message: 'Something Went Wrong Please Check Your Date You Sent'
    });
    
});

app.post('/signup', (req, res)=>{
    const {username, email, password, passwordConfirmation} = req.body;

    if(!username || !email || !password || !passwordConfirmation){
        return res.status(400).json({
            message: "There's Data Missing! Please Make Sure You Filled All Data."
        })
    }

    const stmt = db.prepare(`
        SELECT COUNT(*) FROM users WHERE username = ? or email = ?`);
    const userExsits = stmt.get(username, email);

    if(userExsits['COUNT(*)'] > 0){
        return res.status(409).json({
            message: 'This User Already Exsits.'
        });
    }

    if(password === passwordConfirmation){
        const addUserStmt = db.prepare(`
            INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
        addUserStmt.run(username, email, password);

        return res.status(201).json({
            message: 'User Created Successfully.',
            user: {
                username: username,
                email: email,
                password: password
            }
        });
    }
    else{
        return res.status(400).json({
            message: 'Please Check If The Password Is Correct.'
        });
    }
});

const blackList = [];

app.delete('/logout', (req, res)=>{
    const userHeader = req.headers['authorization'];
    const userToken = userHeader && userHeader.split(' ')[1];
    
    if(!userToken){
        return res.status(400).json({
            message: 'User Is Already Logged Out.'
        })
    }

    jwt.verify(userToken, process.env.SECRET_KEY, (error, user)=>{
        if(error){
            return res.status(400).json({
                message: "Missing Token"
            });
        }

        blackList.push(userToken);
        
        res.cookie('token', '',{
            maxAge: 1
        });
    });

});

app.post('/refresh', (req, res)=>{
    const cookieJwt = req.cookies.refreshToken;
    
    if(!cookieJwt){
        return res.status(403).json({
            message: 'Unauthorized'
        });
    }
    jwt.verify(cookieJwt, process.env.REFRESH_TOKEN_SECRET,
        (error, user)=>{
            if(error){
                return res.status(400).json({
                    message: 'Unauthorized'
                });
            }

            const token = jwt.sign({userid: req.user.userid, role: req.user.role}, process.env.SECRET_KEY,
                {expiresIn: '10m'}
            );

            return res.status(201).json({
                message: 'New Token Generated.',
                token: token
            });
        }
    )
    return res.status(400).json({
        message: 'Unauthorized'
    });

});


// Middleware's for authentications and authorizations

function authenticationToken(req, res, next){
    const headerAuth = req.headers['authorization'];
    const token = headerAuth && headerAuth.split(' ')[1];
    if(!token || blackList.includes(token)){
        return res.status(401).json({
            message: 'The Token Is Missing.'
        });
    }
    jwt.verify(token, process.env.SECRET_KEY, (error, user)=>{
        if(error) return res.status(403).json({
            message: 'Invalid or Expired Token.'
        });
        req.user = user;
        next();
    })
};
  

function authorizeRole(...AllowdRoles){
    return (req, res, next) =>{
        if(!req.user || !AllowdRoles.includes(req.user.role)){
            return res.status(403).json({
                message: "You're Not Allowed From This Premission."
            });
        }
        next();
    }
};


app.get('/resources/',authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userid = req.user.userid;
    const stmt = db.prepare(`
        SELECT * FROM resources WHERE userId = ?`);
    
    const resources = stmt.all(userid);
    return res.status(200).json({ resources });
});


// The function that limits the resources add to the DataBase for each status..

const limit = (status) =>{
    const strStatus = status.toString().toLowerCase();

    if(strStatus === 'current'){
        return 3;
    }
    else if(strStatus === 'library'){
        return 10;
    }
    else if(strStatus === 'finished'){
        return 100;
    }
    else{
        return null;
    }
};


app.post('/resources/', authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userId = req.user.userid;
    const {link, name, status} = req.body;

    if(!link || !name || !status){
        return res.status(400).json({
            message: 'There Are Missing Arguments! Please Fill All The Data.'
        });
    }

    const stmt = db.prepare(`
        SELECT COUNT(*) FROM resources WHERE status = ? AND userId = ?`);
    const result = stmt.get(status.toString().toLowerCase(), userId);

    if(limit(status) === null){
        return res.status(400).json({
            message: `There Is No Such A Status Called ${status}.`
        });
    }
    else if(result['COUNT(*)'] < limit(status)){
        const stmt = db.prepare(`
            INSERT INTO resources (link, name, status, userId) VALUES (?, ?, ?, ?)`);
        stmt.run(link, name, status.toString().toLowerCase(), userId);

        return res.status(201).json({
            message: 'Resource Has Been Added.',
            resource : {
                link: link,
                name: name,
                status: status.toString().toLowerCase()
            }
        });
    }
    else{
        return res.status(400).json({ 
            message: `You Reached The Limits Of Adding ${limit(status)} Status.`
         });
    }
});

// Check for a specific resource..

app.get('/resources/:id/', authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userId = req.user.userid;
    const id = parseInt(req.params.id);
    const stmtId = db.prepare(`
        SELECT COUNT(*) FROM resources WHERE id = ? AND userId = ?`);
    const index = stmtId.get(id, userId);

    if(index['COUNT(*)'] === 0){
        return res.status(400).json({
            message: 'Id Does Not Exist.'
        });
    };
    const stmt = db.prepare(`
        SELECT link, name, status FROM resources WHERE id = ? AND userId = ?`);

    const resource = stmt.get(id, userId);
    res.status(200).json({ resource });
});

app.delete('/resources/:id/', authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userId = req.user.userid;
    const id = parseInt(req.params.id);
    const stmtId = db.prepare(`
        SELECT COUNT(*) FROM resources WHERE id = ? AND userId = ?`);
    const index = stmtId.get(id, userId);

    if(index['COUNT(*)'] === 0){
        res.status(400).json({
            message: 'Id Does Not Exist.'
        });
    };

    const stmt = db.prepare(`
        DELETE from resources WHERE id = ? AND userId = ?`)
    stmt.run(id, userId);

    return res.status(200).json({
        message: 'Resource Deleted Successfully'
    });
});

app.put('/resources/:id/', authenticationToken, authorizeRole('user', 'admin'), (req, res)=>{
    const userId = req.user.userid;
    const id = parseInt(req.params.id);
       const stmtId = db.prepare(`
        SELECT COUNT(*) FROM resources WHERE id = ? AND userId = ?`);
    const index = stmtId.get(id, userId);

    if(index['COUNT(*)'] === 0){
        res.status(400).json({
            message: "Id Does Not Exist."
        });
    }

    const {link, name, status} = req.body;

    if(!name || !link || !status){
        return res.status(400).json({
            message: 'There Are Missing Arguments! Please Fill All The Data.'
        });
    }
    const stmtCount = db.prepare(`
        SELECT COUNT(*) FROM resources WHERE status = ? AND userId = ?`);
    const result = stmtCount.get(status.toString().toLowerCase(), userId);

    if(result['COUNT(*)'] < limit(status)){
        const stmt = db.prepare(`
        UPDATE resources SET link = (?), name = (?), status = (?) WHERE id = (?)`);
        stmt.run(link, name, status, id);

        return res.status(201).json({
            message: `Resource Updated, Id: ${id}`,
            resources: {
                link: link,
                name: name,
                status: status.toString().toLowerCase()
            }
        });
    }
    else if(limit(status) === null){
        return res.status(400).json({
            message: `There Is No Such A Status Called ${status}.`
        });
    }
    else{
        return res.status(400).json({
            message: `You Reached The Limits Of Adding ${limit(status)} Status.`
        });
    }
    
});

app.listen(PORT, (error)=>{
    console.log(`listening on port: ${PORT} ..`);
    if(error){
        console.log(error);
    }
});