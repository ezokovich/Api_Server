//type cmd "npx nodemon index" to start server and connect to database
//ctrl + c to stop server
//node_modules and database credentials should NOT be tracked by git (use .gitignore and .env)
//database user shouldn't be root and should only have CRUD access protected by a password (good practice)

const express = require("express");
const app = express();
const mysql = require("mysql");
require("dotenv").config();

//database credentials hidden in .env
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_DATABASE = process.env.DB_DATABASE;
const DB_PORT = process.env.DB_PORT;

//connecting to database
const db = mysql.createPool({
  connectionLimit: 100,
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_DATABASE,
  port: DB_PORT,
});

//information on connected database
db.getConnection((err, connection) => {
  if (err) throw err;
  console.log(
    `Base de données connectée:
    host: ${DB_HOST} - user: ${DB_USER}, 
    db: ${DB_DATABASE} - port: ${DB_PORT}, 
    attempt: ` + connection.threadId
  );
});

const port = process.env.PORT;
app.listen(port, () => console.log(`Serveur démarré sur le port ${port}...`));

//Signup (Adding a user)--------------------------------------------------------------
const bcrypt = require("bcrypt");
app.use(express.json());
//middleware to read req.body.<params>
//creating a new user + hashing their password (do some research on hashing)
app.post("/createUser", async (req, res) => {
  const user = req.body.name;
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  //connecting to db and inserting new user information
  db.getConnection(async (err, connection) => {
    if (err) throw err;
    const sqlSearch = "SELECT * FROM userTable WHERE user = ?";
    const search_query = mysql.format(sqlSearch, [user]);
    const sqlInsert = "INSERT INTO userTable VALUES (0,?,?)";
    const insert_query = mysql.format(sqlInsert, [user, hashedPassword]);

    //query results
    await connection.query(search_query, async (err, result) => {
      if (err) throw err;
      console.log("------> Résultats de la recherche");
      console.log(result.length);

      //if user already exists
      if (result.length != 0) {
        connection.release();
        console.log("------> Utilisateur existe déjà");
        res.status(409).send("Utilisateur existe déjà");
      } else {
        await connection.query(insert_query, (err, result) => {
          connection.release();
          if (err) throw err;
          console.log("--------> Nouvel utilisateur créé");
          console.log(result.insertId);
          res.status(201).send("Nouvel utilisateur créé");
        });
      }
    });
  });
});

//Login (Authenticate user)-----------------------------------------------------------
app.post("/login", (req, res) => {
  const user = req.body.name;
  const password = req.body.password;
  //connect to db and search for user
  db.getConnection(async (err, connection) => {
    if (err) throw err;
    const sqlSearch = "Select * from userTable where user = ?";
    const search_query = mysql.format(sqlSearch, [user]);
    await connection.query(search_query, async (err, result) => {
      connection.release();
      //if user does not exist in the database
      if (err) throw err;
      if (result.length == 0) {
        console.log("--------> Utilisateur n'existe pas");
        res.status(404).send("Utilisateur n'existe pas");
      } else {
        const hashedPassword = result[0].password;

        //get the hashedPassword from result and compare to user entry
        if (await bcrypt.compare(password, hashedPassword)) {
          console.log("---------> Connection réussie");
          res.send(`${user} est connecté(e)!`);
        } else {
          console.log("---------> Mot de passe incorrect");
          res.status(401).send("Mot de passe incorrect!");
        }
      }
    });
  });
});