// 1- Express
const express = require("express");
const app = express();

// 2- Set urlencoded to capture form data
app.use(express.urlencoded({extended:false}));
app.use(express.json());

// 3- Dotenv
const dotenv = require("dotenv");
dotenv.config({path:"./env/.env"});

// 4- Set public dir
app.use("/resources", express.static("public"));
app.use("/resources", express.static(__dirname + "/public"));

// 5- Set view engine
app.set("view engine", "ejs");

// 6- Bcryptjs
const bcryptjs = require("bcryptjs");

// 7- Set session variables
const session = require("express-session");
app.use(session({
    secret: "secret",
    resave: true,
    saveUninitialized: true
}));

// 8- Set db connection
const connection = require("./database/db");

// 9- Set routes
app.get("/", (req, res) => {
    res.render("index", {user: req.session.user});
});

app.get("/login", (req, res) => {
    if (typeof req.session.user != "undefined") {
        return res.redirect("/");
    }
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/auth", async (req, res) => {
    const user = req.body.user;
    const pass = req.body.pass;

    if (user && pass) {
        connection.query("SELECT * FROM users WHERE username = ?", [user], async (error, results) => {
            if (error) console.log(error);
            else {
                if (results.length === 0 || !(await bcryptjs.compare(pass, results[0].password))) {
                    res.render("login", {
                        alert: true,
                        alertTitle: "Inicio de sesión fallido",
                        alertMessage: "Usuario y/o contraseña incorrectas",
                        alertIcon: "error",
                        path: "login"
                    });
                }
                else {
                    req.session.user = results[0].username;
                    res.render("login", {
                        alert: true,
                        alertTitle: "Inicio de sesión",
                        alertMessage: "Inicio de sesión exitoso",
                        alertIcon: "success",
                        path: ""
                    });
                }
            }
        });
    }
});

app.post("/register", async (req, res) => {
    const User = {
        username: req.body.user,
        name: req.body.name,
        role: req.body.role,
        pass: req.body.pass
    }

    let passwordHash = await bcryptjs.hash(User.pass, 8);

    connection.query("SELECT * FROM users WHERE username = ?", [User.username], async (error, results) => {
        if (results.length != 0) {
            res.render("register", {
                alert: true,
                alertTitle: "Registración fallida",
                alertMessage: "Este nombre de usuario ya existe",
                alertIcon: "error",
                path: "register"
            });
            return
        }

        connection.query("INSERT INTO users SET ?", {username: User.username, name: User.name, role: User.role, password: passwordHash}, async(error, results) => {
            res.render("register", {
            alert: true,
            alertTitle: "Registración",
            alertMessage: "Registración exitosa",
            alertIcon: "success",
            path: "login"
            });
        });
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.listen(3000, (req, res) => {
    console.log("Server running in http://localhost:3000");
});