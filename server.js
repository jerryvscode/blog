// NPM Packete

// Kopiert aus Back-End-Tutorial von...
require("dotenv").config()
const fork = require('child_process').fork
const multer = require("multer")
const jwt = require("jsonwebtoken")
const marked = require("marked")
const sanitizeHTML = require("sanitize-html")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const express = require("express")
const db= require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")
// ...bis




// SQLite Setup

// Kopiert aus Back-End-Tutorial von...
const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run()

  db.prepare(`
    CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    article TEXT NOT NULL,
    likes INTEGER,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
  `).run()
// ...bis

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS articlewishes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email STRING,
    articlewish STRING NOT NULL
    )
    `
  ).run()

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS writers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    writer STRING NOT NULL
    )
    `
  ).run()

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS adminemail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adminemail STRING NOT NULL
    )
    `
  ).run()

  const usersStatement = db.prepare("SELECT username FROM users ORDER BY id ASC")
  const users = usersStatement.all()

  users.forEach(users => {
    db.prepare(
    `
    CREATE TABLE IF NOT EXISTS ${users.username} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    likedArticles STRING NOT NULL
    )
    `
    ).run()
  })
})

createTables()



// NPM Packete verwenden

// Kopiert aus Back-End-Tutorial von...
const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(express.static("pictures"))
app.use(cookieParser())
/////

// Middleware

// Kopiert aus Back-End-Tutorial von...
app.use(function (req, res, next) {
  // Markdownfunktion aktivieren
  res.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
      allowedAttributes: {}
    })
  }

  // Cookie überprüfen
  res.locals.errors = []

  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user = decoded
  } catch (err) {
    req.user = false
  }

  res.locals.user = req.user
  console.log(req.user)

  next()
})
// ...bis



// Funktionen

/////
// Muss Admin sein
function mustBeAdmin(req, res, next) {
  if (req.user.userid == "1") {
    return next()
  }
  return res.redirect("/")
}

function mustBeWriter(req, res, next) {
  const searchWriter = db.prepare("SELECT writer FROM writers WHERE writer = ?")
  const writer = searchWriter.get(req.user.username)
  
  if (!writer) {
    return res.redirect("/")
  } else {
    next()
  }
}

function mustBeLoggedIn(req, res, next) {
  const loggedInStatement = db.prepare(`SELECT username FROM users WHERE id = ?`)
  const loggedIn = loggedInStatement.get(req.user.userid)
  const loggedInCheckFalse = !loggedIn

  if (loggedInCheckFalse) {
    return res.redirect("/account.ejs")
  } else {
    return next()
  }
}

// Überprüfung bei Artikelerstellung

// Kopiert aus Back-End-Tutorial von...
function sharedArticleValidation(req) {
  const errors = []

  if(typeof req.body.title !== "string") req.body.title = ""
  if(typeof req.body.article !== "string") req.body.article = ""

  // Schutz for Angriffen
  req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}})
  req.body.article = sanitizeHTML(req.body.article.trim(), {allowedTags: [], allowedAttributes: {}})

  if (!req.body.title) errors.push("Titel- und Artikelfeld müssen ausgefüllt sein.")
  return errors
  }
// ...bis




// GET requests
// Direkt kopiert aus Back-End-Tutorial von...
app.get("/", (req, res) => {
  const articlesStatement = db.prepare("SELECT * FROM articles ORDER BY createdDate DESC")
  const articles = articlesStatement.all()
  res.render("index", { articles })
})
// ...bis

app.get("/articlewish.ejs", (req, res) => {
  res.render("articlewish")
})

app.get("/contact.ejs", (req, res) => {
  searchAdmin = db.prepare("SELECT username FROM users WHERE id = 1")
  admin = searchAdmin.get()

  searchAdminEmail = db.prepare("SELECT adminemail FROM adminemail WHERE Rowid = 1")
  adminEmail = searchAdminEmail.get()

  res.render("contact", {admin, adminEmail})
})

app.get("/account.ejs", (req, res) => {
  res.render("account")
})

app.get("/login.ejs", (req, res) => {
  res.render("login")
})

app.get("/register.ejs", (req, res) => {
  res.render("register")
})

app.get("/dashboard.ejs", (req, res) => {
  const searchWriter = db.prepare("SELECT writer FROM writers WHERE writer = ?")
  const writer = searchWriter.get(req.user.username)

  const isNotWriter = !writer

  res.render("dashboard", {isNotWriter})
})

app.get("/change-logo.ejs", (req, res) => {
  res.render("change-logo")
})


app.get ("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp")
  res.redirect("/account.ejs")
})

app.get("/dashboard-admin.ejs", mustBeAdmin, (req, res) => {
  userLookUp = db.prepare("SELECT * FROM users WHERE id = ?")
  user = userLookUp.get(req.user.userid)

  res.render("dashboard-admin", {user})
})

app.get("/writers.ejs", mustBeAdmin, (req, res) => {
  // Schreiber aus Datenbank "holen"
  const writerStatement = db.prepare("SELECT * FROM writers ORDER BY id ASC")
  const writers = writerStatement.all()
  res.render("writers", {writers})
})

app.get("/create-article", mustBeWriter, (req, res) => {
  res.render("create-article")
})

app.get("/change-username", (req, res) => {
  res.render("change-username")
})

app.get("/change-password", (req, res) => {
  res.render("change-password")
})

app.get("/articlewishes-list.ejs", mustBeWriter, (req, res) => {
  // Artikelwünsche aus Datenbank "holen"
  const articlewishStatement = db.prepare("SELECT * FROM articlewishes ORDER BY id ASC")
  const articlewishes = articlewishStatement.all()
  res.render("articlewishes-list", { articlewishes })
})

app.get("/security-info.ejs", (req, res) => {
  res.render("security-info")
})

// "Artikel bearbeiten"-Seite
// Abgewandelt opiert aus Back-End-Tutorial von...
app.get("/edit-article/:id", mustBeWriter, (req, res) => {
  // Artikel in Datenbank suchen
  const statement = db.prepare("SELECT * FROM articles WHERE id = ?")
  const article = statement.get(req.params.id)

  if (!article) {
    return res.redirect("/")
  }

  // Zugriff nur erlauben, wenn Autor
  if (article.authorid !== req.user.userid && req.user.userid !== 1) {
    return res.redirect("/")
  }

  res.render("edit-article", { article: article })
})
// ...bis

// Artikel öffnen
// Direkt kopiert aus Back-End-Tutorial von...
app.get("/article/:id", (req, res) => {
  // Artikel in Datenbank suchen
  const statement = db.prepare("SELECT articles.*, users.username FROM articles INNER JOIN users ON articles.authorid = users.id WHERE articles.id = ?")
  const article = statement.get(req.params.id)

  if (!article) {
    return res.redirect("/")
  }

  // Herausfinden, ob Benutzer der Autor ist
  const isAuthor = article.authorid === req.user.userid
  const userid = req.user.userid

  const likesStatement = db.prepare(`SELECT likes FROM articles WHERE id = ?`)
  const likes = likesStatement.get(req.params.id)

  res.render("single-article", {article: article, isAuthor, userid, likes})
})
// ...bis


// POST requests

app.post("/like-article/:id", mustBeLoggedIn, (req, res) => {
  const alreadyLikedStatement = db.prepare(`SELECT likedArticles FROM ${req.user.username} WHERE likedArticles = ?`)
  const alreadyLiked = alreadyLikedStatement.get(req.params.id)
  const alreadyLikedCheckFalse = !alreadyLiked

  if (alreadyLikedCheckFalse) {
    const addLike = db.prepare(`UPDATE articles SET likes = likes + 1 WHERE id = ?`)
    addLike.run(req.params.id)

    saveLikingUser = db.prepare(`INSERT INTO ${req.user.username} (likedArticles) VALUES (?)`)
    saveLikingUser.run(req.params.id)
  } else {
    const removeLike = db.prepare(`UPDATE articles SET likes = likes - 1 WHERE id = ?`)
    removeLike.run(req.params.id)

    removeLikingUser = db.prepare(`DELETE FROM ${req.user.username} WHERE likedArticles = ?`)
    removeLikingUser.run(req.params.id)
  }
  
  res.redirect(`/article/${req.params.id}`)
})

app.post("/articlewish-input", (req, res) => {
  let errors = []

  if (!req.body.email) {
    req.body.email = "-"
  }
  if (!req.body.articlewish) {
    errors = ["Artikelwunschfeld muss ausgefüllt sein."]
    return res.render("articlewish.ejs", {errors})
  } else {
  const saveArticlewish = db.prepare("INSERT INTO articlewishes (email, articlewish) VALUES (?, ?)")
  saveArticlewish.run(req.body.email, req.body.articlewish)
  }

  res.redirect("/articlewish.ejs")
})

// Loginbutton gedrückt
//ed
app.post("/login", (req, res) => {
  // Überprüfung der Loginangaben
  const errors = []

  if (req.body.username.trim() == "") {errors.push("Bitte Benutzername eingeben."); return res.render("login", {errors})}
  if (req.body.password.trim() == "") {errors.push("Bitte Passwort eingeben."); return res.render("login", {errors})}

  if (typeof req.body.username !== "string") {req.body.username = ""; errors.push("Der Benutzername muss Textformat haben."); return res.render("login", {errors})}
  if (typeof req.body.password !== "string") {req.body.password = ""; errors.push("Das Passwort muss Textformat haben."); return res.render("login", {errors})}

  const userInQuestionStatement = db.prepare("Select * FROM users Where USERNAME = ?")
  const userInQuestion = userInQuestionStatement.get(req.body.username)

  if (!userInQuestion) {
    errors.push("Invalieder Benutzername")
    return res.render("login", {errors})
  }

  const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
  if (!matchOrNot) {
    errors.push("Invaliedes Passwort")
    return res.render("login", {errors})
  }

  // Cookie generieren
  const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username}, process.env.JWTSECRET)

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  res.redirect("/")
})
/////

let whichPicture = ""
function logoPicture(req, res, next) {
  whichPicture = "logo"
  next()
}
function thumbnailPicture(req, res, next) {
  whichPicture = "thumbnail"
  next()
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (whichPicture === "logo") {
      cb(null, `pictures/logo`);
    }
    if (whichPicture === "thumbnail") {
      cb(null, 'pictures/articles');
    }
  },
  filename: function (req, file, cb) {
    if (whichPicture === "logo") {
      cb(null, `logo.jpg`)
    }
    if (whichPicture === "thumbnail") {
      cb(null, `${realArticle.id}.jpg`)
    }
  },
})
const upload = multer({storage})

app.post("/upload-logo", mustBeWriter, logoPicture, upload.single("logo"), (req, res) => {
  return res.redirect("/")
})

app.post("/change-username", (req, res) => {
  const errors = []

  req.body.newusername = req.body.newusername.trim()
  if (typeof req.body.newusername !== "string") {req.body.newusername = ""; errors.push("Der Benutzername muss Textformat haben."); return res.render("change-username", {errors})}
  else if (!req.body.newusername) {errors.push("Es muss ein Benutzername eingegeben werden."); return res.render("change-username", {errors})}
  else if (req.body.newusername.length == 1 || req.body.newusername.length == 2) {errors.push("Der Benutzername muss mindestens 3 Zeichen lang sein."); return res.render("change-username", {errors})}
  else if (req.body.newusername.length > 20) {errors.push("Der Benutzername darf nicht länger als 20 Zeichen sein."); return res.render("change-username", {errors})}
  else if (!req.body.newusername.match(/^[a-zA-Z0-9]+$/)) {errors.push("Nur Buchstaben und Zahlen sind erlaubt im Benutzernamen."); return res.render("change-username", {errors})}

  const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
  const usernameCheck = usernameStatement.get(req.body.newusername)

  if (usernameCheck) {errors.push("Dieser Benutzername existiert schon."); return res.render("change-username", {errors})}
  else {
    const changeStatement = db.prepare("UPDATE users SET username = ? WHERE id = ?")
    changeStatement.run(req.body.newusername, req.user.userid)
    return res.redirect("/dashboard-admin.ejs")
  }
})

app.post("/change-password", (req, res) => {
  const errors = []

  if (req.body.newpassword !== req.body.newpasswordcheck) {
    errors.push("Passwörter stimmen nicht überein.")
    return res.render("change-password", {errors})
  } else if (req.body.newpassword == "") {
    errors.push("Es muss ein Passwort eingegeben werden.")
    return res.render("change-password", {errors})
  } else {
    const salt = bcrypt.genSaltSync(10)
    req.body.newpassword = bcrypt.hashSync(req.body.newpassword, salt)
    const changeStatement = db.prepare("UPDATE users SET password = ? WHERE id = ?")
    changeStatement.run(req.body.newpassword, req.user.userid)
    return res.render("dashboard-admin")
  }
})

app.post("/admin-email", mustBeAdmin, (req, res) => {
  const changeAdminEmail = db.prepare("UPDATE adminemail SET adminemail = ? WHERE Rowid = 1")
  changeAdminEmail.run(req.body.adminemail)
  res.redirect("/contact.ejs")
})


// Artikelveröffentlichungsbutton gedrückt
/////

let realArticle = ""

app.post("/create-article", mustBeWriter, (req, res) => {
  // Überprüfung des Artikels
  const errors = sharedArticleValidation(req)

  if (errors.length) {
    return res.render("create-article", { errors })
  }

  // Artikel in Datenbank speichern
  const ourStatement = db.prepare("INSERT INTO articles (title, article, likes, authorid, createdDate) VALUES (?, ?, 0, ?, ?)")
  const result = ourStatement.run(req.body.title, req.body.article, req.user.userid, new Date().toISOString())

  const getArticleStatement = db.prepare("SELECT * FROM articles WHERE ROWID = ?")
  realArticle = getArticleStatement.get(result.lastInsertRowid)
  
  res.render("upload-picture")
})
/////

app.post("/save-picture", mustBeWriter, thumbnailPicture, upload.single("picture"), (req, res) => {
  return res.redirect(`/article/${realArticle.id}`)
})



app.post("/add-writer", mustBeAdmin, (req, res) => {
  const ourStatement = db.prepare("INSERT INTO writers (writer) VALUES (?)")
  ourStatement.run(req.body.addwriter)
  res.render("dashboard-admin")
})

app.post("/remove-writer", mustBeAdmin, (req, res) => {
  const deleteStatement = db.prepare("DELETE FROM writers WHERE writer = ?")
  deleteStatement.run(req.body.removewriter)
  res.render("dashboard-admin")
})



// "Artikel bearbeiten"-veröffentlichenbutton gedrückt
/////
app.post("/edit-article/:id", mustBeWriter, (req, res) => {
  // Artikel in Datenbank suchen
  const statement = db.prepare("SELECT * FROM articles WHERE id = ?")
  const article = statement.get(req.params.id)

  if (!article) {
    return res.redirect("/")
  }

  // Artikel in Datenbank suchen
  if (article.authorid !== req.user.userid && req.user.userid !== 1) {
    return res.redirect("/")
  }

  // Errorüberprüfung
  const errors = sharedArticleValidation(req)

  if (errors.length) {
    return res.render("edit-article", { errors })
  }

  // Artikel bearbeiten
  const updateStatement = db.prepare("UPDATE articles SET title = ?, article = ? WHERE id = ?")
  updateStatement.run(req.body.title, req.body.article, req.params.id)

  res.redirect(`/article/${req.params.id}`)
})
/////

// "Artikel löschen"-button gedrückt
/////
app.post("/delete-article/:id", mustBeWriter, (req, res) => {
  // Artikel in Datenbank suchen
  const statement = db.prepare("SELECT * FROM articles WHERE id = ?")
  const article = statement.get(req.params.id)

  if (!article) {
    return res.redirect("/")
  }

  // Artikel in Datenbank suchen
  if (article.authorid !== req.user.userid && req.user.userid !== 1) {
    return res.redirect("/")
  }

  // Artikel löschen
  const deleteStatement = db.prepare("DELETE FROM articles WHERE id = ?")
  deleteStatement.run(req.params.id)

  res.redirect("/")
})
/////

// Registrierenbutton gedrückt
/////
app.post("/register", (req, res) => {
  // Errors
  const errors = []

  if (req.body.username.trim() == "") {errors.push("Bitte Benutzername eingeben."); return res.render("register", {errors})}
  if (req.body.password.trim() == "") {errors.push("Bitte Passwort eingeben."); return res.render("register", {errors})}

  if (typeof req.body.username !== "string") {req.body.username = ""; errors.push("Der Benutzername muss Textformat haben."); return res.render("register", {errors})}
  if (typeof req.body.password !== "string") {req.body.password = ""; errors.push("Das Passwort muss Textformat haben."); return res.render("register", {errors})}

  req.body.username = req.body.username.trim()

  if (req.body.username.length == 1 || req.body.username.length == 2) {errors.push("Der Benutzername muss mindestens 3 Zeichen lang sein."); return res.render("register", {errors})}
  if (req.body.username.length > 20) {errors.push("Der Benutzername darf nicht länger als 20 Zeichen sein."); return res.render("register", {errors})}
  if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) {errors.push("Nur Buchstaben und Zahlen sind erlaubt im Benutzernamen."); return res.render("register", {errors})}

  const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
  const usernameCheck = usernameStatement.get(req.body.newusername)

  if (usernameCheck) {errors.push("Dieser Benutzername existiert schon."); return res.render("register", {errors})}

  if (req.body.password.length == 1 && req.body.password.length == 2 && req.body.password.length == 3 && req.body.password.length == 4) {errors.push("Das Passwort muss mindestens 5 Zeichen lang sein."); return res.render("register", {errors})}

  // Neuer Benutzer in Datenbank abspeichern
  const salt = bcrypt.genSaltSync(10)
  req.body.password = bcrypt.hashSync(req.body.password, salt)

  const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
  const result = ourStatement.run(req.body.username, req.body.password)

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
  const ourUser = lookupStatement.get(result.lastInsertRowid)

  // Benutzer einloggen -> Cookie geben
  const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  let server = fork('server')
  server.on('close', (code) => {
    console.log("Restarted")
  });
  res.redirect("/")
})
/////


app.listen(3000)

// ///// = Kopiert aus Backend-Tutorial