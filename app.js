const express = require("express");
const app = new express();
const path = require("path");


app.use(express.json());

app.use(express.static(path.join(__dirname, "client")));

app.get("/", (req, res) => {
    res.render("index.html");
});

app.get("/server", (req, res) => {
    res.send("Works").status(200);
})

app.listen(3000);