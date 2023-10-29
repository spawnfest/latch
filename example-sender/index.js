const express = require("express");
const cors = require('cors')
const { request } = require('undici');
const PORT = process.env.PORT || "5555";
const app = express();

app.use(cors());
app.use(express.json())

app.all("/", async (req, res) => {
  const request1 = request('https://catfact.ninja/fact');

  const { body } = await request1;

  const data = await body.json();

  await request('https://api.chucknorris.io/jokes/random');
  return res.json({ method: req.method, message: data, ...req.body });
});

app.get('/404', (req, res) => {
  res.sendStatus(404);
})

app.listen(parseInt(PORT, 10), () => {
  console.log(`Listening for requests on http://localhost:${PORT}`);
})
