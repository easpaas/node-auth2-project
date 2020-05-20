const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const router = require("express").Router();

const Users = require("../users/users-model.js");
const { isValid } = require("../users/users-service.js");

router.post("/register", (req, res) => {
  const credentials = req.body;

  if (isValid(credentials)) {
    const rounds = process.env.BCRYPT_ROUNDS || 2;

    // hash the password
    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;

    // save the user to the database
    Users.add(credentials)
      .then(user => {
        res.status(201).json({ data: user });
      })
      .catch(error => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message: "please provide username and password and the password shoud be alphanumeric",
    });
  }
});

router.post('/login', (req, res) => {
  let {username, password} = req.body;

  Users.findBy({ username })
      .first()
      .then(someone => {
          if (someone && bcryptjs.compareSync(password, someone.password)) {
              const token = createToken(someone);
              res.status(200).json({ message: `Welcome ${someone.username}`, token})
          } else {
              res.status(401).json({ message: 'Invalid Credentials!' })
          }
      })
      .catch(err => {
          console.log('error logging in', err)
          res.status(500).json({ errorMessage: 'Could not log in!' })
      })
})
// router.post("/login", (req, res) => {
//   const { username, password } = req.body;

//     Users.findBy({ username })
//       .then(([user]) => {
//         // compare the password the hash stored in the database
//         if (user && bcryptjs.compareSync(password, user.password)) {
//           // produce and send a token that includes the username and the role of the user
//           const token = createToken(user);

//           res.status(200).json({ message: "Welcome to our API", token });
//         } else {
//           res.status(401).json({ message: "Invalid credentials" });
//         }
//       })
//       .catch(error => {
//         res.status(500).json({ message: error.message });
//       });

//     // res.status(400).json({
//     //   message: "please provide username and password and the password shoud be alphanumeric",
//     // });
// });

function createToken(user) {
  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
  };

  const secret = process.env.JWT_SECRET || "keepitsecret,keepitsafe!";

  const options = {
    expiresIn: "1d",
  };

  return jwt.sign(payload, secret, options);
}

module.exports = router;
