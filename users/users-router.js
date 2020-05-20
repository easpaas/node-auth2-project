const router = require("express").Router();

const Users = require("./users-model.js");
const restricted = require("../auth/restricted-middleware.js");
const { isValid } = require("./users-service.js");

router.use(restricted);

router.get("/", (req, res) => {
  Users.find()
    .then(users => {
      res.status(200).json({ users, jwt: req.jwt });
    })
    .catch(err => res.send(err));
});

// only accounts with the admin role can create users
router.post("/", checkRoles(["admin"]), (req, res) => {
  const user = req.body;

  if (isValid(user)) {
    Users.add(user)
      .then(saved => {
        res.status(201).json({ data: saved });
      })
      .catch(error => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({ message: "please provide all user information" });
  }
});

function checkRoles(roles) {
  return function (req, res, next) {
    const role = req.jwt.role;

    if (req.jwt && req.jwt.role && roles.includes(role)) {
      next();
    } else {
      res.status(403).json({ you: "have no power here" });
    }
  };
}

module.exports = router;
