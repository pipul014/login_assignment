const express = require("express");
const router = new express.Router();
const conn = require("../db/conn");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const JWT_SECRET = "your_secret_key";


// register user data
router.post("/create", async (req, res) => {
  // console.log(req.body);

  const { firstName, lastName, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  if (!firstName || !lastName || !email || !password) {
    res.status(422).json("plz fill the all data");
  }

  try {
    conn.query(
      "SELECT * FROM codes_tomorrow WHERE email = ?",
      email,
      (err, result) => {
        if (result.length) {
          res.status(422).json("This Data is Already Exist");
        } else {
          conn.query(
            "INSERT INTO codes_tomorrow SET ?",
            { firstName, lastName, email, password: hashedPassword },
            (err, result) => {
              if (err) {
                console.log("err" + err);
              } else {
                res.status(201).json(req.body);
              }
            }
          );
        }
      }
    );
  } catch (error) {
    res.status(422).json(error);
  }
});

// login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Retrieve user from database
  conn.query(
    "SELECT * FROM codes_tomorrow WHERE email = ?",
    [email],
    async (error, results) => {
      if (error) throw error;

      if (results.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
        expiresIn: "120s",
      });

      return res.status(200).send({
        msg: "logged In",
        token,
        user: results[0],
      });
    }
  );
});

// get All userdata
router.get("/getusers", (req, res) => {
    conn.query("SELECT * FROM codes_tomorrow", (err, result) => {
      if (err) {
        console.error("Error retrieving users:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      
      if (result.length === 0) {
        return res.status(404).json({ error: "No users found" });
      }
  
      return res.status(200).json(result);
    });
  });
  
// Route to send password reset link
router.post("/sendpasswordlink", async (req, res) => {
  console.log(req.body);

  const { email } = req.body;

  if (!email) {
    res.status(401).json({ status: 401, message: "Enter Your Email" });
  }

  try {
    // Find user by email
    conn.query(
      "SELECT * FROM codes_tomorrow WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          throw err;
        }
        if (results.length === 0) {
          res.status(401).json({ status: 401, message: "Invalid User" });
        } else {
          const user = results[0];
          // Generate token for password reset
          const token = jwt.sign({ _id: user.id }, JWT_SECRET, {
            expiresIn: "120s",
          });
          // Update user's token in the database
          conn.query(
            "UPDATE codes_tomorrow SET verifytoken = ? WHERE id = ?",
            [token, user.id],
            async (err, result) => {
              if (err) {
                throw err;
              }
              // Send password reset email
              const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                  user: "pipuldolai2018@gmail.com",
                  pass: "lglj sqsf fvlc jhdi",
                },
              });
              const mailOptions = {
                from: "pipuldolai2018@gmail.com",
                to: email,
                subject: "Sending Email For Password Reset",
                text: `This Link Valid For 2 MINUTES http://localhost:3001/resetpassword/${user.id}/${token}`,
              };
              transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                  console.log("error", error);
                  res
                    .status(401)
                    .json({ status: 401, message: "Email not sent" });
                } else {
                  console.log("Email sent", info.response);
                  res
                    .status(201)
                    .json({ status: 201, message: "Email sent successfully" });
                }
              });
            }
          );
        }
      }
    );
  } catch (error) {
    res.status(401).json({ status: 401, message: "Invalid User" });
  }
});

// Route to verify user for password reset
router.get("/sendpasswordlink/:id/:token", async (req, res) => {
  const { id, token } = req.params;
// console.log(req.params);

  try {
    // Find user by id and token
    conn.query(
      "SELECT * FROM codes_tomorrow WHERE id = ? AND verifytoken = ?",
      [id, token],
      async (err, results) => {
        if (err) {
          throw err;
        }
        if (results.length === 0) {
          res.status(401).json({ status: 401, message: "Invalid User" });
        } else {
          const user = results[0];
          const verifyToken = jwt.verify(token, JWT_SECRET);

            console.log(user);
          console.log(verifyToken);



          if (verifyToken._id === user.id) {
            res.status(201).json({ status: 201, user });
          } else {
            res.status(401).json({ status: 401, message: "Invalid User" });
          }
        }
      }
    );
  } catch (error) {
    res.status(401).json({ status: 401, message: "Invalid User" });
  }
});


//reset password
router.put("/resetpassword/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;

    try {
        // Verify the token
        const decodedToken = jwt.verify(token, JWT_SECRET);

        // Check if the decoded token's _id matches the user's id
        if (String(decodedToken._id) !== String(id)) {
            return res.status(400).json({ error: "Token does not match user" });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Update the user's password in the database
        conn.query("UPDATE codes_tomorrow SET password = ? WHERE id = ?", [hashedPassword, id], (err, result) => {
            if (err) {
                console.error("Error updating password:", err);
                return res.status(500).json({ error: "Internal server error" });
            }
            return res.status(200).json({ message: "Password reset successfully" });
        });
    } catch (error) {
        console.error("Token verification error:", error);
        return res.status(400).json({ error: "Link expired. Please create a new link" });
    }
});





module.exports = router;

