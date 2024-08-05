const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const csrf = require("tiny-csrf");
const path = require("path");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const flash = require("connect-flash");
const { Todo, User } = require("./models");

require("dotenv").config();

const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
const saltRounds = 10;

app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("shh! some secret string"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));
app.use(express.static(path.join(__dirname, "public")));
app.use(flash());
app.use(
  session({
    secret: "my-super-secret-key-21728172615261562",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);
app.use(function (request, response, next) {
  response.locals.messages = request.flash();
  next();
});
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      User.findOne({ where: { email: username } })
        .then(async (user) => {
          if (!user) {
            return done(null, false, { message: "Invalid login credentials" });
          }
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Invalid login credentials" });
          }
        })
        .catch((error) => {
          return done(error);
        });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findByPk(id)
    .then((user) => {
      done(null, user);
    })
    .catch((error) => {
      done(error, null);
    });
});

const { GoogleGenerativeAI } = require("@google/generative-ai");
const genAI = new GoogleGenerativeAI("${{ secrets.API_KEY }}");

const systemPrompt =
  "You are an assistant helping a user manage their to-do list. " +
  "Given a message, you should extract the to-do item from it and provide a JSON response with 'name' and 'args' fields. " +
  "The 'name' field should be 'createTodo' for adding a to-do item. " +
  "The 'args' field should be a JSON object containing 'text' and 'dueAt' fields. " +
  "The user may provide a due date along with the to-do item. " +
  "To compute relative dates, assume that the current timestamp is " +
  new Date().toISOString() +
  ". When the input is ambiguous, ask for clarification.";

const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

async function askGPT(question) {
  try {
    const prompt = systemPrompt + "\n\n" + question;
    const result = await model.generateContent(prompt);
    const response = await result.response;
    let text = await response.text();

    console.log("Raw response text:", text);

    // Remove Markdown code block delimiters
    text = text
      .replace(/^json\s*/i, "")
      .replace(/\s*$/, "")
      .trim();

    // Parse the cleaned JSON
    let toolCall;
    try {
      toolCall = JSON.parse(text);
      console.log("Tool call:", toolCall);
    } catch (parseError) {
      console.error("Failed to parse JSON:", parseError);
      throw new Error("Unexpected response format");
    }

    return toolCall;
  } catch (error) {
    console.error("Error making a query", error);
    throw error;
  }
}

async function addTodoWithGemini(question, user) {
  try {
    const toolCall = await askGPT(question);
    if (toolCall.name === "createTodo") {
      const args = toolCall.args; // No need to parse

      // Check if args contains the expected fields
      if (args.text && args.dueAt) {
        await Todo.addTodo({
          title: args.text,
          dueDate: args.dueAt,
          userId: user.id,
        });
        console.log("Adding todo", args.text, args.dueAt);
      } else {
        throw new Error("Invalid arguments received");
      }
    } else {
      console.log("Unknown tool call", toolCall.name);
    }
  } catch (error) {
    console.error("Error adding todo with Gemini", error);
  }
}

app.post(
  "/natural",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    await addTodoWithGemini(request.body.naturalText, request.user);
    response.redirect("/");
  }
);

app.get(
  "/",
  connectEnsureLogin.ensureLoggedOut({
    redirectTo: "/todos",
  }),
  (request, response) => {
    response.render("index", {
      title: "Todo application",
      csrfToken: request.csrfToken(),
    });
  }
);

app.get(
  "/todos",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const loggedInUser = request.user.id;
    const overdue = await Todo.overdue(loggedInUser);
    const dueToday = await Todo.dueToday(loggedInUser);
    const dueLater = await Todo.dueLater(loggedInUser);
    const completed = await Todo.completed(loggedInUser);
    if (request.accepts("html")) {
      response.render("todos", {
        title: "Todo application",
        overdue,
        dueToday,
        dueLater,
        completed,
        csrfToken: request.csrfToken(),
      });
    } else {
      response.json({
        overdue,
        dueToday,
        dueLater,
        completed,
      });
    }
  }
);

app.get("/signup", (request, response) => {
  response.render("signup", {
    title: "Signup",
    csrfToken: request.csrfToken(),
  });
});

app.post("/users", async (request, response) => {
  const password = request.body.password.trim();
  if (password.length < 8) {
    request.flash("error", "Password should be at least 8 characters long");
    return response.redirect("/signup");
  }
  // Hash password
  const hashedPwd = await bcrypt.hash(password, saltRounds);
  try {
    // Create user
    const user = await User.create({
      firstName: request.body.firstName ,
      lastName: request.body.lastName,
      email: request.body.email,
      password: hashedPwd,
    });
    request.login(user, (err) => {
      if (err) {
        console.log(err);
        return response.redirect("/signup");
      }
      response.redirect("/todos");
    });
  } catch (error) {
    console.log(error);
    error.errors &&
      error.errors.length &&
      error.errors.map((anError) => request.flash("error", anError.message));
    response.redirect("/signup");
  }
});

app.get("/login", (request, response) => {
  response.render("login", { title: "Login", csrfToken: request.csrfToken() });
});

app.post(
  "/session",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request, response) => {
    response.redirect("/todos");
  }
);

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});

app.post(
  "/todos",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    try {
      await Todo.addTodo({
        title: request.body.title,
        dueDate: request.body.dueDate,
        userId: request.user.id,
      });
      return response.redirect("/todos");
    } catch (error) {
      console.log(error.message);
      request.flash("error", error.message);
      return response.redirect("/todos");
    }
  }
);

app.put(
  "/todos/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const todo = await Todo.findByPk(request.params.id);
    if (todo.userId !== request.user.id) {
      return response.status(401).json({ error: "No such item" });
    }
    try {
      const updatedTodo = await todo.setCompletionStatus(
        request.body.completed
      );
      return response.json(updatedTodo);
    } catch (error) {
      console.log(error);
      return response.status(422).json(error);
    }
  }
);

app.delete(
  "/todos/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    try {
      const deletedRows = await Todo.remove(request.params.id, request.user.id);
      return response.json({ success: deletedRows > 0 });
    } catch (error) {
      return response.status(422).json(error);
    }
  }
);

module.exports = app;