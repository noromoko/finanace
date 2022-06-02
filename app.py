import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"] # Getting user's id

    # Getting data to display on portfolio page
    trans_db = db.execute("SELECT share, SUM(quantity) AS totalQuantity, price, name FROM shares WHERE person_id = ? GROUP BY share", user_id)

    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    total = cash
    for row in trans_db:
        total += row["price"] * row["totalQuantity"]


    return render_template("index.html", transactions = trans_db, cash = cash, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol") # Symbol input
        if not request.form.get("quantity") or not symbol:
            return apology("must provide a symbol and\or quantity") # IF user didnt provide a symbol or quantity
        quantity = int(request.form.get("quantity")) # Quantity input

        stock = lookup(symbol) # Stock's data (float)
        if stock == None:
            return apology("must provide a valid symbol") # If user provided invalid symbol

        if quantity < 1:
            return apology("quantity must be a positive integer") # If provided quantity is not a positive integer

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"]) # User's cash data
        total = quantity * stock["price"] # Total transaction value
        cash = user_cash[0]["cash"] # User's cash

        if cash < total:
            return apology("u broke") # If user doesn't have enough money

        # Update user's cash
        updt_cash = cash - total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, session["user_id"])

        # Update user's portfolio
        db.execute("INSERT INTO shares (person_id, share, quantity, name, price, date) VALUES(?, ?, ?, ?, ?, datetime('now', 'localtime'))",
        session["user_id"], stock["symbol"], quantity, stock["name"], stock["price"])
        #db.execute("INSERT INTO history (person_id, share, action, price, quantity, date) VALUES(?, ?, Buy, ?, ?, datetime('now','localtime'))",
        #user["id"], stock["symbol"], stock["price"], quantity) # Update user's history

        flash("Successfully bought!")
        return redirect("/")

    else:
        return render_template("/buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session['user_id']
    trans_db = db.execute("SELECT * FROM shares WHERE person_id = ? ORDER BY date DESC", user_id)

    return render_template("history.html", transactions = trans_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    quote = request.form.get("quote")

    if request.method == "POST":

        if not quote:
            return apology("must provide quote", 403)

        lookedup = lookup(quote)
        if lookedup == None:
            return apology("quote doesnt exist", 403)

        name = lookedup['name']
        price = lookedup['price']
        symbol = lookedup['symbol']

        return render_template("quoted.html", name=name, price=price, symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    #Forget any user_id
    session.clear()

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    usernames = db.execute("SELECT username FROM users")
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not username:
            return apology("must provide username")
        # Ensure username doesnt exists in database
        elif username in usernames:
            return apology("username already exists")

        # Ensure password was submitted
        elif not password:
            return apology("must provide password")
        # Ensure confirmation password was submitted
        elif not confirmation:
            return apology("must provide confirmation password")
        #Ensure password and confirmation password are matching
        elif password != confirmation:
            return apology("passwords does not match")

        # Generating the hash of the user's password
        hash = generate_password_hash(password)

        # INSERT the new user into users
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        return redirect("/")

    else:
        return render_template("/register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        user_id = session["user_id"]
        symbols_db = db.execute("SELECT share FROM shares WHERE person_id = ? GROUP BY share HAVING SUM(quantity) > 0", user_id)
        return render_template("sell.html", symbols = [row["share"] for row in symbols_db])

    # IF POST
    else:
        symbol = request.form.get("symbol") # Symbol input
        if not request.form.get("shares") or not symbol:
            return apology("must provide a symbol and\ or quantity") # If user didn't provide a symbol or quantity
        quantity = int(request.form.get("shares")) # Quantity input

        stock = lookup(symbol) # Stock's data (float)

        if quantity < 1:
            return apology("quantity must be a positive integer") # If provided quantity is not a positive integer

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"]) # User's cash data
        total = quantity * stock["price"] # Total transaction value
        cash = user_cash[0]["cash"] # User's cash

        share_quan = db.execute("SELECT SUM(quantity) AS quantity FROM shares WHERE person_id = ? AND share = ?", session["user_id"], symbol) # available quantity of the share
        share_quan = share_quan[0]['quantity']

        if share_quan < quantity:
            return apology("not enough shares in stock") # If not enough shares in stock

        # Update user's cash
        updt_cash = cash + total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, session["user_id"])

        # Update user's portfolio
        db.execute("INSERT INTO shares (person_id, share, quantity, name, price, date) VALUES(?, ?, ?, ?, ?, datetime('now', 'localtime'))",
        session["user_id"], stock["symbol"], (-1)*quantity, stock["name"], stock["price"])
        #db.execute("INSERT INTO history (person_id, share, action, price, quantity, date) VALUES(?, ?, Buy, ?, ?, datetime('now','localtime'))",
        #user["id"], stock["symbol"], stock["price"], quantity) # Update user's history


        flash("Successfully sold!")
        return redirect("/")

