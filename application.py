import os

from cs50 import SQL
from flask import Flask, flash, json, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, get_time

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as shares_num FROM transactions WHERE id = :id GROUP BY symbol HAVING shares_num > 0 ORDER BY symbol", id=session["user_id"])
    share_sum = 0
    for stock in stocks:
        q = lookup(stock["symbol"])
        stock["name"] = q["name"]
        stock["price"] = q["price"]
        stock["sum"] = q["price"] * stock["shares_num"]
        share_sum += stock["sum"]
        stock["sum"] = stock["sum"]
    rows = db.execute("SELECT username, cash FROM users WHERE id = :id", id=session["user_id"])
    username = rows[0]["username"]
    cash = rows[0]["cash"]
    total = share_sum + cash
    return render_template("index.html", stocks=stocks, cash=cash, total=total, username=username)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))
            if shares < 1:
                return apology(message="please enter a positive number")
        except:
            return apology(message="please enter a positive integer")
        if not symbol or not shares:
            return apology(message="please enter a symbol and a share")
        quote = lookup(symbol)
        if not quote:
            return apology(message="invalid symbol")
        query = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = query[0]['cash']
        price = quote["price"] * shares
        if cash < price:
            return apology(message="not enough cash")
        transacted = get_time()
        buy = db.execute("INSERT INTO transactions(id, symbol, shares, price, transacted) VALUES(:id, :symbol, :shares, :price, :transacted)", id=session["user_id"],
                         symbol=symbol.upper(), shares=shares, price=price, transacted=transacted)
        flash("Bought!")
        cash -= price
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=cash, id=session["user_id"])
        return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    verify = db.execute("SELECT username FROM users WHERE username = :username", username=username)
    if verify:
        return jsonify(False)
    else:
        return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE id = :id", id=session["user_id"])
    return render_template("history.html", history=history)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology(message="please enter a symbol")
        quote = lookup(symbol)
        if not quote:
            print(quote)
            return apology(message="invalid symbol")
        return render_template("quoted.html", name=quote["name"], price=quote["price"], symbol=quote["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation or password != confirmation:
            return apology(message="Please fill the form correctly to register.")
    # Specifications for password

    # password length
    if len(password) < 6:
        return apology(message="password must be longer than 6 characters")
    # password must contain numbers
    if password.isalpha():
        return apology(message="password must contain numbers")
    # password must contain letters
    if password.isdigit():
        return apology(message="password must contain letters")

    for c in username:
        if not c.isalpha() and not c.isdigit() and c != "_":
            return apology(message="Please enter a valid username.")
    if len(username) < 1:
        return apology(message="please enter a username with more than 1 character.")
    hash_pw = generate_password_hash(password)
    try:
        insertion = db.execute("INSERT INTO users(username, hash) VALUES(:username, :hash_pw)", username=username, hash_pw=hash_pw)
        if not insertion:
            return apology(message="Username already exists.")
    except:
        return apology(message="Something went wrong with the database.")
    rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
    session["user_id"] = rows[0]["id"]
    flash("Registered!")
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        # Getting symbols user owns to display
        stocks = db.execute(
            "SELECT symbol FROM transactions WHERE id = :id GROUP BY symbol HAVING SUM(shares) > 0  ORDER BY symbol", id=session["user_id"])
        return render_template("sell.html", stocks=stocks)
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or not shares:
            return apology(message="please enter a symbol and a share")
        stocks = db.execute(
            "SELECT SUM(shares) FROM transactions WHERE id = :id AND symbol = :symbol GROUP BY symbol HAVING SUM(shares) > 0", id=session["user_id"], symbol=symbol)
        shares_owned = stocks[0]["SUM(shares)"]
        try:
            shares = int(shares)
            if shares < 1:
                return apology(message="please enter a positive number")
        except:
            return apology(message="please enter a positive integer")
        if shares > shares_owned:
            return apology(message="you don't have enough shares")
        quote = lookup(symbol.lower())
        if not quote:
            return apology(message="invalid symbol")
        # Getting the user's cash balance
        query = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = query[0]['cash']
        # Getting the result of stock * shares to add to user's cash
        price = quote["price"] * shares
        # Converting positive number to negative number to add to database negative number as a sell
        shares = int('-' + str(shares))
        transacted = get_time()
        sell = db.execute("INSERT INTO transactions(id, symbol, shares, price, transacted) VALUES(:id, :symbol, :shares, :price, :transacted)", id=session["user_id"],
                          symbol=symbol, shares=shares, price=price, transacted=transacted)
        flash("Sold!")
        # Updating the user's cash balance
        cash += price
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=cash, id=session["user_id"])
        return redirect("/")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        username = db.execute("SELECT username FROM users WHERE id = :id", id=session["user_id"])[0]["username"]
        return render_template("change.html", username=username)
    else:
        password = request.form.get("password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        pw_hash = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])[0]["hash"]
        if not password or not new_password or new_password != confirmation or not check_password_hash(pw_hash, password):
            return apology("provide password correctly")
        else:
            q = db.execute("UPDATE users SET hash = :new_password WHERE id = :id",
                           new_password=generate_password_hash(new_password), id=session["user_id"])
            flash("Password updated!")
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
