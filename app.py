import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from datetime import datetime
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from utility import get_username, get_now, get_user_id
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    balance = db.execute("SELECT username, cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    user = get_username(db, session)
    stocks = db.execute("SELECT * FROM shares WHERE user = ? and shares > 0", user)

    # This line gets the current value of "just_registered" and then pops it off
    first_time = session.pop("just_registered", False)
    grand_total = balance;

    # Appending current price, gain and total_value of each stock to the stocks[] array
    for stock in stocks:
        current_price = lookup(stock["company"])["price"]
        shares = stock["shares"]
        stock["current_price"] = usd(current_price)
        stock["total_value"] = usd(current_price * shares)
        grand_total += current_price * shares
        stock["gain"] = usd((current_price * shares) - (stock["price"] * shares)) # price = price bought at
        stock["price"] = usd(stock["price"])

    grand_total = usd(grand_total)

    return render_template("index.html", stocks=stocks, user=user, balance=usd(balance), grand_total=grand_total, first_time=first_time)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # If company field was empty
        company_symbol = request.form.get("symbol").upper()
        if not company_symbol:
            return apology("Please enter a company")

        # If company doesn't exist
        price = lookup(company_symbol)
        if price is None:
            return apology("Invalid company")
        else:
            price = price["price"]

        # If the user doesn't have the funds.
        shares = int(request.form.get("shares"))
        current_balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if (shares * price) > current_balance:
            return apology("Insufficient balance")

        # If the user is buying MORE shares in a company
        user = get_username(db, session)
        has_shares_already = db.execute("SELECT * FROM shares WHERE company = ? AND user = ?", company_symbol.upper(), user)
        print(has_shares_already)

        # Finally, if all is good
        now = get_now()

        # If the user's buying more shares
        if has_shares_already != []:
            db.execute("""UPDATE shares SET shares = shares + ?, price = (price + ?) / 2,
                        time_bought = ? WHERE company = ? """,
                        int(shares), price, now, company_symbol)
        # If the user's buying shares from a company for the first time
        else:
            db.execute("INSERT INTO shares (company, shares, price, time_bought, user) VALUES (?,?,?,?,?)",
                        company_symbol, shares, price, now, user)

        # Updating cash balance
        db.execute("UPDATE users SET cash = ? WHERE username = ?", current_balance - (shares * price), user)

        # Adding transaction to the database
        db.execute("""INSERT INTO transactions (company, of_type, shares, price, time_bought, user)
                   VALUES (?,?,?,?,?,?)""", company_symbol, "BOUGHT", shares, usd(price), now, user)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

    transactions = db.execute("SELECT * FROM transactions WHERE user = ?", user)

    return render_template("history.html", transactions=transactions, user=user)


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

    if request.method == "POST":
        company_symbol = request.form.get("symbol")
        quote = lookup(company_symbol)

        if quote is None:
            return apology("Invalid company")

        return render_template("quote.html", quote=quote)

    else:
        return render_template("quote.html", quote=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    # If the user is registering, this page will be accessed via post
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # If some details are empty
        if not (username and password and confirmation):
            return apology("All details must be entered")

        # If passwords don't match
        if password != confirmation:
            return apology("Passwords don't match")

        rows = db.execute("SELECT * FROM users WHERE username = ? LIMIT 1", username)
        if rows:
            return apology("Username is already registered")

        # Finally, if all the details are good, add to database and put into session
        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, generate_password_hash(password))
        session["user_id"] = get_user_id(db,username)
        session["just_registered"] = True

        return redirect("/")

    # If they're arriving at the register page for the first time, they come via get
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = get_username(db, session)

    if request.method == "POST":
        # Number of shares to sell
        selling = int(request.form.get("shares"))
        company = request.form.get("symbol")

        # If some details are empty
        if not (selling and company):
            return apology("Please enter all details")

        # If shares to sell exceeds shares owned
        owned = db.execute("SELECT shares FROM shares WHERE company = ?", company)[0]["shares"]
        if owned < selling:
            return apology("Insufficient shares owned to perform sale")

        # Get the time
        now = get_now()

        # Finally, if all is good - updates shares, cash balance and add transaction to database
        # Update shares, including deleting the row if shares <= 0
        db.execute("UPDATE shares SET shares = shares - ? WHERE company = ?", selling, company)
        db.execute("DELETE FROM shares WHERE shares <= 0")
        # Update cash balance
        current_price = lookup(company)["price"]
        db.execute("UPDATE users SET cash = cash + ? WHERE username = ?",
                   selling * current_price, user)
        # Update transactions
        db.execute("""INSERT INTO transactions (company, of_type, shares, price, time_bought, user)
                   VALUES (?,?,?,?,?,?)""", company, "SOLD", selling, usd(current_price), now, user)

        return redirect("/")

    else:
        companies = db.execute("SELECT company FROM shares WHERE user = ?", user)

        return render_template("sell.html", companies=companies)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deeposit():
    if request.method == "POST":
        username = get_username(db, session)
        id = session["user_id"]
        amount = int(request.form.get("amount"))

        if not amount:
            return apology("Please enter an amount")

        now = get_now()
        user = get_username(db, session)

        # Update cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE username = ? AND id = ?",
                   amount, username, id)
        # Update transactions
        db.execute("""INSERT INTO transactions (company, of_type, shares, price, time_bought, user)
                   VALUES (?,?,?,?,?,?)""", "N/A", "DEPOSIT", 0, usd(amount), now, user)

        return redirect("/")

    else:
       return render_template("deposit.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        entered_password = request.form.get("current-password")
        new_password = request.form.get("new-password")
        confirmation = request.form.get("confirmation")

        if not (entered_password and new_password and confirmation):
            return apology("All details must be entered")

        # Check if the new passwords match
        if not new_password == confirmation:
            return apology("New passwords don't match")

        # If new password is the same as the old
        if entered_password == new_password:
            return apology("Please enter different password")

        username = get_username(db, session)
        current_hash = db.execute("SELECT hash FROM users WHERE username = ?", username)[0]["hash"]

        # Check if the old passwords match
        if not check_password_hash(current_hash, entered_password):
            return apology("Current password inccorrect")

        # If all is good
        db.execute("UPDATE users SET hash = ? WHERE username = ? AND id = ?",
                   generate_password_hash(new_password), username, session["user_id"])


        return redirect("/")


    else:
        return render_template("change-password.html")

