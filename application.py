import os


from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required
import qrcode


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


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///truckloader.db")


@app.route("/")
@login_required
def index():
    """Show Where Everything Is"""
    items = db.execute("SELECT * FROM inventory WHERE organization = ? ORDER BY name", session["org"])
    length = len(items)
    return render_template("homepage.html", items = items, length = length)


@app.route("/inventory", methods=["GET", "POST"])
@login_required
def inventory():
    """Add to Inventory, Locations (Admin Only)"""

    # Accessed via GET
    if request.method == "GET":
        #check that user is authorized
        auth = db.execute("SELECT admin FROM users WHERE id = :id",
                          id = session["user_id"])
        if auth[0]["admin"] != 1:
            return apology("you are not authorized")
        else:
            #get location options
            locations = db.execute("SELECT * FROM locations WHERE org = ?", session["org"])
            length = len(locations)
            return render_template("inventory.html", locations = locations, length = length)

    #Accessed via post
    else:
        #determine what is being added
        if not request.form.get("item"):
            if not request.form.get("location"):
                return apology("must input new item or location", 403)

            #location input
            else:
                #check that location doesn't exist yet
                location = request.form.get("location")
                loccheck = db.execute("SELECT * FROM locations WHERE loc_name = ? AND org = ?", location, session["org"])
                if len(loccheck) != 0:
                    return apology("location already exists")

                #insert location
                else:
                    db.execute("INSERT INTO locations(loc_name, org) VALUES (?, ?)", location, session["org"])
                    return redirect("/inventory")

        #item input
        else:
            #check that starter location was given
            if not request.form.get("startspot"):
                return apology("must provide starting location")

            #check that item doesn't exist
            item = request.form.get("item")
            userdata = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            itemcheck = db.execute("SELECT * FROM inventory WHERE name = ? AND organization = ?", item, userdata[0]["organization"])
            if len(itemcheck) != 0:
                return apology("this item already exists")

            #check that desired location exists
            loc = request.form.get("startspot")
            loccheck = db.execute("SELECT * FROM locations WHERE loc_name = ? AND org = ?", loc, session["org"])
            if len(loccheck) != 1:
                return apology("invalid location")

            #insert item and create qrcode
            else:
                #get needed data
                itemname = request.form.get("item")
                time = datetime.now()
                db.execute("INSERT INTO inventory(name, organization, location, lastmoved, mover) VALUES (?, ?, ?, ?, ?)", itemname, userdata[0]["organization"], loc, time, userdata[0]["username"] )
                item = db.execute("SELECT * FROM inventory WHERE name = ?", itemname)
                image = qrcode.make(f"{itemname}")
                image.save(f"static/{item[0]['id']}.png", "PNG")
                return redirect("/inventory")


@app.route("/removeitems", methods=["GET", "POST"])
@login_required
def removeitems():
    """Remove Items/Locations (Admin Only)"""
    # Accessed via GET
    if request.method == "GET":
        #check that user is authorized
        auth = db.execute("SELECT admin FROM users WHERE id = :id",
                          id = session["user_id"])
        if auth[0]["admin"] != 1:
            return apology("you are not authorized")
        else:
            #get location and item options
            locations = db.execute("SELECT * FROM locations WHERE org = ?", session["org"])
            loclength = len(locations)
            items = db.execute("SELECT * FROM inventory WHERE organization = ?", session["org"])
            itemlength = len(items)
            return render_template("removeitems.html", locations = locations, loclength = loclength, items = items, itemlength = itemlength)

    #Accessed via post
    else:
        #determine what is being removed
        if not request.form.get("item"):
            if not request.form.get("location"):
                return apology("must input item or location to delete", 403)

            #check location input
            else:
                #check that location exits
                location = request.form.get("location")
                loccheck = db.execute("SELECT * FROM locations WHERE loc_name = ? AND org = ?", location, session["org"])
                if len(loccheck) != 1:
                    return apology("must select valid location")

                #remove location
                else:
                    db.execute("DELETE FROM locations WHERE loc_name = ? AND ORG = ?", location, session["org"])
                    return redirect("/removeitems")

        #check item input
        else:
            #check that item exists
            item = request.form.get("item")
            userdata = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            itemcheck = db.execute("SELECT * FROM inventory WHERE name = ? AND organization = ?", item, session["org"])
            if len(itemcheck) != 1:
                return apology("must select item to delete")

            #delete item
            else:
                #get needed data
                itemname = request.form.get("item")
                db.execute("DELETE FROM inventory WHERE name = ? AND organization = ?", itemname, session["org"])
                return redirect("/removeitems")



@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    """View/Edit Organization Users (Admin Only)"""

    # Accessed via GET
    if request.method == "GET":
        #check that user is authorized
        auth = db.execute("SELECT admin FROM users WHERE id = :id",
                          id = session["user_id"])
        if auth[0]["admin"] != 1:
            return apology("you are not authorized")
        else:
            #get user options
            users = db.execute("SELECT * FROM users WHERE organization = ? ORDER BY username", session["org"])
            length = len(users)
            return render_template("users.html", users = users, length = length)

    #Accessed via post
    else:
        #user options
        users = db.execute("SELECT * FROM users WHERE organization = ? ORDER BY username", session["org"])
        length = len(users)

        #selection info
        deletion = request.form.get("who")
        print(f"{deletion}")
        if deletion != session["username"]:
            return render_template("confirm.html", deletion = deletion, users = users, length = length)
        else:
            return apology("you may not delete yourself")


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    """Delete a user(Admin Only)"""
    decision = request.form.get("decision")
    if decision == "cancel":
        return redirect("/users")
    else:
        db.execute("DELETE FROM users WHERE username = ?", decision)
        return redirect("/users")


@app.route("/relocate", methods=["GET", "POST"])
@login_required
def relocate():
    """Update location of item"""

    # Accessed via GET
    if request.method == "GET":
        #get location options
        locations = db.execute("SELECT * FROM locations WHERE org = ?", session["org"])
        length = len(locations)
        return render_template("relocate.html", locations = locations, length = length, setloc = session["location"])

    #accessed via POST
    else:
        #get needed info (user, location, item, time)
        loc = request.form.get("loc")
        session["location"] = loc
        item = request.form.get("item")
        now = datetime.now()
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        print(f"{loc} {item} {now} {user}")

        #check if item is valid
        check = db.execute("SELECT * FROM inventory WHERE name = ? AND organization = ?", item, session["org"])
        if len(check) != 1:
            return apology("invalid item")

        #check if location has been set
        if loc == "None":
            return apology("must set location")

        #update inventory and user stats
        else:
            db.execute("UPDATE inventory SET location = ?, lastmoved = ?, mover = ? WHERE name = ? AND organization = ?", loc, now, user[0]["username"], item, session["org"])

            #update user stats
            userinfo = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            currentmoves = userinfo[0]["moves"]
            newmoves = currentmoves + 1
            db.execute("UPDATE users SET currentlocation = ?, moves = ?, asof = ? WHERE id = ?", loc, newmoves, now, session["user_id"])

            #return page
            return redirect("/relocate")


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

        # Query database for username, get necessary validation data
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        else:
            org = rows[0]["organization"]
            givenorg = request.form.get("orgname")
            if org != givenorg:
                return apology("you are not associated with this organization", 403)
            else:
                # Remember which user has logged in and other info
                session["user_id"] = rows[0]["id"]
                session["username"] = rows[0]["username"]
                session["org"] = rows[0]["organization"]
                session["location"] = "None"
                session["admin"] = rows[0]["admin"]

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


@app.route("/neworg", methods=["GET", "POST"])
def neworg():
    """Set Up New Organization"""

    # Accessed via GET
    if request.method == "GET":
        return render_template("neworg.html")

    #Reached via POST, registration time!
    elif request.method == "POST":

        # Ensure organization name was submitted
        if not request.form.get("orgname"):
            return apology("must provide organization name", 403)

        # Ensure username was submitted
        if not request.form.get("admin"):
            return apology("must provide admin username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 403)

        #Ensure orgname is unique
        orgcheck = db.execute("SELECT * FROM organizations WHERE name = :orgname",
                                orgname = request.form.get("orgname"))
        if len(orgcheck) != 0:
            return apology("orgname taken")

        #Ensure username is unique
        namecheck = db.execute("SELECT * FROM users WHERE username = :username",
                                username = request.form.get("admin"))
        if len(namecheck) != 0:
            return apology("username taken")
        else:
            #Ensure that passwords match
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")
            if password != confirmation:
                return apology("passwords do not match")
            else:
                orgname = request.form.get("orgname")
                username = request.form.get("admin")
                hashedpass = generate_password_hash(password)
                db.execute("INSERT INTO users(username, hash, organization, admin) VALUES (?, ?, ?, ?)", username, hashedpass, orgname, 1)
                db.execute("INSERT INTO organizations(name, admin_name) VALUES (?, ?)", orgname, username)
                return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Accessed via GET
    if request.method == "GET":
        return render_template("register.html")

    #Reached via POST, registration time!
    elif request.method == "POST":

        # Ensure orgname was submitted
        if not request.form.get("orgname"):
            return apology("must provide organization name", 403)

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 403)

        #Ensure organization is valid
        validorg = db.execute("SELECT * FROM organizations WHERE name = :orgname",
                                orgname = request.form.get("orgname"))
        if len(validorg) != 1:
            return apology("must request to join a valid organization")

        #Ensure username is unique
        uniquecheck = db.execute("SELECT * FROM users WHERE username = :username",
                                username = request.form.get("username"))
        if len(uniquecheck) != 0:
            return apology("username taken")
        else:
            #Ensure that passwords match
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")
            if password != confirmation:
                return apology("passwords do not match")
            else:
                orgname = request.form.get("orgname")
                username = request.form.get("username")
                hashedpass = generate_password_hash(password)
                db.execute("INSERT INTO users(username, hash, organization) VALUES (?, ?, ?)", username, hashedpass, orgname)
                return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
