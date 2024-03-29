from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "OIEFNOikjesmeolikmo")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///users.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(
                    app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("welcome"))


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["pass"]
        re_password = request.form["re_pass"]

        if not password == re_password:
            flash("Passwords doesn't match.")
            return redirect(url_for("sign_up"))

        all_users = db.session.query(Users).all()
        selected_users = [
            user
            for user in all_users
            if name in user.name
        ]
        if not len(selected_users) == 1:
            try:
                last_num = [int(user.name.split("(")[1].split(")")[0])
                            for user in selected_users[1:]
                            ][-1]
                name += f" ({last_num + 1})"
            except IndexError:
                pass
        else:
            name += " (1)"
        try:
            new_user = Users(
                name=name,
                email=email,
                password=generate_password_hash(
                    password=password,
                    salt_length=8
                )
            )
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            flash("This email already exists.")
            return redirect(url_for("sign_up"))

        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("sign-up.html")


@app.route("/sign-in", methods=["GET", "POST"])
def sign_in():

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["pass"]

        user = Users.query.filter_by(email=email).first()
        if user:
            is_correct = check_password_hash(
                pwhash=user.password,
                password=password
            )
            if is_correct:
                login_user(user)

                return redirect(url_for("dashboard"))
            else:
                flash("Wrong password.")
                return redirect(url_for("sign_in"))
        else:
            flash("This is email doesn't exist.")
            return redirect(url_for("sign_in"))

    return render_template("sign-in.html")


@app.route("/log-out")
@login_required
def log_out():
    logout_user()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    all_users = db.session.query(Users).all()
    return render_template("index.html", users=all_users)


@app.route("/welcome")
def welcome():
    return render_template("welcome.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True)
