from flask import Blueprint, render_template, redirect, url_for


dashboard_pages_bp = Blueprint("dashboard_pages", __name__)


@dashboard_pages_bp.route("/")
def home():
    return redirect(url_for("dashboard_pages.login_page"))


@dashboard_pages_bp.route("/login")
def login_page():
    return render_template("login.html")


@dashboard_pages_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@dashboard_pages_bp.route("/users")
def users_view():
    return render_template("users.html")


@dashboard_pages_bp.route("/user-profile/<int:user_id>")
def user_profile_view(user_id):
    return render_template("user_profile.html", profile_id=user_id)


@dashboard_pages_bp.route("/topology")
def network_topology_page():
    return render_template("network_topology.html")
