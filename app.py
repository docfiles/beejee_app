import sqlite3
from sqlite3 import Error
from flask import Flask, jsonify, render_template, request, redirect, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from wtforms.validators import InputRequired, Length
from wtforms import StringField, PasswordField, SubmitField
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt



#### BLOCK 1
""" initializing a Flask app, configuring a dB and encryption"""

app = Flask(__name__)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



""" define a user model and a login form"""

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=3, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


#### BLOCK 2
"""Defines all the functions related to the tasks database"""

db_tasks='db.db'

def dB_conn(dB=db_tasks):
    """Creates a connection with a database
    Returns:
    Connection or description of an Error if anything goes wrong"""
    dB_con=None
    try:
        dB_con=sqlite3.connect(dB)
    except Error as e:
        print(e)
    return dB_con



def fetch_todo() -> dict:
    """Reads all tasks listed in the todo table
    Returns:
        A list of dictionaries
    """

    conn = dB_conn()
    c = conn.cursor()
    query_results = c.execute("SELECT * FROM tasks").fetchall()
    conn.close()
    todo_list = []
    for result in query_results:
        item = {
            "id": result[0],
            "task": result[1],
            "status": result[2]
        }
        todo_list.append(item)

    return todo_list


def update_task_entry(task_id: int, text: str) -> None:
    """Updates task description based on given `task_id`
    Args:
        task_id (int): Targeted task_id
        text (str): Updated description
    Returns:
        None
    """

    conn = dB_conn()
    c = conn.cursor()
    query = 'UPDATE tasks SET task = "{}" WHERE id = {}'.format(text, task_id)
    c.execute(query)
    conn.commit()
    conn.close()


def update_status_entry(task_id: int, text: str) -> None:
    """Updates task status based on given `task_id`
    Args:
        task_id (int): Targeted task_id
        text (str): Updated status
    Returns:
        None
    """

    conn = dB_conn()
    c = conn.cursor()
    query = 'UPDATE tasks SET status = "{}" WHERE id = {}'.format(text, task_id)
    c.execute(query)
    conn.commit()
    conn.close()


def insert_new_task(text: str) ->  int:
    """Insert new task to todo table.
    Args:
        text (str): Task description
    Returns: The task ID for the inserted entry
    """

    conn = dB_conn()
    c = conn.cursor()
    query = 'Insert Into tasks (task, status) VALUES ("{}", "{}")'.format(
        text, "Todo")
    conn.execute(query)
    query_results = c.execute("SELECT last_insert_rowid()")
    query_results = [x for x in query_results]
    task_id = query_results[0][0]
    conn.commit()
    conn.close()

    return task_id


def remove_task_by_id(task_id: int) -> None:
    """ remove entries based on task ID """
    conn = dB_conn()
    c = conn.cursor()
    query = 'DELETE FROM tasks WHERE id={}'.format(task_id)
    c.execute(query)
    conn.commit()
    conn.close()



#### BLOCK 3
""" Specifies routing for the application"""


@app.route("/delete/<int:task_id>", methods=['POST'])
def delete(task_id):
    """ recieved post requests for entry delete """

    try:
        remove_task_by_id(task_id)
        result = {'success': True, 'response': 'Removed task'}
    except:
        result = {'success': False, 'response': 'Something went wrong'}

    return jsonify(result)


@app.route("/edit/<int:task_id>", methods=['POST'])
def update(task_id):
    """ recieved post requests for entry updates """

    data = request.get_json()

    try:
        if "status" in data:
            update_status_entry(task_id, data["status"])
            result = {'success': True, 'response': 'Status Updated'}
        elif "description" in data:
            update_task_entry(task_id, data["description"])
            result = {'success': True, 'response': 'Task Updated'}
        else:
            result = {'success': True, 'response': 'Nothing Updated'}
    except:
        result = {'success': False, 'response': 'Something went wrong'}

    return jsonify(result)


@app.route("/create", methods=['POST'])
def create():
    """ recieves post requests to add new task """
    data = request.get_json()
    insert_new_task(data['description'])
    result = {'success': True, 'response': 'Done'}
    return jsonify(result)




@login_manager.user_loader
def load_user(user_id):
    """gets user out of dB"""
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """login function, returns redirecting to an authorized homepage or returns a login page back """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('homepage'))
    return render_template('login.html', form=form)


@app.route("/")
def entry_page():
    """ returns rendered entry page """
    items = fetch_todo()
    return render_template("entry_page.html", items=items)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """ log out an authorised session and redirect to a login page """
    logout_user()
    return redirect(url_for('login'))


@app.route("/index")
@login_required
def homepage():
    """ returns rendered homepage for authorized users"""
    items = fetch_todo()
    return render_template("index.html", items=items)


##### by Denis Miroslavsky aka gnuTech, from 0 Flask and jS knowledge up to this, with help of a2975667_tcheng and arpanneupane19 guides, maximum respect to them!

if __name__ == '__main__':
    app.run(debug = True)