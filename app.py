from flask import Flask, render_template, url_for, request, redirect
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import os
from flask_sqlalchemy import SQLAlchemy
from main import *

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["UPLOAD_DIRECTORY"] = 'uploads/'
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
db = SQLAlchemy(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=["POST"])
def upload():
    try:
        file = request.files['upload-code']
        if file:
            filepath = os.path.join(
                app.config["UPLOAD_DIRECTORY"],
                secure_filename(file.filename)
            )
            # files = os.listdir(app.config["UPLOAD_DIRECTORY"])
            file.save(filepath)
            parse = parse_file(filepath)
            return render_template('parse.html', file=parse)
    except RequestEntityTooLarge:
        return "File is larger than the 16MB limit"
    return redirect('/')



if __name__ == "__main__":
    app.run(debug=True)