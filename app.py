from flask import Flask, render_template, url_for, request, redirect, session
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import os
from flask_sqlalchemy import SQLAlchemy
from main import parse_file, flow_of_data, possible_sql_injection, get_vulnerable_data

app = Flask(__name__)
app.secret_key = 'supersecretkeyhello'

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
            file.save(filepath)
            session['uploaded_file'] = filepath
            parse = parse_file(filepath)
            sql_detection = possible_sql_injection(filepath)
            show_data = get_vulnerable_data(filepath)
            return render_template('parse.html',
                                   file=parse,
                                   sql=sql_detection,
                                   data=show_data)
    except RequestEntityTooLarge:
        return "File is larger than the 16MB limit"
    return redirect('/')

@app.route('/upload/flow', methods=["POST"])
def flow():
    existing_file = session.get('uploaded_file')
    source = request.form['source']
    sink = request.form['sink']
    parse = parse_file(existing_file)
    flow = flow_of_data(existing_file, source, sink)
    return render_template('flow.html', file=flow, list=parse)


if __name__ == "__main__":
    app.run(debug=True)