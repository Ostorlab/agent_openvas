from flask import Flask, json, request
from flask_pymongo import PyMongo
import requests, json

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/openvasdb"
mongo = PyMongo(app)


@app.route('/reports', methods=['POST'])
def get_reprots():
    if request.method == 'POST':
        reportdate = request.form.get('selectedDate')

    reports = mongo.db.vul_reports.find({"report_date": reportdate}).pretty()

    return flask.jsonify([report for report in reports])


if __name__ == '__main__':
    app.run() 