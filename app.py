from flask import Flask, jsonify
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Text

app = Flask(__name__)

# تنظیمات اتصال به پایگاه داده PostgreSQL
DATABASE_URI = 'postgresql://postgres:2933230fateme@localhost:5432/vuln_db'
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

# تعریف مدل جدول vuln
class Vuln(Base):
    __tablename__ = 'vuln'
    id = Column(Integer, primary_key=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    cve = Column(String)
    sensor = Column(String)
    endpoint = Column(String)

# خواندن داده‌ها از پایگاه داده
def fetch_data_from_db():
    vuln_data = session.query(Vuln).all()
    data = [{
        'id': vuln.id,
        'title': vuln.title,
        'description': vuln.description,
        'severity': vuln.severity,
        'cve': vuln.cve,
        'sensor': vuln.sensor,
        'endpoint': vuln.endpoint
    } for vuln in vuln_data]
    return data

# خواندن داده‌ها از فایل CSV
def fetch_data_from_csv():
    df = pd.read_csv('vuln2.csv')
    return df.to_dict('records')

# ادغام داده‌ها از پایگاه داده و CSV
def merge_data():
    db_data = fetch_data_from_db()
    csv_data = fetch_data_from_csv()
    return db_data + csv_data

# گروه‌بندی آسیب‌پذیری‌های مشابه
def group_vulnerabilities(data):
    grouped = {}
    for item in data:
        key = (item['endpoint'], item['cve'])
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(item)
    
    result = []
    group_id = 1
    for key, vulnerabilities in grouped.items():
        for vuln in vulnerabilities:
            vuln['tag'] = f'group_{group_id}'
        result.extend(vulnerabilities)
        group_id += 1
    
    return result

# ایجاد API برای برگرداندن لیست آسیب‌پذیری‌های گروه‌بندی شده
@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    data = merge_data()
    grouped_data = group_vulnerabilities(data)
    return jsonify(grouped_data)

if __name__ == '__main__':
    app.run(debug=True)