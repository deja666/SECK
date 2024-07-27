from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id_user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    
    def get_id(self):
        return str(self.id_user)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    nama = db.Column(db.String(255), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    dt = db.Column(db.DateTime, default=datetime.utcnow)

class ReconDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    domain_id = db.Column(db.String(255))
    creation_date = db.Column(db.String(255))
    expiration_date = db.Column(db.String(255))
    registrar = db.Column(db.String(255))
    registrar_city= db.Column(db.String(255))
    registrar_phone= db.Column(db.String(255))
    name_servers = db.Column(db.Text)

class WappalyzerResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    technology = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<WappalyzerResult {self.id}>'

class NmapScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    hostname = db.Column(db.VARCHAR(100))
    state = db.Column(db.String(50))
    protocol = db.Column(db.String(50))
    port = db.Column(db.Integer)
    service_name = db.Column(db.String(255))
    product = db.Column(db.String(255))
    version = db.Column(db.String(255))
    extrainfo = db.Column(db.String(255))
    vuln_id = db.Column(db.String(255))
    vuln_description = db.Column(db.Text)

class CVSSScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    nama_score = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Float, nullable=False)
    vector = db.Column(db.String(200), nullable=False)

class Eksploitasi(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id_user'), nullable=False)
    nama_eksploit = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(100), nullable=False)
    poc = db.Column(db.Text)