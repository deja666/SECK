import logging
from flask import Flask, flash, render_template, request, jsonify, redirect, make_response, current_app as app, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
from sqlalchemy import func
from decorators import role_required
import requests
from zapv2 import ZAPv2
from threading import Thread
import json, time, uuid, os
from xhtml2pdf import pisa
import io
import whois
from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import unquote
import nmap
from deep_translator import GoogleTranslator
translator = GoogleTranslator(source='en', target='id')
# icon sidebar / icon kembali detail eksploit,domain,vuln
# pesan belum ada

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackerJGNm3ncuri-321'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from models import db, User, Scan, ReconDomain, WappalyzerResult, NmapScan, CVSSScore,Eksploitasi

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
apikey = "atji3c8ninrqb5hb7i052g4bio" #ZAP API

# Initialize database
with app.app_context():
    db.create_all()

def get_data():
    return Scan.query.filter_by(id_user=current_user.id_user).all()

def get_data_domain():
    return ReconDomain.query.filter_by(id_user=current_user.id_user).all()

def get_data_frameworkWAP():
    return WappalyzerResult.query.filter_by(id_user=current_user.id_user).all()

def get_data_scanNmap():
    return NmapScan.query.filter_by(id_user=current_user.id_user).all()

def get_data_cvss():
    return CVSSScore.query.filter_by(id_user=current_user.id_user).all()

def getDataEksploit():
    return Eksploitasi.query.filter_by(id_user=current_user.id_user).all()

def getDataUser():
    return User.query.all()

def getDataDomainByUserRole(model, user_id):
    return db.session.query(model.domain, func.count(model.id)).filter_by(id_user=user_id).group_by(model.domain).count()

def getDataTechByUserRole(model, user_id):
    return db.session.query(model.url, func.count(model.id)).filter_by(id_user=user_id).group_by(model.url).count()

def getDataPortByUserRole(model, user_id):
    return db.session.query(model.hostname, func.count(model.id)).filter_by(id_user=user_id).group_by(model.hostname).count()

def getDataVulnByUserRole(model, user_id):
    return db.session.query(model.target, func.count(model.id)).filter_by(id_user=user_id).group_by(model.target).count()

def getDataExploitByUserRole(model, user_id):
    return db.session.query(model.url, func.count(model.id)).filter_by(id_user=user_id).group_by(model.url).count()

def getDataScoreByUserRole(model, user_id):
    return db.session.query(model.nama_score, func.count(model.id)).filter_by(id_user=user_id).group_by(model.nama_score).count()

@app.route('/')
@login_required
def index():
    user_role = current_user.role
    username = current_user.username
    
    if user_role == 'admin':
        return redirect(url_for('dashboardAdmin'))
    elif user_role == 'operator':
        return redirect(url_for('dashboardOperator'))
    else:
        return redirect(url_for('logout'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('dashboardAdmin'))
            elif user.role == 'operator':
                return redirect(url_for('dashboardOperator'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/manageUser', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manageUser():
    user_role = current_user.role    
    if request.method == 'POST':
        username = request.form.get('Username')
        password = request.form.get('Password')
        role = request.form.get('role')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password,role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('manageUser'))
    return render_template('viewManageUser.html',role=user_role,data=getDataUser())

@app.route('/admin/manageUser/edit/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def ubahUser(id):
    user = User.query.get_or_404(id)
    username = request.form.get('Username')
    password = request.form.get('Password')
    role = request.form.get('role')
    
    user.username = username
    if password:
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
    user.role = role
    
    db.session.commit()
    flash('User berhasil diubah', 'success')
    return redirect(url_for('manageUser'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def dashboardAdmin():
    user_role = current_user.role
    total_user = User.query.count()
    username = current_user.username

    total_user = User.query.count()
    total_pengintaian_domain = ReconDomain.query.count() 
    total_pengintaian_tech = db.session.query(WappalyzerResult.url).distinct().count()
    total_pemindaian_port = db.session.query(NmapScan.hostname).distinct().count()
    total_pemindaian_kerentanan = Scan.query.count() 
    total_eksploit = Eksploitasi.query.count() 
    total_penilaian_kerentanan = CVSSScore.query.count()

    return render_template('dashboardAdmin.html', 
                           role=user_role,
                           username=username,
                           total_user=total_user,
                           total_pengintaian_domain=total_pengintaian_domain,
                           total_pengintaian_tech=total_pengintaian_tech,
                           total_pemindaian_port=total_pemindaian_port,
                           total_pemindaian_kerentanan=total_pemindaian_kerentanan,
                           total_eksploit=total_eksploit,
                           total_penilaian_kerentanan=total_penilaian_kerentanan)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password,role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin/manageUser/delete/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def hapusUser(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User berhasil dihapus', 'success')
    return redirect(url_for('manageUser'))

@app.route('/operator/dashboard', methods=['GET', 'POST'])
@login_required
@role_required('operator')
def dashboardOperator():
    user_role = current_user.role
    user_id = current_user.id_user
    username = current_user.username

    total_pengintaian_domain = getDataDomainByUserRole(ReconDomain,user_id)
    total_pengintaian_tech = getDataTechByUserRole(WappalyzerResult, user_id)
    total_pemindaian_port = getDataPortByUserRole(NmapScan, user_id)
    total_pemindaian_kerentanan = getDataVulnByUserRole(Scan,user_id)
    total_eksploit = getDataExploitByUserRole(Eksploitasi,user_id)
    total_penilaian_kerentanan = getDataScoreByUserRole(CVSSScore,user_id)

    return render_template('dashboardOperator.html',
                           username=username, 
                           role=user_role, 
                           total_pengintaian_domain=total_pengintaian_domain,
                           total_pengintaian_tech=total_pengintaian_tech,
                           total_pemindaian_port=total_pemindaian_port,
                           total_pemindaian_kerentanan=total_pemindaian_kerentanan,
                           total_eksploit=total_eksploit,
                           total_penilaian_kerentanan=total_penilaian_kerentanan)

@app.route('/laporan/<fn>/delete')
def deletelaporan(fn):
    scan = Scan.query.filter_by(nama=fn).first()
    if scan:
        db.session.delete(scan)
        db.session.commit()
    return redirect("/")

@app.route('/laporan/<fn>', methods=['GET'])
@login_required
@role_required('operator')
def laporan(fn):
    user_role = current_user.role
    username = current_user.username
    scan = Scan.query.filter_by(path=fn).first()
    if not scan:
        return "Laporan tidak ditemukan", 404

    with open(f'data/json/{scan.path}.json', 'r') as file:
        data = json.load(file)
    a = [i["deskripsi_masalah"] for i in data["alerts"]]
    dt = translator.translate(scan.dt.strftime('%A %B %d %H:%M:%S'))
    infocount = a.count("Informasional") + a.count("Informasi")

    if request.method == 'GET':
        download = request.args.get('download', 'false').lower()
        if download == 'true':
            context = {
                "dt": dt, 
                "nama": scan.nama, 
                "target": scan.target, 
                "info": infocount,
                "low": a.count("Rendah"), 
                "medium": a.count("Sedang"), 
                "high": a.count("Tinggi"),
                "total": len(a), 
                "vuln": [i for i in data["alerts"]]
            }
            html_str = render_template('exportVuln.html', **context)
            pdf = io.BytesIO()
            pisa_status = pisa.CreatePDF(io.StringIO(html_str), dest=pdf)
            if pisa_status.err:
                return "Error creating PDF", 500
            response = make_response(pdf.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            return response

    return render_template('detailVuln.html', 
                           id=fn, 
                           dt=dt, 
                           nama=scan.nama, 
                           target=scan.target, 
                           info=infocount,
                           low=a.count("Rendah"), 
                           medium=a.count("Sedang"), 
                           high=a.count("Tinggi"), 
                           total=len(a),
                           vuln=[i for i in data["alerts"]],
                           role=user_role,
                           username = username
                           )

logging.basicConfig(level=logging.DEBUG)

def setcache(target, data):
    logging.debug(f"Updating cache for {target} with data: {data}")
    with open(f"cache/{target}.txt", "w+") as f:
        f.write(data)

@app.route('/cache/<target>', methods=['GET'])
def get_and_clear_cache(target):
    cache_file = f"cache/{target}.txt"
    try:
        with open(cache_file, "r") as f:
            data = f.read()
        os.remove(cache_file)
    except FileNotFoundError:
        data = ""
    return jsonify({'data': data})

def add_data(nama, target, jpath, user_id):
    scan = Scan(nama=nama, target=target, path=jpath, id_user=user_id)
    db.session.add(scan)
    db.session.commit()

def start_scan_background(target, nama, jpath, user_id):
    with app.app_context():
        logging.debug(f"Starting ZAP scan for target {target}")
        setcache(nama, f'Memulai ZAP dengan target {target}')
        zap = ZAPv2(apikey=apikey)
        time.sleep(0.5)
        zap.urlopen(target)
        time.sleep(0.5)
        setcache(nama, 'Memulai proses scanning')
        time.sleep(0.5)
        scanid = zap.spider.scan(target)
        time.sleep(0.2)
        while (int(zap.spider.status(scanid)) < 100):
            status = zap.spider.status(scanid)
            setcache(nama, 'Progress scan Spider %: {}'.format(zap.spider.status(scanid)))
            logging.debug(f"Spider scan progress: {status}")
            time.sleep(0.4)

        setcache(nama, 'Scanning selesai')
        setcache(nama, 'Menyimpan hasil scan')
        alerts = []
        data = zap.core.alerts()
        for i in data:
            alerts.append(
                {
                    "nama": i['name'] if i['name'] != "" else "Tak terdefinisi",
                    "deskripsi": i['description'] if i['description'] != "" else "Tak terdefinisi",
                    "deskripsi_masalah": i['risk'] if i['risk'] != "" else "Tak terdefinisi",
                    "solusi_masalah": i['solution'] if i['solution'] != "" else "Tak terdefinisi",
                    "url": i['url'] if 'url' in i else "Tidak tersedia",
                    "evidence": i['evidence'] if 'evidence' in i else "Tidak tersedia",
                    "cweid": i['cweid'] if 'cweid' in i else "Tidak tersedia",
                    "reference": i['reference'] if 'reference' in i else "Tidak tersedia"
                }
            )
        setcache(nama, 'Mengubah bahasa hasil scan menjadi Indonesia')

        texts = [str(i) for i in alerts]
        translated = translator.translate_batch(texts)

        alerts = []

        for translation in translated:
            alerts.append(eval(translation.replace("Medium", "Sedang").replace("Low", "Rendah").replace("Informational", "Informasional")))

        setcache(nama, 'Berhasil Mengubah bahasa hasil scan')

        hasil = {
            "target": target,
            "alerts": alerts,
        }

        with open(f'data/json/{jpath}.json', 'w') as file:
            json.dump(hasil, file, indent=4)
        setcache(nama, 'Berhasil menyimpan hasil scan')
        add_data(nama, target, jpath, user_id)

@app.route('/viewVuln')
@login_required
@role_required('operator')
def viewVuln():
    user_role = current_user.role
    username = current_user.username
    return render_template('viewVuln.html',username=username,role=user_role, data=get_data())

@app.route('/processVuln', methods=['GET', 'POST'])
@login_required
def processVuln():
    if request.method == 'POST':
        name = request.form.get('scan_name')
        target = request.form.get('scan_target')
        jpath = uuid.uuid4().hex[:16]
        user_id = current_user.id_user
        Thread(target=start_scan_background, args=(target, name, jpath, user_id)).start()
        return render_template('processVuln.html', nama=name, path=jpath)
    return render_template('processVuln.html')

@app.route('/viewDomain', methods=['GET', 'POST'])
@login_required
@role_required('operator')
def viewDomain():
    user_role = current_user.role
    username = current_user.username
    if request.method == 'POST':
        domain = request.form['domain']
        
        # Menggunakan library whois untuk mendapatkan informasi domain
        try:
            domain_info = whois.whois(domain)
            domain_id = str(domain_info.domain_id)
            creation_date = str(domain_info.creation_date)
            expiration_date = str(domain_info.expiration_date)
            registrar = str(domain_info.registrar)
            registrar_city = str(domain_info.registrar_city)
            registrar_phone = str(domain_info.registrar_phone)
            name_servers = ', '.join(domain_info.name_servers) if domain_info.name_servers else 'N/A'
        except Exception as e:
            return render_template('error.html', error=str(e))
        
        # Menyimpan hasil whois ke database
        whois_result = ReconDomain(
            domain_id=domain_id,
            domain=domain,
            creation_date=creation_date, 
            expiration_date=expiration_date, 
            registrar=registrar, 
            name_servers=name_servers,
            registrar_city=registrar_city,
            registrar_phone=registrar_phone,
            id_user=current_user.id_user
        )
        db.session.add(whois_result)
        db.session.commit()
        
        return redirect(url_for('detailDomain', result_id=whois_result.id))
    
    return render_template('viewDomain.html',username=username,role=user_role,data=get_data_domain())

@app.route('/detailDomain/<int:result_id>')
@login_required
@role_required('operator')
def detailDomain(result_id):
    user_role = current_user.role
    username = current_user.username
    whois_result = ReconDomain.query.get_or_404(result_id)
    return render_template('detailDomain.html', username = username,whois_result=whois_result, role=user_role)

@app.route('/viewTech', methods=['GET', 'POST'])
@login_required
@role_required('operator')
def viewTech():
    user_role = current_user.role
    username = current_user.username

    if request.method == 'POST':
        url = request.form.get('url')
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url)
            technologies = wappalyzer.analyze(webpage)
            
            # Simpan hasil ke database
            for tech in technologies:
                result = WappalyzerResult(
                    url=url, 
                    technology=tech,
                    id_user=current_user.id_user
                )
                db.session.add(result)
            db.session.commit()
        except requests.exceptions.Timeout:
            error_message = "Timeout: Server tidak merespons dalam waktu yang diizinkan."
            return render_template('viewTech.html', error=error_message)

        except Exception as e:
            error_message = str(e)
            return render_template('viewTech.html', error=error_message)
    
    return render_template('viewTech.html',username = username,role=user_role,data=get_data_frameworkWAP())

@app.route('/getDataTech', methods=['GET'])
@login_required
def getDataTech():
    results = WappalyzerResult.query.filter_by(id_user=current_user.id_user).all()
    data = list(set([result.url for result in results]))  # mengambil url unik
    return jsonify(data)

@app.route('/getDetailDataTech/<path:url>', methods=['GET'])
def getDetailDataTech(url):
    decoded_url = unquote(url)
    results = WappalyzerResult.query.filter_by(id_user=current_user.id_user, url=decoded_url).all()
    result_data = []
    for result in results:
        result_data.append({
            'id': result.id,
            'url': result.url,
            'technology': result.technology
        })
    return jsonify(result_data)

@app.route('/deleteDataTech/<path:url>', methods=['DELETE'])
def deleteDataTech(url):
    decoded_url = unquote(url)
    results = WappalyzerResult.query.filter_by(url=decoded_url).all()
    if results:
        for result in results:
            db.session.delete(result)
        db.session.commit()
        return jsonify({'message': f'All records for URL {url} deleted successfully'}), 200
    else:
        return jsonify({'message': f'No records found for URL {url}'}), 404

def perform_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV --script vulners')

    scan_results = []

    for host in nm.all_hosts():
        hostname = nm[host].hostname()
        state = nm[host].state()

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service_info = nm[host][proto][port]
                port_info = {
                    'hostname': hostname,
                    'state': state,
                    'protocol': proto,
                    'port': port,
                    'service_name': service_info.get('name', 'unknown'),
                    'product': service_info.get('product', 'unknown'),
                    'version': service_info.get('version', 'unknown'),
                    'extrainfo': service_info.get('extrainfo', 'unknown'),
                    'vulners': []
                }

                # Check if 'vulners' script output exists and is in expected format
                if 'script' in service_info and 'vulners' in service_info['script']:
                    vulners_output = service_info['script']['vulners']
                    if isinstance(vulners_output, dict):
                        for vuln_id, vuln_desc in vulners_output.items():
                            vuln_info = {
                                'id': vuln_id,
                                'description': vuln_desc
                            }
                            port_info['vulners'].append(vuln_info)
                            scan_entry = NmapScan(
                                hostname=hostname,
                                state=state,
                                protocol=proto,
                                port=port,
                                service_name=port_info['service_name'],
                                product=port_info['product'],
                                version=port_info['version'],
                                extrainfo=port_info['extrainfo'],
                                vuln_id=vuln_info['id'],
                                vuln_description=vuln_info['description'],
                                id_user=current_user.id_user
                            )
                            db.session.add(scan_entry)

                if not port_info['vulners']:
                    scan_entry = NmapScan(
                        hostname=hostname,
                        state=state,
                        protocol=proto,
                        port=port,
                        service_name=port_info['service_name'],
                        product=port_info['product'],
                        version=port_info['version'],
                        extrainfo=port_info['extrainfo'],
                        vuln_id='None',
                        vuln_description='No vulnerabilities found',
                        id_user=current_user.id_user
                    )
                    db.session.add(scan_entry)

        db.session.commit()
        scan_results.append(port_info)

    return scan_results

@app.route('/get_nmap', methods=['GET'])
@login_required
def get_nmap():
    results = NmapScan.query.filter_by(id_user=current_user.id_user).all()
    data = list(set([result.hostname for result in results]))  # mengambil hostname unik
    return jsonify(data)

@app.route('/get_nmap_detail/<hostname>', methods=['GET'])
@login_required
def get_nmap_detail(hostname):
    scans = NmapScan.query.filter_by(hostname=hostname).all()
    scan_data = []
    for scan in scans:
        scan_data.append({
            'port': scan.port,
            'protocol': scan.protocol,
            'state': scan.state,
            'service_name': scan.service_name,
            'product': scan.product,
            'version': scan.version,
            # 'extrainfo': scan.extrainfo,
            # 'vulnerabilities': scan.vulnerabilities
        })
    return jsonify(scan_data)

@app.route('/viewPort')
@login_required
@role_required('operator')
def viewPort():
    user_role = current_user.role
    username = current_user.username

    return render_template('viewPort.html',username = username,role=user_role,data=get_data_scanNmap())

@app.route('/delete_nmap/<hostname>', methods=['DELETE'])
@login_required
def delete_nmap(hostname):
    results = NmapScan.query.filter_by(id_user=current_user.id_user, hostname=hostname).all()
    for result in results:
        db.session.delete(result)
    db.session.commit()
    return jsonify({"message": f"All records for hostname {hostname} deleted successfully"})

@app.route('/nmap_start', methods=['GET','POST'])
def nmapStart():
    target = request.form.get('target')
    results= perform_nmap_scan(target)
    return redirect(url_for('viewPort'))
    # return render_template('detailPort.html', results=results ,data=get_data_scanNmap())

@app.route('/viewScore')
@login_required
@role_required('operator')
def viewScore():
    user_role = current_user.role
    username = current_user.username
    return render_template('viewScore.html',username =username,role=user_role,data=get_data_cvss())

@app.route('/addScore')
@login_required
@role_required('operator')
def addScore():
    user_role = current_user.role
    username = current_user.username
    return render_template('addScore.html',username = username,role=user_role)

@app.route('/save_cvss', methods=['POST'])
def save_cvss():
    data = request.get_json()
    try:
        new_score = CVSSScore(
            nama_score=data['nama_score'],
            score=data['score'],
            vector=data['vector'],
            id_user=current_user.id_user
        )
        db.session.add(new_score)
        db.session.commit()
        return jsonify(success=True), 201
    except Exception as e:
        print(e)
        return jsonify(success=False), 500

@app.route('/cvss/delete/<int:id>', methods=['POST'])
def deleteCVSS(id):
    try:
        result = CVSSScore.query.get_or_404(id)
        db.session.delete(result)
        db.session.commit()
        return redirect(url_for('viewScore'))
    except SQLAlchemyError as e:
        error_message = str(e)
        return render_template('error.html', error=error_message)
    
@app.route('/viewEksploit',methods=['GET'])
@login_required
@role_required('operator')
def viewEksploit():
    user_role = current_user.role
    username = current_user.username
    return render_template('viewExploit.html',username = username,role=user_role ,data=getDataEksploit())

@app.route('/addEksploit', methods=['POST'])
@login_required
def addEksploit():
    url = request.form.get('url')
    nama_eksploit = request.form.get('nama_eksploit')
    poc = request.form.get('poc')

    print(f"URL: {url}, Nama Eksploit: {nama_eksploit}, POC: {poc}")

    tambahEksploit = Eksploitasi(
        id_user=current_user.id_user,
        url=url,
        nama_eksploit=nama_eksploit,
        poc=poc
    )

    try:
        db.session.add(tambahEksploit)
        db.session.commit()
        flash('Data Eksploit berhasil ditambahkan', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Gagal menambahkan Data Eksploit', 'danger')

    return redirect(url_for('viewEksploit'))

@app.route('/editEksploit/<int:id>', methods=['GET', 'POST'])
@login_required
def editEksploit(id):
    eksploit = Eksploitasi.query.get_or_404(id)

    if request.method == 'POST':
        eksploit.url = request.form.get('url')
        eksploit.nama_eksploit = request.form.get('nama_eksploit')
        eksploit.poc = request.form.get('poc')

        try:
            db.session.commit()
            flash('Eksploit berhasil diperbarui', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Gagal memperbarui eksploit', 'danger')

        return redirect(url_for('viewEksploit'))

    return render_template('editEksploit.html', eksploit=eksploit)

@app.route('/deleteEksploit/<int:id>', methods=['POST'])
@login_required
def deleteEksploit(id):
    eksploit = Eksploitasi.query.get_or_404(id)

    try:
        db.session.delete(eksploit)
        db.session.commit()
        flash('Eksploit berhasil dihapus', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Gagal menghapus eksploit', 'danger')

    return redirect(url_for('viewEksploit'))

@app.route('/detailEksploit/<int:result_id>')
@login_required
@role_required('operator')
def detailEksploit(result_id):
    resultEksploit = Eksploitasi.query.get_or_404(result_id)
    user_role = current_user.role
    username = current_user.username
    return render_template('detailEksploit.html',username = username,role=user_role,data=resultEksploit)

if __name__ == '__main__':
    app.run(debug=True, port=9092, host='0.0.0.0')
