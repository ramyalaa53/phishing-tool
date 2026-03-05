from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from models import db, User, ScanHistory, Blacklist, Whitelist
from forms import RegisterForm, LoginForm, URLForm, BlacklistForm, WhitelistForm
from rules import evaluate_url
from utils import export_history_to_csv
import os
import socket
import tempfile
import time
import mimetypes
import requests
from dotenv import load_dotenv

# ---------------- إعدادات عامة ----------------
load_dotenv()
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 50 * 1024 * 1024))  # 50MB
VT_API_KEY_ENV = "VIRUSTOTAL_API_KEY"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'replace_this_with_a_strong_secret')
    base_dir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'phishing.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------------- الصفحة الرئيسية ----------------
    @app.route('/')
    def home():
        form = URLForm()

        return render_template('index.html', form=form)

    # ---------------- فحص الروابط ----------------
    @app.route('/check', methods=['POST'])
    def check():
        form = URLForm()
        if form.validate_on_submit():
            url = form.url.data.strip()
            blacklist = [b.pattern for b in Blacklist.query.all()]
            whitelist = [w.pattern for w in Whitelist.query.all()]

            res = evaluate_url(url, blacklist_patterns=blacklist, whitelist_patterns=whitelist)
            score = res.get('score', 0)
            result_text = res.get('result', '')
            reasons = '; '.join(res.get('reasons', []))
            user_id = current_user.id if current_user.is_authenticated else None

            entry = ScanHistory(user_id=user_id, url=url, result=result_text, score=score, reasons=reasons)
            db.session.add(entry)

            # ✅ لو النتيجة خطر أو مشبوهة أضفها تلقائيًا للـ blacklist
            if any(word in result_text.lower() for word in ['malicious', 'suspicious', 'phishing', 'blacklisted']):
                if not Blacklist.query.filter_by(pattern=url).first():
                    db.session.add(Blacklist(pattern=url, note="Auto-added after suspicious scan"))

            db.session.commit()
            return render_template('index.html', form=form, scan=res, url=url)

        flash("Invalid input", "danger")
        return redirect(url_for('home'))

    # ---------------- فحص الملفات (VirusTotal) ----------------
    @app.route('/scan_file', methods=['POST'])
    def scan_file():
        """
        Uploads received file to VirusTotal, polls until analysis completes (or times out),
        stores a ScanHistory entry, and renders the index with scan_file_summary.
        """
        VT_API_KEY = os.environ.get(VT_API_KEY_ENV)
        if not VT_API_KEY:
            flash("VirusTotal API key not configured on server.", "danger")
            return redirect(url_for('home'))

        if 'file' not in request.files:
            flash("No file uploaded.", "warning")
            return redirect(url_for('home'))

        file = request.files['file']
        if not file or file.filename == '':
            flash("No file selected.", "warning")
            return redirect(url_for('home'))

        filename = secure_filename(file.filename)
        tmp = tempfile.NamedTemporaryFile(delete=False)

        try:
            file.save(tmp.name)
            tmp.close()

            # السماح بكل أنواع الملفات (fallback generic)
            mime_type, _ = mimetypes.guess_type(tmp.name)
            if not mime_type:
                mime_type = "application/octet-stream"

            if os.path.getsize(tmp.name) > MAX_FILE_SIZE:
                flash(f"File too large (limit {MAX_FILE_SIZE // (1024 * 1024)} MB).", "danger")
                return redirect(url_for('home'))

            # رفع الملف إلى VirusTotal
            headers = {"x-apikey": VT_API_KEY}
            with open(tmp.name, 'rb') as f:
                files = {'file': (filename, f)}
                upload_resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

            if upload_resp.status_code not in (200, 201):
                # اضف التفاصيل عشان تعرف السبب (403, 400, quota, ...)
                flash(f"Upload failed ({upload_resp.status_code}): {upload_resp.text}", "danger")
                return redirect(url_for('home'))

            analysis_id = upload_resp.json().get("data", {}).get("id")
            if not analysis_id:
                flash("Failed to get analysis ID from VirusTotal.", "danger")
                return redirect(url_for('home'))

            # انتظار انتهاء التحليل (polling)
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            headers = {"x-apikey": VT_API_KEY}

            for _ in range(20):  # تقريبًا 20 مرات * 5 ثواني = 100 ثانية كحد أقصى
                resp = requests.get(analysis_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        stats = data["data"]["attributes"]["stats"]
                        sha256 = data.get("meta", {}).get("file_info", {}).get("sha256", "")
                        vt_link = f"https://www.virustotal.com/gui/file/{sha256}/detection"

                        summary = {
                            "filename": filename,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "harmless": stats.get("harmless", 0),
                            "vt_link": vt_link
                        }

                        # حفظ النتيجة في قاعدة البيانات
                        entry = ScanHistory(
                            user_id=current_user.id if current_user.is_authenticated else None,
                            url=filename,
                            result=f"File scan: {summary['malicious']} malicious, {summary['suspicious']} suspicious",
                            score=summary['malicious'],
                            reasons=f"sha256: {sha256}"
                        )
                        db.session.add(entry)
                        db.session.commit()

                        flash("File scanned successfully!", "success")
                        return render_template('index.html', form=URLForm(), scan_file_summary=summary)

                # انتظر قبل الطلب التالي
                time.sleep(5)

            flash("Analysis not completed yet. Try again later.", "warning")
            return redirect(url_for('home'))

        except Exception as e:
            # اطبع الخطأ في الكونسول للتتبع ثم أعرض رسالة عامة في الواجهة
            import traceback
            print("Error during file scan:", e)
            traceback.print_exc()
            flash(f"Unexpected error during file scan: {e}", "danger")
            return redirect(url_for('home'))

        finally:
            # احذف الملف المؤقت دائمًا
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

    # ---------------- التسجيل وتسجيل الدخول ----------------
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data).first():
                flash("Email already registered", "warning")
                return redirect(url_for('register'))
            user = User(name=form.name.data, email=form.email.data,
                        password_hash=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            flash("Account created. Login now.", "success")
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Logged in successfully", "success")
                return redirect(url_for('dashboard'))
            flash("Invalid credentials", "danger")
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash("Logged out", "info")
        return redirect(url_for('home'))

    # ---------------- لوحة التحكم ----------------
    @app.route('/dashboard')
    @login_required
    def dashboard():
        form = URLForm()
        rows = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).limit(20).all()
        return render_template('dashboard.html', form=form, rows=rows)

    @app.route('/history')
    @login_required
    def history():
        rows = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).all()
        return render_template('history.html', rows=rows)

    @app.route('/delete_scan/<int:scan_id>', methods=['POST', 'GET'])
    @login_required
    def delete_scan(scan_id):
        record = ScanHistory.query.get_or_404(scan_id)
        if record.user_id != current_user.id and getattr(current_user, 'role', '') != 'admin':
            flash("You are not authorized to delete this record.", "danger")
            return redirect(url_for('dashboard'))

        try:
            db.session.delete(record)
            db.session.commit()
            flash("Scan deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting record: {e}", "danger")

        return redirect(url_for('dashboard'))

    @app.route('/export_history')
    @login_required
    def export_history():
        rows = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).all()
        buf = export_history_to_csv(rows)
        return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='scan_history.csv')

    # ---------------- الأدمن والقوائم ----------------
    def admin_required(func):
        from functools import wraps
        @wraps(func)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or getattr(current_user, 'role', '') != 'admin':
                flash("Admin access required", "danger")
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return decorated

    @app.route('/admin')
    @login_required
    @admin_required
    def admin():
        rows = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(100).all()
        blacklist = Blacklist.query.all()
        whitelist = Whitelist.query.all()
        return render_template('admin.html', rows=rows, blacklist=blacklist, whitelist=whitelist)

    @app.route('/blacklist', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def blacklist_page():
        form = BlacklistForm()
        if form.validate_on_submit():
            if not Blacklist.query.filter_by(pattern=form.pattern.data.strip()).first():
                db.session.add(Blacklist(pattern=form.pattern.data.strip(), note=form.note.data))
                db.session.commit()
                flash("Added to blacklist", "success")
            else:
                flash("Already exists in blacklist", "warning")
            return redirect(url_for('blacklist_page'))
        items = Blacklist.query.order_by(Blacklist.id.desc()).all()
        return render_template('blacklist.html', form=form, items=items)

    @app.route('/whitelist', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def whitelist_page():
        form = WhitelistForm()
        if form.validate_on_submit():
            if not Whitelist.query.filter_by(pattern=form.pattern.data.strip()).first():
                db.session.add(Whitelist(pattern=form.pattern.data.strip(), note=form.note.data))
                db.session.commit()
                flash("Added to whitelist", "success")
            else:
                flash("Already exists in whitelist", "warning")
            return redirect(url_for('whitelist_page'))
        items = Whitelist.query.order_by(Whitelist.id.desc()).all()
        return render_template('blacklist.html', form=form, items=items, whitelist=True)

    @app.route('/delete_blacklist/<int:item_id>')
    @login_required
    @admin_required
    def delete_blacklist(item_id):
        b = Blacklist.query.get_or_404(item_id)
        db.session.delete(b)
        db.session.commit()
        flash("Deleted from blacklist", "info")
        return redirect(url_for('blacklist_page'))

    @app.route('/delete_whitelist/<int:item_id>')
    @login_required
    @admin_required
    def delete_whitelist(item_id):
        w = Whitelist.query.get_or_404(item_id)
        db.session.delete(w)
        db.session.commit()
        flash("Deleted from whitelist", "info")
        return redirect(url_for('whitelist_page'))

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    return app


import os

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)