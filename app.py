from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, re, random, string
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = "leonor_maquina_secret_2026_mz_super_segura"
app.permanent_session_lifetime = timedelta(days=7)

UPLOAD_FOLDER = "static/uploads"
ALLOWED = {"png","jpg","jpeg","gif","webp","pdf","docx","txt","mp4","mp3"}
IMG_EXT = {"png","jpg","jpeg","gif","webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB = "banco.db"

# ============ CONEXÃO BLINDADA ============
@contextmanager
def db():
    """Context manager que SEMPRE fecha a conexão."""
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def init_db():
    with db() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT, email TEXT UNIQUE, telefone TEXT UNIQUE,
                senha TEXT, foto TEXT DEFAULT 'default.png',
                bio TEXT DEFAULT '', criado_em TEXT);
            CREATE TABLE IF NOT EXISTS arquivos(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER, nome_original TEXT, nome_arquivo TEXT,
                tipo TEXT, tamanho INTEGER, enviado_em TEXT);
            CREATE TABLE IF NOT EXISTS mensagens(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remetente_id INTEGER, destinatario_id INTEGER,
                texto TEXT, lida INTEGER DEFAULT 0, enviado_em TEXT);
            CREATE TABLE IF NOT EXISTS tokens(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER, token TEXT UNIQUE,
                expira_em TEXT, usado INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS acessos(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER, ip TEXT, data TEXT);
        """)

init_db()

# ============ HELPERS ============
def validar_telefone_mz(tel):
    tel = re.sub(r"\D", "", tel)
    return bool(re.match(r"^8[4-7]\d{7}$", tel))

def validar_email(email):
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email))

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            flash("Faça login primeiro.", "erro")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

# ============ ROTAS ============
@app.route("/", methods=["GET","POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("perfil"))
    if request.method == "POST":
        ident = request.form.get("identificador","").strip()
        senha = request.form.get("senha","")
        with db() as con:
            u = con.execute("SELECT * FROM usuarios WHERE email=? OR telefone=?",
                            (ident, ident)).fetchone()
        if u and check_password_hash(u["senha"], senha):
            session.permanent = True
            session["user_id"] = u["id"]
            session["nome"] = u["nome"]
            with db() as con:
                con.execute("INSERT INTO acessos(usuario_id,ip,data) VALUES(?,?,?)",
                            (u["id"], request.remote_addr,
                             datetime.now().strftime("%Y-%m-%d %H:%M")))
            return redirect(url_for("perfil"))
        flash("Email/Telefone ou senha incorretos!", "erro")
    return render_template("login.html")

@app.route("/cadastro", methods=["GET","POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form.get("nome","").strip()
        email = request.form.get("email","").strip().lower()
        telefone = re.sub(r"\D", "", request.form.get("telefone",""))
        senha = request.form.get("senha","")
        confirma = request.form.get("confirma","")
        if not nome or len(nome) < 3:
            flash("Nome inválido.", "erro")
        elif not validar_email(email):
            flash("Email inválido.", "erro")
        elif not validar_telefone_mz(telefone):
            flash("Telefone MZ inválido. Use 84/85/86/87 + 7 dígitos.", "erro")
        elif len(senha) < 6:
            flash("Senha mínima: 6 caracteres.", "erro")
        elif senha != confirma:
            flash("Senhas não coincidem.", "erro")
        else:
            try:
                with db() as con:
                    con.execute("""INSERT INTO usuarios(nome,email,telefone,senha,criado_em)
                        VALUES(?,?,?,?,?)""",
                        (nome,email,telefone,generate_password_hash(senha),
                         datetime.now().strftime("%Y-%m-%d %H:%M")))
                flash("Conta criada! Faça login.", "sucesso")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Email ou telefone já cadastrado.", "erro")
    return render_template("cadastro.html")

@app.route("/recuperar", methods=["GET","POST"])
def recuperar():
    if request.method == "POST":
        ident = request.form.get("identificador","").strip().lower()
        with db() as con:
            u = con.execute("SELECT * FROM usuarios WHERE email=? OR telefone=?",
                            (ident, ident)).fetchone()
            if u:
                token = ''.join(random.choices(string.ascii_letters+string.digits, k=40))
                expira = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
                con.execute("INSERT INTO tokens(usuario_id,token,expira_em) VALUES(?,?,?)",
                            (u["id"], token, expira))
                link = url_for("resetar", token=token, _external=True)
                flash(f"Link de recuperação (válido 1h): {link}", "sucesso")
            else:
                flash("Se existir conta, enviaremos instruções.", "sucesso")
        return redirect(url_for("login"))
    return render_template("recuperar.html")

@app.route("/resetar/<token>", methods=["GET","POST"])
def resetar(token):
    with db() as con:
        t = con.execute("SELECT * FROM tokens WHERE token=? AND usado=0",
                        (token,)).fetchone()
    if not t:
        flash("Token inválido ou usado.", "erro")
        return redirect(url_for("login"))
    if datetime.strptime(t["expira_em"], "%Y-%m-%d %H:%M") < datetime.now():
        flash("Token expirado.", "erro")
        return redirect(url_for("login"))
    if request.method == "POST":
        senha = request.form.get("senha","")
        confirma = request.form.get("confirma","")
        if len(senha) < 6 or senha != confirma:
            flash("Senhas inválidas ou não coincidem.", "erro")
        else:
            with db() as con:
                con.execute("UPDATE usuarios SET senha=? WHERE id=?",
                            (generate_password_hash(senha), t["usuario_id"]))
                con.execute("UPDATE tokens SET usado=1 WHERE id=?", (t["id"],))
            flash("Senha alterada! Faça login.", "sucesso")
            return redirect(url_for("login"))
    return render_template("resetar.html", token=token)

@app.route("/perfil")
@login_required
def perfil():
    with db() as con:
        u = con.execute("SELECT * FROM usuarios WHERE id=?",
                        (session["user_id"],)).fetchone()
        nl = con.execute("""SELECT COUNT(*) c FROM mensagens
            WHERE destinatario_id=? AND lida=0""",
            (session["user_id"],)).fetchone()["c"]
    return render_template("perfil.html", user=u, nao_lidas=nl)

@app.route("/atualizar_perfil", methods=["POST"])
@login_required
def atualizar_perfil():
    nome = request.form.get("nome","").strip()
    email = request.form.get("email","").strip().lower()
    telefone = re.sub(r"\D", "", request.form.get("telefone",""))
    bio = request.form.get("bio","").strip()
    with db() as con:
        con.execute("UPDATE usuarios SET nome=?, email=?, telefone=?, bio=? WHERE id=?",
                    (nome,email,telefone,bio,session["user_id"]))
    session["nome"] = nome
    flash("Perfil atualizado!", "sucesso")
    return redirect(url_for("perfil"))

@app.route("/upload_foto", methods=["POST"])
@login_required
def upload_foto():
    f = request.files.get("foto")
    if f and f.filename:
        ext = f.filename.rsplit(".",1)[-1].lower()
        if ext in IMG_EXT:
            nome = f"perfil_{session['user_id']}_{int(datetime.now().timestamp())}.{ext}"
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], nome))
            with db() as con:
                con.execute("UPDATE usuarios SET foto=? WHERE id=?",
                            (nome, session["user_id"]))
            flash("Foto atualizada!", "sucesso")
    return redirect(url_for("perfil"))

@app.route("/storage", methods=["GET","POST"])
@login_required
def storage():
    if request.method == "POST":
        with db() as con:
            for f in request.files.getlist("arquivos"):
                if f and f.filename:
                    ext = f.filename.rsplit(".",1)[-1].lower()
                    if ext in ALLOWED:
                        seguro = secure_filename(f.filename)
                        nome_final = f"{session['user_id']}_{int(datetime.now().timestamp())}_{seguro}"
                        caminho = os.path.join(app.config["UPLOAD_FOLDER"], nome_final)
                        f.save(caminho)
                        con.execute("""INSERT INTO arquivos
                            (usuario_id,nome_original,nome_arquivo,tipo,tamanho,enviado_em)
                            VALUES(?,?,?,?,?,?)""",
                            (session["user_id"], f.filename, nome_final, ext,
                             os.path.getsize(caminho),
                             datetime.now().strftime("%d/%m/%Y %H:%M")))
        flash("Arquivos enviados!", "sucesso")
    with db() as con:
        arquivos = con.execute("SELECT * FROM arquivos WHERE usuario_id=? ORDER BY id DESC",
                               (session["user_id"],)).fetchall()
    return render_template("storage.html", arquivos=arquivos)

@app.route("/deletar_arquivo/<int:aid>")
@login_required
def deletar_arquivo(aid):
    with db() as con:
        a = con.execute("SELECT * FROM arquivos WHERE id=? AND usuario_id=?",
                        (aid, session["user_id"])).fetchone()
        if a:
            try: os.remove(os.path.join(app.config["UPLOAD_FOLDER"], a["nome_arquivo"]))
            except: pass
            con.execute("DELETE FROM arquivos WHERE id=?", (aid,))
    return redirect(url_for("storage"))

@app.route("/chat")
@app.route("/chat/<int:uid>")
@login_required
def chat(uid=None):
    with db() as con:
        usuarios = con.execute("SELECT id,nome,foto FROM usuarios WHERE id!=?",
                               (session["user_id"],)).fetchall()
        if uid is None and usuarios:
            uid = usuarios[0]["id"]
        destinatario = None
        mensagens = []
        if uid:
            destinatario = con.execute("SELECT id,nome,foto FROM usuarios WHERE id=?",
                                       (uid,)).fetchone()
            mensagens = con.execute("""SELECT * FROM mensagens
                WHERE (remetente_id=? AND destinatario_id=?)
                   OR (remetente_id=? AND destinatario_id=?)
                ORDER BY id ASC""",
                (session["user_id"], uid, uid, session["user_id"])).fetchall()
            con.execute("""UPDATE mensagens SET lida=1
                WHERE destinatario_id=? AND remetente_id=?""",
                (session["user_id"], uid))
    return render_template("chat.html", usuarios=usuarios,
                           destinatario=destinatario, mensagens=mensagens, uid=uid)

@app.route("/api/enviar", methods=["POST"])
@login_required
def api_enviar():
    data = request.get_json()
    uid = data.get("destinatario")
    texto = data.get("texto","").strip()
    if not texto or not uid:
        return jsonify({"ok": False})
    with db() as con:
        con.execute("""INSERT INTO mensagens(remetente_id,destinatario_id,texto,enviado_em)
            VALUES(?,?,?,?)""",
            (session["user_id"], uid, texto,
             datetime.now().strftime("%d/%m/%Y %H:%M")))
    return jsonify({"ok": True})

@app.route("/api/mensagens/<int:uid>")
@login_required
def api_mensagens(uid):
    with db() as con:
        msgs = con.execute("""SELECT * FROM mensagens
            WHERE (remetente_id=? AND destinatario_id=?)
               OR (remetente_id=? AND destinatario_id=?)
            ORDER BY id ASC""",
            (session["user_id"], uid, uid, session["user_id"])).fetchall()
    return jsonify([dict(m) for m in msgs])

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        ta = con.execute("SELECT COUNT(*) c FROM arquivos WHERE usuario_id=?",
                         (session["user_id"],)).fetchone()["c"]
        esp = con.execute("SELECT COALESCE(SUM(tamanho),0) t FROM arquivos WHERE usuario_id=?",
                          (session["user_id"],)).fetchone()["t"]
        tm = con.execute("""SELECT COUNT(*) c FROM mensagens
            WHERE remetente_id=? OR destinatario_id=?""",
            (session["user_id"], session["user_id"])).fetchone()["c"]
        tu = con.execute("SELECT COUNT(*) c FROM usuarios").fetchone()["c"]
        ac = con.execute("""SELECT data FROM acessos WHERE usuario_id=?
            ORDER BY id DESC LIMIT 7""", (session["user_id"],)).fetchall()
    return render_template("dashboard.html",
        total_arquivos=ta, espaco=round(esp/1024/1024, 2),
        total_msgs=tm, total_usuarios=tu,
        acessos=[a["data"] for a in ac])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.errorhandler(413)
def grande(e):
    flash("Arquivo muito grande (máx 50 MB).", "erro")
    return redirect(url_for("storage"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
