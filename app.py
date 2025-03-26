import os
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# Configuración de la aplicación Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'clave_secreta'

# Configuración para subir archivos
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}

# Inicialización de la base de datos y seguridad
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Modelo de usuario


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta principal que redirige al login


@app.route('/')
def home():
    return redirect(url_for('login'))

# Ruta para el login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # <-- Mensaje de depuración
            print(f"✅ Usuario autenticado: {user.username}")
            return redirect(url_for('dashboard'))
        else:
            flash("Usuario o contraseña incorrectos", "danger")
            # Redirigir limpia los mensajes duplicados
            print("❌ Error de autenticación")  # <-- Mensaje si fallA
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No se seleccionó ningún archivo", "danger")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash("Nombre de archivo inválido", "danger")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash("Archivo subido con éxito", "success")

    return render_template('dashboard.html', username=current_user.username)

# Ruta para el logout


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Función para verificar extensiones de archivos


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ruta protegida (dashboard) con subida de archivos


# Ruta para el registro de usuarios


# Ruta para el registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Verificar si las contraseñas coinciden
        if password != confirm_password:
            return render_template('register.html', error="Las contraseñas no coinciden")

        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="El usuario ya existe")

        # Hashear la contraseña y guardar el usuario
        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Redirige al login después del registro
        return redirect(url_for('login'))

    return render_template('register.html')


# Ejecutar la aplicación
if __name__ == '__main__':
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)
