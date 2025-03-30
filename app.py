from flask import send_from_directory
import os
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask import send_from_directory
from flask_migrate import Migrate


# Configuración de la aplicación Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'clave_secreta'

# Configuración para subir archivos
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}

# Inicialización de la base de datos y seguridad
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Inicializamos Flask-Migrate
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
    role = db.Column(db.String(50), nullable=False,
                     default="cliente")  # Nuevo campo


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Ruta principal que redirige al login
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    user = db.relationship('User', backref=db.backref('products', lazy=True))


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
    if current_user.role != "vendedor":
        flash("No tienes permisos para acceder al panel de vendedor", "danger")
        return redirect(url_for('catalogo'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No se seleccionó ningún archivo", "danger")
            return redirect(request.url)

        file = request.files['file']
        description = request.form['description']
        price = request.form['price']

        if file.filename == '':
            flash("Nombre de archivo inválido", "danger")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_product = Product(
                image_filename=filename,
                description=description,
                price=price,
                user_id=current_user.id
            )
            db.session.add(new_product)
            db.session.commit()
            flash("Producto subido con éxito", "success")

    products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', username=current_user.username, products=products)


@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash("No tienes permiso para eliminar este producto", "danger")
        return redirect(url_for('dashboard'))

    db.session.delete(product)
    db.session.commit()
    flash("Producto eliminado con éxito", "success")
    return redirect(url_for('dashboard'))


@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Verifica que el producto pertenece al usuario autenticado
    if product.user_id != current_user.id:
        flash("No tienes permiso para actualizar este producto", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Obtener nuevos datos
        product.description = request.form['description']
        product.price = request.form['price']

        # Si el usuario sube una nueva imagen
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_filename = filename  # Actualizar la imagen en la BD

        # Guardar cambios en la BD
        db.session.commit()
        flash("Producto actualizado con éxito", "success")
        return redirect(url_for('dashboard'))

    return render_template('update_product.html', product=product)


@app.route('/catalogo')
def catalogo():
    productos = Product.query.all()  # Obtener todos los productos de la base de datos
    print(productos)  # Esto imprimirá los productos en la terminal
    return render_template('catalogo.html', productos=productos)


@app.route('/ver_producto/<int:product_id>')
def ver_producto(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('ver_producto.html', product=product)


@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html', user=current_user)


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
        role = request.form['role']  # Nuevo campo

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
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        # Redirige al login después del registro
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Ejecutar la aplicación
if __name__ == '__main__':
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)
