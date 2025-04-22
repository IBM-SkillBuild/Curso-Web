from flask import Flask, render_template, session, request, make_response, redirect, url_for, jsonify, send_from_directory
from utils.database import crear_db, get_db_connection
import sqlite3
import os
import uuid
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
from PIL import Image
import io
import json
from flask_cors import CORS
from flask_session import Session

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp4', 'avi', 'mov', 'mkv'}

# Load environment variables from .env
# load_dotenv()
load_dotenv('/etc/secrets/prod.env')


fecha_ultima_actualizacion = os.getenv('ULTIMA_ACTUALIZACION')
nombre_del_sitio_web = os.getenv('NOMBRE_DEL_SITIO_WEB')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://curso-web-alvr.onrender.com", "http://localhost:5000"], "supports_credentials": True}})

# Flask configuration for sessions
app.secret_key = os.getenv('FLASK_SECRET_KEY') or os.urandom(24)  # Fallback to random key if not set
app.config['SESSION_COOKIE_NAME'] = 'flask_session'  # Explicit cookie name
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime

# Configure Flask-Session to use filesystem
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'sessions')
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 500  # Max session files

# Create sessions directory
try:
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
except OSError as e:
    print(f"Error creating sessions directory: {e}")
    raise

# Initialize Flask-Session
Session(app)

STATIC_FOLDER = 'static'

# Configure OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile', 'prompt': 'select_account'},
    redirect_uri='https://curso-web-alvr.onrender.com/google_callback'
)

# Create database
crear_db()

# Main route
@app.route('/')
def inicio():
    session_token = request.cookies.get('session_token')
    if not session_token:
        return render_template('componentes/login.html')
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, foto FROM users WHERE session_token = ?', (session_token,))
            user = cursor.fetchone()
            if user:
                user_data = {'id': user['id'], 'nombre': user['nombre'], 'foto': user['foto']}
                return render_template('index.html', user=user_data)
            return render_template('componentes/login.html')
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Login route (email/password)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('componentes/login.html')
    
    email = request.form.get('email')
    password = request.form.get('password')
    keep_logged_in = request.form.get('keep_logged_in') == 'on'

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password, nombre FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session_token = str(uuid.uuid4())
                cursor.execute('UPDATE users SET session_token = ? WHERE id = ?', (session_token, user['id']))
                conn.commit()
                response = make_response(render_template('componentes/respuesta_login_ok.html', nombre=user['nombre']))
                response.set_cookie('session_token', session_token, max_age=None if keep_logged_in else 21600)
                return response
            return render_template('componentes/respuesta_login_error.html')
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Google login route
@app.route('/google')
def google_login():
    state = str(uuid.uuid4())
    session['oauth_state'] = state
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri=redirect_uri, state=state)

@app.route('/google_callback')
def google_callback():
    received_state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    if not stored_state or stored_state != received_state:
        print(f"ERROR: mismatching_state: stored_state={stored_state}, received_state={received_state}")
        return "Authentication error: CSRF Warning! State mismatch.", 500

    try:
        token = google.authorize_access_token()
        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
        
        if response.status_code != 200:
            print(f"ERROR: Failed to fetch user info. Status code: {response.status_code}")
            return "Error fetching user info.", 500
            
        user_info = response.json()
        print(f"Received user info: {user_info}")
        email = user_info['email']
        name = user_info['name']
        google_foto = user_info.get('picture', '/static/images/foto-perfil.png')
    except Exception as e:
        print(f"DETAILED ERROR in Google authentication: {str(e)}")
        return "Authentication error. Check server logs for details.", 500

    print(f"Accessing 'users' table with email: {email}")
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, foto FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            
            session_token = str(uuid.uuid4())
            if user:
                print(f"User found: {user['id']}. Updating session_token.")
                foto = user['foto'] if user['foto'] and user['foto'] != '/static/images/foto-perfil.png' else google_foto
                cursor.execute('UPDATE users SET session_token = ?, foto = ? WHERE id = ?', 
                               (session_token, foto, user['id']))
            else:
                print("User not found. Inserting new user.")
                dummy_password = generate_password_hash('google-authenticated')
                cursor.execute('INSERT INTO users (nombre, email, password, session_token, foto) VALUES (?, ?, ?, ?, ?)',
                               (name, email, dummy_password, session_token, google_foto))
            conn.commit()
            print("Database operation completed successfully.")
            response = make_response(redirect(url_for('inicio')))
            response.set_cookie('session_token', session_token, max_age=21600)
            return response
    except sqlite3.Error as e:
        print(f"Database error in /google_callback: {e}")
        return f"Database error: {e}", 500
    except Exception as e:
        print(f"Unexpected error in /google_callback: {e}")
        return f"Unexpected error: {e}", 500

# Logout route
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET session_token = NULL WHERE session_token = ?', (session_token,))
                conn.commit()
        except sqlite3.Error as e:
            return f"Database error: {e}", 500
    
    response = make_response(redirect(url_for('inicio')))
    response.delete_cookie('session_token')
    return response

# Registration route
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'GET':
        return render_template('componentes/registro.html')
    
    nombre = request.form.get('nombre')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not all([nombre, email, password]):
        return render_template('componentes/respuesta_registro_error.html', mensaje="All fields are required"), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return render_template('componentes/respuesta_registro_error.html', mensaje="Email already registered"), 400
            
            session_token = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)
            foto_predeterminada = '/static/images/foto-perfil.png'
            cursor.execute('INSERT INTO users (nombre, email, password, session_token, foto) VALUES (?, ?, ?, ?, ?)',
                          (nombre, email, hashed_password, session_token, foto_predeterminada))
            conn.commit()
            response = make_response(render_template('componentes/respuesta_registro_ok.html', nombre=nombre))
            response.set_cookie('session_token', session_token, max_age=21600)
            return response
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Profile route
@app.route('/perfil', methods=['GET'])
def perfil():
    user_id = request.args.get('id')
    if not user_id:
        return "User ID not provided", 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, email, foto, cursos FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if user:
                user_data = {
                    'id': user['id'],
                    'nombre': user['nombre'],
                    'email': user['email'],
                    'foto': user['foto'],
                    'cursos': user['cursos'] if user['cursos'] else "No courses enrolled",
                }
                return render_template('componentes/perfil.html', user=user_data)
            return "User not found", 404
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Update profile route
@app.route('/actualizar_perfil', methods=['POST'])
def actualizar_perfil():
    user_id = request.form.get('id')
    nombre = request.form.get('nombre')
    foto_url = request.form.get('foto_url')
    foto_file = request.files.get('foto_file')
    print(f"user_id: {user_id}, nombre: {nombre}, foto_url: {foto_url}, foto_file: {foto_file}, foto_file.filename: {getattr(foto_file, 'filename', 'No filename')}")

    if not user_id or not nombre:
        return '<div class="text-red-500">Required data missing</div>', 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT foto, email, cursos FROM users WHERE id = ?', (user_id,))
            resultado = cursor.fetchone()
            if not resultado:
                return '<div class="text-red-500">User not found</div>', 404
            
            foto_actual = resultado['foto']
            email = resultado['email']
            cursos = resultado['cursos']
            nueva_foto = foto_actual

            if foto_file and hasattr(foto_file, 'filename') and foto_file.filename:
                img = Image.open(foto_file)
                width, height = img.size
                if width == height:
                    img = img.resize((100, 100), Image.Resampling.LANCZOS)
                else:
                    nuevo_alto = int((100 / width) * height)
                    img = img.resize((100, nuevo_alto), Image.Resampling.LANCZOS)
                
                os.makedirs(os.path.join(app.static_folder, 'images'), exist_ok=True)
                nombre_archivo = f"user_{user_id}_{uuid.uuid4().hex[:8]}.png"
                ruta_guardado = os.path.join(app.static_folder, 'images', nombre_archivo)
                img.save(ruta_guardado, 'PNG')
                nueva_foto = f"/static/images/{nombre_archivo}"

                if foto_actual and foto_actual.startswith('/static/images/') and foto_actual != '/static/images/foto-perfil.png':
                    ruta_foto_actual = os.path.join(app.static_folder, 'images', os.path.basename(foto_actual))
                    if os.path.exists(ruta_foto_actual):
                        os.remove(ruta_foto_actual)
            elif foto_url:
                nueva_foto = foto_url
                if foto_actual and foto_actual.startswith('/static/images/') and foto_actual != '/static/images/foto-perfil.png':
                    ruta_foto_actual = os.path.join(app.static_folder, 'images', os.path.basename(foto_actual))
                    if os.path.exists(ruta_foto_actual):
                        os.remove(ruta_foto_actual)

            # Update database
            cursor.execute('UPDATE users SET nombre = ?, foto = ? WHERE id = ?', (nombre, nueva_foto, user_id))
            conn.commit()

            mensaje = "Profile updated successfully."
            user_data = {
                'id': user_id,
                'nombre': nombre,
                'email': email,
                'foto': nueva_foto,
                'cursos': cursos if cursos else "No courses enrolled"
            }
            return render_template('componentes/perfil.html', user=user_data, mensaje=mensaje)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return f'<div class="text-red-500">Database error: {e}</div>', 500
    except IOError as e:
        print(f"Error processing image or file: {e}")
        return f'<div class="text-red-500">Error processing image: {e}</div>', 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return f'<div class="text-red-500">Unexpected error: {e}</div>', 500

# List courses route
@app.route('/cursos', methods=['GET'])
def listar_cursos():
    user_id = request.args.get('id')
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, inscritos FROM cursos')
            cursos = cursor.fetchall()
            return render_template("componentes/lista_de_cursos.html", cursos=cursos, user_id=user_id)
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# List users route
@app.route('/users')
def listar_usuarios():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, cursos, foto FROM users')
            usuarios = cursor.fetchall()
            usuarios_procesados = [
                (u['id'], u['nombre'], json.loads(u['cursos']) if u['cursos'] else [], u['foto'])
                for u in usuarios
            ]
            return render_template("componentes/lista_de_usuarios.html", usuarios=usuarios_procesados)
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Add course route
@app.route('/agregar_curso', methods=['GET'])
def agregar_curso():
    user_id = request.args.get('id')
    curso_nombre = request.args.get('curso')

    if not user_id or not curso_nombre:
        return jsonify({'error': 'Missing user ID or course name'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cursos FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            cursos = json.loads(user['cursos']) if user['cursos'] else []
            if curso_nombre not in cursos:
                cursos.append(curso_nombre)
                cursor.execute('UPDATE users SET cursos = ? WHERE id = ?', (json.dumps(cursos), user_id))
                cursor.execute('UPDATE cursos SET inscritos = inscritos + 1 WHERE nombre = ?', (curso_nombre,))
                if cursor.rowcount == 0:
                    cursor.execute('INSERT INTO cursos (nombre, inscritos) VALUES (?, 1)', (curso_nombre,))
                conn.commit()
                return render_template('componentes/respuesta_curso_agregado.html', user_id=user_id, cursos=cursos, curso_nombre=curso_nombre), 200
            return render_template('componentes/respuesta_curso_ya_inscrito.html', user_id=user_id, cursos=cursos, curso_nombre=curso_nombre), 200
    except sqlite3.Error as e:
        return jsonify({'error': f"Database error: {e}"}), 500

# My courses route
@app.route('/mis_cursos', methods=['GET'])
def mis_cursos():
    user_id = request.args.get('id')
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cursos FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return "User not found", 404
            
            cursos = json.loads(user['cursos']) if user['cursos'] else []
            cursos_lista = [{"id": idx + 1, "nombre": curso} for idx, curso in enumerate(cursos)]
            return render_template('componentes/mis_cursos.html', cursos=cursos_lista, user_id=user_id)
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Video list route (HTMX)
@app.route('/lista_de_videos/<nombre_curso>/<int:id_usuario>', methods=['GET'])
def lista_de_videos(nombre_curso, id_usuario):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verify course exists
            curso = cursor.execute('SELECT carpeta FROM cursos WHERE nombre = ?', (nombre_curso,)).fetchone()
            if not curso:
                return "Course not found", 404

            # Fetch videos from videos table
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (nombre_curso,)).fetchall()

            # Fetch user data
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "User not found", 404
            
            videos_terminados = json.loads(usuario['videos_terminados']) if usuario['videos_terminados'] else []
            reproduciendo = json.loads(usuario['reproduciendo']) if usuario['reproduciendo'] else []

            video_reproduciendo = None
            for entry in reproduciendo:
                if entry.get('curso') == nombre_curso:
                    video_reproduciendo = entry.get('video')
                    break

            # Prepare video list for frontend
            videos_lista = [
                {
                    'nombre': video['nombre'],
                    'url': video['url'],
                    'descripcion': video['descripcion'] or '',
                    'terminado': f"{nombre_curso}/{video['nombre']}" in videos_terminados
                }
                for video in videos
            ]

            total_videos = len(videos_lista)
            videos_terminados_count = sum(1 for video in videos_lista if video['terminado'])
            progreso = (videos_terminados_count / total_videos * 100) if total_videos > 0 else 0

            conn.commit()
            print(f"Video list fetched from database: {videos_lista}")
            return render_template('componentes/lista_de_videos.html', 
                                 videos=videos_lista, 
                                 nombre_curso=nombre_curso,
                                 progreso=progreso,
                                 id_usuario=id_usuario,
                                 total_videos=total_videos,
                                 videos_terminados=videos_terminados_count,
                                 video_reproduciendo=video_reproduciendo)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return f"Database error: {e}", 500

# Update playing video route
@app.route('/reproduciendo', methods=['POST'])
def reproduciendo():
    data = request.get_json()
    curso = data.get('curso')
    video = data.get('video')
    id_usuario = data.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return jsonify({'error': 'Missing data: curso, video, or id_usuario'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Fetch user
            cursor.execute('SELECT reproduciendo FROM users WHERE id = ?', (id_usuario,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            # Initialize reproduciendo as empty list if None
            reproduciendo = json.loads(user['reproduciendo']) if user['reproduciendo'] else []
            
            # Create new entry
            new_entry = {'curso': curso, 'video': video}
            
            # Remove existing entry for the same course
            reproduciendo = [entry for entry in reproduciendo if entry['curso'] != curso]
            
            # Add new entry
            reproduciendo.append(new_entry)
            
            # Update database
            cursor.execute('UPDATE users SET reproduciendo = ? WHERE id = ?', 
                          (json.dumps(reproduciendo), id_usuario))
            conn.commit()

            return jsonify({'status': 'success', 'reproduciendo': reproduciendo})
    except sqlite3.Error as e:
        return jsonify({'error': f"Database error: {e}"}), 500

# Mark video as completed route
@app.route('/marcar_video_terminado', methods=['POST'])
def marcar_video_terminado():
    data = request.get_json()
    curso = data.get('curso')
    video = data.get('video')
    id_usuario = data.get('id_usuario')
    duracion = data.get('duracion')

    # Validate required data
    if not all([curso, video, id_usuario]):
        print(f"Missing data: curso={curso}, video={video}, id_usuario={id_usuario}, duracion={duracion}")
        return jsonify({'error': 'Missing data: curso, video, or id_usuario'}), 400

    # Log received duration
    print(f"Received duration: {duracion}, type: {type(duracion)}")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Fetch video watch time and duration
            cursor.execute('SELECT tiempo_visto, duracion FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                print(f"Video {video} not found in course {curso}")
                return jsonify({'error': 'Video not found'}), 404

            tiempo_visto_db = json.loads(video_data['tiempo_visto']) if video_data['tiempo_visto'] else []
            tiempo_visto_usuario = next((float(entry['tiempo']) for entry in tiempo_visto_db if entry.get('id_user') == str(id_usuario)), 0.0)
            duracion_db = video_data['duracion']

            # Handle duration
            if duracion_db is None and duracion is not None:
                try:
                    duracion_db = str(float(duracion))  # Store as string to match schema
                    cursor.execute('UPDATE videos SET duracion = ? WHERE nombre = ? AND curso = ?', 
                                  (duracion_db, video, curso))
                    conn.commit()
                    print(f"Duration updated in DB: {duracion_db}")
                except (ValueError, TypeError) as e:
                    print(f"Error converting received duration: {duracion}, error: {e}")
                    return jsonify({'error': f"Invalid duration: {duracion}"}), 400
            elif duracion_db is None:
                print(f"Duration not available in DB or request for video {video}, course {curso}")
                return jsonify({'error': 'Video duration not available'}), 400

            # Convert duration to float for calculations
            try:
                duracion_db = float(duracion_db)
            except (ValueError, TypeError) as e:
                print(f"Error converting DB duration: {duracion_db}, error: {e}")
                return jsonify({'error': f"Invalid duration format in database: {duracion_db}"}), 400

            # Fetch user's completed videos
            cursor.execute('SELECT videos_terminados FROM users WHERE id = ?', (id_usuario,))
            user = cursor.fetchone()
            if not user:
                print(f"User {id_usuario} not found")
                return jsonify({'error': 'User not found'}), 404

            videos_terminados = json.loads(user['videos_terminados']) if user['videos_terminados'] else []
            video_id = f"{curso}/{video}"

            # Validate if user has watched at least 80% of the video
            umbral = duracion_db * 0.8
            print(f"Validating: tiempo_visto={tiempo_visto_usuario}, umbral={umbral}, duracion_db={duracion_db}")
            if tiempo_visto_usuario < umbral:
                return jsonify({
                    'status': 'insufficient_time',
                    'videos_terminados': videos_terminados,
                    'tiempo_visto': tiempo_visto_usuario,
                    'duracion': duracion_db,
                    'umbral': umbral
                }), 200

            # Mark video as completed if not already in list
            if video_id not in videos_terminados:
                videos_terminados.append(video_id)
                cursor.execute('UPDATE users SET videos_terminados = ? WHERE id = ?', 
                              (json.dumps(videos_terminados), id_usuario))
                conn.commit()
                print(f"Video {video_id} marked as completed for id_usuario={id_usuario}")

            # Check if all videos in course are completed
            cursor.execute('SELECT nombre FROM videos WHERE curso = ?', (curso,))
            todos_videos = cursor.fetchall()
            todos_videos_ids = [f"{curso}/{video['nombre']}" for video in todos_videos]
            videos_terminados_en_curso = [video_id for video_id in todos_videos_ids if video_id in videos_terminados]

            progreso = (len(videos_terminados_en_curso) / len(todos_videos_ids)) * 100 if todos_videos_ids else 0
            progreso_completo = len(videos_terminados_en_curso) == len(todos_videos_ids)

            return jsonify({
                'status': 'success',
                'videos_terminados': videos_terminados,
                'duracion': duracion_db,
                'tiempo_visto': tiempo_visto_usuario,
                'progreso': progreso,
                'progreso_completo': progreso_completo
            })

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': f"Database error: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': f"Unexpected error: {e}"}), 500

@app.route('/tiempo_visto', methods=['GET', 'POST'])
def tiempo_visto():
    if request.method == 'POST':
        data = request.get_json()
        id_usuario = data.get('id_usuario')
        nombre_curso = data.get('nombre_curso')
        video = data.get('video')
        tiempo_incremento = data.get('tiempo_incremento')
        current_time = data.get('current_time')
        duracion = data.get('duracion')
    else:  # GET
        id_usuario = request.args.get('id_usuario')
        nombre_curso = request.args.get('nombre_curso')
        video = request.args.get('video')
        tiempo_incremento = None
        current_time = None
        duracion = None

    if not all([id_usuario, nombre_curso, video]):
        print(f"Missing data: id_usuario={id_usuario}, nombre_curso={nombre_curso}, video={video}")
        return jsonify({'error': 'Missing data'}), 400

    # Log received duration in POST
    if request.method == 'POST':
        print(f"Received duration in /tiempo_visto: {duracion}, type: {type(duracion)}")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT tiempo_visto, tiempo_continuar, duracion FROM videos WHERE nombre = ? AND curso = ?', 
                          (video, nombre_curso))
            video_data = cursor.fetchone()

            if not video_data:
                print(f"Video {video} not found in course {nombre_curso}, inserting...")
                cursor.execute('INSERT OR IGNORE INTO videos (nombre, curso, tiempo_visto, tiempo_continuar, duracion) VALUES (?, ?, ?, ?, ?)',
                              (video, nombre_curso, json.dumps([]), json.dumps([]), None))
                conn.commit()
                tiempo_visto_db = []
                tiempo_continuar_db = []
                duracion_db = None
            else:
                tiempo_visto_db = json.loads(video_data['tiempo_visto']) if video_data['tiempo_visto'] else []
                tiempo_continuar_db = json.loads(video_data['tiempo_continuar']) if video_data['tiempo_continuar'] else []
                duracion_db = video_data['duracion']

            if tiempo_incremento is not None:
                tiempo_incremento = float(tiempo_incremento)
                # Update tiempo_visto by adding real increment
                usuario_encontrado = False
                for i, entry in enumerate(tiempo_visto_db):
                    if entry.get('id_user') == str(id_usuario):
                        tiempo_visto_db[i]['tiempo'] = float(entry.get('tiempo', 0)) + tiempo_incremento
                        usuario_encontrado = True
                        break
                if not usuario_encontrado:
                    tiempo_visto_db.append({'id_user': str(id_usuario), 'tiempo': tiempo_incremento})

                # Update tiempo_continuar if provided
                if current_time is not None:
                    current_time = float(current_time)
                    usuario_encontrado = False
                    for i, entry in enumerate(tiempo_continuar_db):
                        if entry.get('id_user') == str(id_usuario):
                            tiempo_continuar_db[i]['currentTime'] = current_time
                            usuario_encontrado = True
                            break
                    if not usuario_encontrado:
                        tiempo_continuar_db.append({'id_user': str(id_usuario), 'currentTime': current_time})

                # Update duration if provided from frontend
                if duracion_db is None and duracion is not None:
                    try:
                        duracion_db = str(float(duracion))  # Store as string to match schema
                        cursor.execute('UPDATE videos SET duracion = ? WHERE nombre = ? AND curso = ?', 
                                      (duracion_db, video, nombre_curso))
                        print(f"Duration updated in DB: {duracion_db}")
                    except (ValueError, TypeError) as e:
                        print(f"Error converting received duration: {duracion}, error: {e}")
                        return jsonify({'error': f"Invalid duration: {duracion}"}), 400

                cursor.execute('UPDATE videos SET tiempo_visto = ?, tiempo_continuar = ? WHERE nombre = ? AND curso = ?', 
                              (json.dumps(tiempo_visto_db), json.dumps(tiempo_continuar_db), video, nombre_curso))
                conn.commit()
                print(f"Watch time incremented by {tiempo_incremento} seconds for id_usuario={id_usuario} in video={video}, course={nombre_curso}")
                return '', 204
            else:
                # Return tiempo_continuar and duration for specific user
                tiempo_continuar_usuario = next((float(entry['currentTime']) for entry in tiempo_continuar_db if entry.get('id_user') == str(id_usuario)), 0.0)
                try:
                    duracion_float = float(duracion_db) if duracion_db else None
                except (ValueError, TypeError) as e:
                    print(f"Error converting DB duration: {duracion_db}, error: {e}")
                    duracion_float = None
                print(f"Returning tiempo_continuar={tiempo_continuar_usuario}, duracion={duracion_float} for id_usuario={id_usuario}")
                return jsonify({
                    'tiempo_continuar': tiempo_continuar_usuario,
                    'duracion': duracion_float
                })

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': f"Database error: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': f"Unexpected error: {e}"}), 500

# New video request form route (if authorized)
@app.route('/peticion_de_nuevo_video', methods=['GET'])
def peticion_de_nuevo_video():
    session_token = request.cookies.get('session_token')
    if not session_token:
        return render_template('componentes/no_autorizado.html')
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre FROM users WHERE session_token = ?', (session_token,))
            user = cursor.fetchone()
            if not user or user['id'] != 1 or 'eduardo' not in user['nombre'].lower():
                return render_template('componentes/no_autorizado.html')
            
            cursos = cursor.execute('SELECT nombre FROM cursos').fetchall()
            cursos_lista = [curso['nombre'] for curso in cursos]
            return render_template('componentes/formulario_nuevo_video.html', cursos=cursos_lista)
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

# Process new video route
@app.route('/nuevo_video', methods=['POST'])
def nuevo_video():
    session_token = request.cookies.get('session_token')
    if not session_token:
        return render_template('componentes/no_autorizado.html')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre FROM users WHERE session_token = ?', (session_token,))
            user = cursor.fetchone()
            if not user or user['id'] != 1 or 'eduardo' not in user['nombre'].lower():
                return render_template('componentes/no_autorizado.html')

            nombre = request.form.get('nombre')
            video = request.files.get('video')
            video_url = request.form.get('video_url')
            descripcion = request.form.get('descripcion')
            curso = request.form.get('curso')
            video_source = request.form.get('video_source')

            if not all([nombre, curso]):
                return render_template('componentes/error_nuevo_video.html', mensaje="Required data missing (name and course)"), 400

            if video_source == 'upload' and video and video.filename:
                if not allowed_file(video.filename):
                    return render_template('componentes/error_nuevo_video.html', mensaje="Invalid video format. Use mp4, avi, mov, or mkv."), 400
                video_filename = secure_filename(video.filename)
                video_path = os.path.join('static/videos', video_filename)
                video.save(video_path)
                final_url = f'/static/videos/{video_filename}'
            elif video_source == 'url' and video_url:
                final_url = video_url
            else:
                return render_template('componentes/error_nuevo_video.html', mensaje="Must upload a video or provide a valid URL"), 400

            cursor.execute('SELECT id FROM videos WHERE nombre = ? AND curso = ?', (nombre, curso))
            if cursor.fetchone():
                return render_template('componentes/video_ya_existe.html')

            cursor.execute('''
                INSERT INTO videos (nombre, url, descripcion, curso, tiempo_visto, tiempo_continuar, duracion)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (nombre, final_url, descripcion, curso, json.dumps([]), json.dumps([]), None))
            conn.commit()

            return render_template('componentes/video_registrado.html')
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

@app.route('/editar_video', methods=['GET'])
def editar_video():
    curso = request.args.get('curso')
    video = request.args.get('video')
    id_usuario = request.args.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Missing data: curso, video, or id_usuario"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nombre, url, descripcion FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video not found"), 404

            return render_template('componentes/formulario_editar_video.html',
                                 curso=curso,
                                 video=video_data['nombre'],
                                 url=video_data['url'],
                                 descripcion=video_data['descripcion'] or '',
                                 id_usuario=id_usuario)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Database error: {e}"), 500    

@app.route('/borrar_video', methods=['GET'])
def borrar_video():
    curso = request.args.get('curso')
    video = request.args.get('video')
    id_usuario = request.args.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Missing data: curso, video, or id_usuario"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nombre FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video not found"), 404

            return render_template('componentes/formulario_borrar_video.html',
                                 curso=curso,
                                 video=video,
                                 id_usuario=id_usuario)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Database error: {e}"), 500

@app.route('/actualizar_video', methods=['POST'])
def actualizar_video():
    curso = request.form.get('curso')
    video_original = request.form.get('video_original')
    nombre = request.form.get('nombre')
    url = request.form.get('url')
    descripcion = request.form.get('descripcion')
    id_usuario = request.form.get('id_usuario')

    if not all([curso, video_original, nombre, url, id_usuario]):
        return render_template('componentes/error.html', mensaje="Missing required data"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE videos SET nombre = ?, url = ?, descripcion = ? WHERE nombre = ? AND curso = ?',
                          (nombre, url, descripcion, video_original, curso))
            if cursor.rowcount == 0:
                return render_template('componentes/error.html', mensaje="Video not found"), 404

            # Fetch updated video list
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (curso,)).fetchall()
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "User not found", 404
            
            videos_terminados = json.loads(usuario['videos_terminados']) if usuario['videos_terminados'] else []
            reproduciendo = json.loads(usuario['reproduciendo']) if usuario['reproduciendo'] else []

            video_reproduciendo = None
            for entry in reproduciendo:
                if entry.get('curso') == curso:
                    video_reproduciendo = entry.get('video')
                    break

            videos_lista = [
                {
                    'nombre': video['nombre'],
                    'url': video['url'],
                    'descripcion': video['descripcion'] or '',
                    'terminado': f"{curso}/{video['nombre']}" in videos_terminados
                }
                for video in videos
            ]

            total_videos = len(videos_lista)
            videos_terminados_count = sum(1 for video in videos_lista if video['terminado'])
            progreso = (videos_terminados_count / total_videos * 100) if total_videos > 0 else 0

            conn.commit()
            return render_template('componentes/lista_de_videos.html', 
                                 videos=videos_lista, 
                                 nombre_curso=curso,
                                 progreso=progreso,
                                 id_usuario=id_usuario,
                                 total_videos=total_videos,
                                 videos_terminados=videos_terminados_count,
                                 video_reproduciendo=video_reproduciendo)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Database error: {e}"), 500

@app.route('/eliminar_video', methods=['POST'])
def eliminar_video():
    curso = request.form.get('curso')
    video = request.form.get('video')
    id_usuario = request.form.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Missing required data"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT url FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video not found"), 404

            # Delete file if in static/videos
            url = video_data['url']
            if url.startswith('/static/videos/'):
                video_path = os.path.join(app.static_folder, 'videos', os.path.basename(url))
                if os.path.exists(video_path):
                    os.remove(video_path)

            # Delete video from videos table
            cursor.execute('DELETE FROM videos WHERE nombre = ? AND curso = ?', (video, curso))

            # Clean references in videos_terminados and reproduciendo
            cursor.execute('SELECT id, videos_terminados, reproduciendo FROM users')
            users = cursor.fetchall()
            for user in users:
                videos_terminados = json.loads(user['videos_terminados']) if user['videos_terminados'] else []
                reproduciendo = json.loads(user['reproduciendo']) if user['reproduciendo'] else []
                video_id = f"{curso}/{video}"
                
                # Remove video from videos_terminados
                if video_id in videos_terminados:
                    videos_terminados.remove(video_id)
                    cursor.execute('UPDATE users SET videos_terminados = ? WHERE id = ?', 
                                  (json.dumps(videos_terminados), user['id']))
                
                # Remove video from reproduciendo
                reproduciendo = [entry for entry in reproduciendo if not (entry.get('curso') == curso and entry.get('video') == video)]
                cursor.execute('UPDATE users SET reproduciendo = ? WHERE id = ?', 
                              (json.dumps(reproduciendo), user['id']))

            # Fetch updated video list
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (curso,)).fetchall()
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "User not found", 404
            
            videos_terminados = json.loads(usuario['videos_terminados']) if usuario['videos_terminados'] else []
            reproduciendo = json.loads(usuario['reproduciendo']) if usuario['reproduciendo'] else []

            video_reproduciendo = None
            for entry in reproduciendo:
                if entry.get('curso') == curso:
                    video_reproduciendo = entry.get('video')
                    break

            videos_lista = [
                {
                    'nombre': video['nombre'],
                    'url': video['url'],
                    'descripcion': video['descripcion'] or '',
                    'terminado': f"{curso}/{video['nombre']}" in videos_terminados
                }
                for video in videos
            ]

            total_videos = len(videos_lista)
            videos_terminados_count = sum(1 for video in videos_lista if video['terminado'])
            progreso = (videos_terminados_count / total_videos * 100) if total_videos > 0 else 0

            conn.commit()
            return render_template('componentes/lista_de_videos.html', 
                                 videos=videos_lista, 
                                 nombre_curso=curso,
                                 progreso=progreso,
                                 id_usuario=id_usuario,
                                 total_videos=total_videos,
                                 videos_terminados=videos_terminados_count,
                                 video_reproduciendo=video_reproduciendo)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Database error: {e}"), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return render_template('componentes/error.html', mensaje=f"Unexpected error: {e}"), 500

# Static routes
@app.route('/fondo_presentacion')
def fondo_presentacion():
    return render_template('componentes/fondo_presentacion.html')

@app.route('/privacy')
def privacy_policy():
    return render_template('componentes/privacy.html', fecha=fecha_ultima_actualizacion, nombre_del_sitio_web=nombre_del_sitio_web)

@app.route('/terms')
def terms_of_service():
    return render_template('componentes/terms.html', fecha=fecha_ultima_actualizacion, nombre_del_sitio_web=nombre_del_sitio_web)

@app.route('/cookies')
def cookies_policy():
    return render_template('componentes/cookies.html', fecha=fecha_ultima_actualizacion, nombre_del_sitio_web=nombre_del_sitio_web)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)