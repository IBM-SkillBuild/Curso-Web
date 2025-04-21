from flask import Flask, render_template, session, request, make_response, redirect, url_for, jsonify
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp4', 'avi', 'mov', 'mkv'}

# Cargar variables de entorno desde .env
load_dotenv()
fecha_ultima_actualizacion = os.getenv('ULTIMA_ACTUALIZACION')
nombre_del_sitio_web = os.getenv('NOMBRE_DEL_SITIO_WEB')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Clave secreta desde .env
STATIC_FOLDER = 'static'

# Configurar OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile', 'prompt': 'select_account'},
    redirect_uri='https://curso-web-alvr.onrender.com/google_callback'
)

# Crear la base de datos al iniciar
crear_db()

# Ruta principal
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
        return f"Error en la base de datos: {e}", 500

# Ruta para login con email/password
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
        return f"Error en la base de datos: {e}", 500

# Ruta para iniciar sesión con Google
@app.route('/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri=redirect_uri)

@app.route('/google_callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
        
        if response.status_code != 200:
            print(f"ERROR: No se pudo obtener información del usuario. Código: {response.status_code}")
            return "Error al obtener información del usuario.", 500
            
        user_info = response.json()
        print(f"Información de usuario recibida: {user_info}")
        email = user_info['email']
        name = user_info['name']
        google_foto = user_info.get('picture', '/static/images/foto-perfil.png')
    except Exception as e:
        print(f"ERROR DETALLADO en autenticación con Google: {str(e)}")
        return "Error en autenticación. Revisa la consola para más detalles.", 500

    print(f"Intentando acceder a la tabla 'users' con email: {email}")
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, foto FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            
            session_token = str(uuid.uuid4())
            if user:
                print(f"Usuario encontrado: {user['id']}. Actualizando session_token.")
                # Mantener la foto existente si ya tiene una configurada
                foto = user['foto'] if user['foto'] and user['foto'] != '/static/images/foto-perfil.png' else google_foto
                cursor.execute('UPDATE users SET session_token = ?, foto = ? WHERE id = ?', 
                               (session_token, foto, user['id']))
            else:
                print("Usuario no encontrado. Insertando nuevo usuario.")
                dummy_password = generate_password_hash('google-authenticated')
                cursor.execute('INSERT INTO users (nombre, email, password, session_token, foto) VALUES (?, ?, ?, ?, ?)',
                               (name, email, dummy_password, session_token, google_foto))
            conn.commit()
            print("Operación en la base de datos completada con éxito.")
            response = make_response(redirect(url_for('inicio')))
            response.set_cookie('session_token', session_token, max_age=21600)
            return response
    except sqlite3.Error as e:
        print(f"Error en la base de datos en /google_callback: {e}")
        return f"Error en la base de datos: {e}", 500
    except Exception as e:
        print(f"Error inesperado en /google_callback: {e}")
        return f"Error inesperado: {e}", 500

# Ruta para cerrar sesión
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
            return f"Error en la base de datos: {e}", 500
    
    response = make_response(redirect(url_for('inicio')))
    response.delete_cookie('session_token')
    return response

# Ruta para registro manual
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'GET':
        return render_template('componentes/registro.html')
    
    nombre = request.form.get('nombre')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not all([nombre, email, password]):
        return render_template('componentes/respuesta_registro_error.html', mensaje="Todos los campos son requeridos"), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return render_template('componentes/respuesta_registro_error.html', mensaje="El email ya está registrado"), 400
            
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
        return f"Error en la base de datos: {e}", 500

# Ruta para mostrar y editar el perfil
@app.route('/perfil', methods=['GET'])
def perfil():
    user_id = request.args.get('id')
    if not user_id:
        return "ID de usuario no proporcionado", 400
    
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
                    'cursos': user['cursos'] if user['cursos'] else "Ningún curso inscrito",
                }
                return render_template('componentes/perfil.html', user=user_data)
            return "Usuario no encontrado", 404
    except sqlite3.Error as e:
        return f"Error en la base de datos: {e}", 500

# Ruta para actualizar el perfil
@app.route('/actualizar_perfil', methods=['POST'])
def actualizar_perfil():
    user_id = request.form.get('id')
    nombre = request.form.get('nombre')
    foto_url = request.form.get('foto_url')
    foto_file = request.files.get('foto_file')
    print(f"user_id: {user_id}, nombre: {nombre}, foto_url: {foto_url}, foto_file: {foto_file}, foto_file.filename: {getattr(foto_file, 'filename', 'No filename')}")

    if not user_id or not nombre:
        return '<div class="text-red-500">Faltan datos requeridos</div>', 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT foto, email, cursos FROM users WHERE id = ?', (user_id,))
            resultado = cursor.fetchone()
            if not resultado:
                return '<div class="text-red-500">Usuario no encontrado</div>', 404
            
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

            # Actualizar datos en la base de datos
            cursor.execute('UPDATE users SET nombre = ?, foto = ? WHERE id = ?', (nombre, nueva_foto, user_id))
            conn.commit()

            mensaje = "Perfil actualizado correctamente."
            user_data = {
                'id': user_id,
                'nombre': nombre,
                'email': email,
                'foto': nueva_foto,
                'cursos': cursos if cursos else "Ningún curso inscrito"
            }
            mensaje = "Perfil actualizado correctamente."  # Nuevo mensaje
            return render_template('componentes/perfil.html', user=user_data, mensaje=mensaje)

    except sqlite3.Error as e:
        print(f"Error en la base de datos: {e}")
        return f'<div class="text-red-500">Error en la base de datos: {e}</div>', 500
    except IOError as e:
        print(f"Error al procesar la imagen o archivo: {e}")
        return f'<div class="text-red-500">Error al procesar la imagen: {e}</div>', 500
    except Exception as e:
        print(f"Error inesperado: {e}")
        return f'<div class="text-red-500">Error inesperado: {e}</div>', 500

# Ruta para listar cursos
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
        return f"Error al acceder a la base de datos: {e}", 500

# Ruta para listar usuarios
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
        return f"Error al acceder a la base de datos: {e}", 500

# Ruta para agregar un curso al usuario
@app.route('/agregar_curso', methods=['GET'])
def agregar_curso():
    user_id = request.args.get('id')
    curso_nombre = request.args.get('curso')

    if not user_id or not curso_nombre:
        return jsonify({'error': 'Faltan id o nombre del curso'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cursos FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404

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
        return jsonify({'error': f"Error en la base de datos: {e}"}), 500

# Ruta para mostrar los cursos del usuario
@app.route('/mis_cursos', methods=['GET'])
def mis_cursos():
    user_id = request.args.get('id')
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cursos FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return "Usuario no encontrado", 404
            
            cursos = json.loads(user['cursos']) if user['cursos'] else []
            cursos_lista = [{"id": idx + 1, "nombre": curso} for idx, curso in enumerate(cursos)]
            return render_template('componentes/mis_cursos.html', cursos=cursos_lista, user_id=user_id)
    except sqlite3.Error as e:
        return f"Error en la base de datos: {e}", 500

# Ruta para manejar la solicitud HTMX
@app.route('/lista_de_videos/<nombre_curso>/<int:id_usuario>', methods=['GET'])
def lista_de_videos(nombre_curso, id_usuario):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar que el curso existe
            curso = cursor.execute('SELECT carpeta FROM cursos WHERE nombre = ?', (nombre_curso,)).fetchone()
            if not curso:
                return "Curso no encontrado", 404

            # Obtener la lista de videos directamente de la tabla videos
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (nombre_curso,)).fetchall()

            # Obtener datos del usuario
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "Usuario no encontrado", 404
            
            videos_terminados = json.loads(usuario['videos_terminados']) if usuario['videos_terminados'] else []
            reproduciendo = json.loads(usuario['reproduciendo']) if usuario['reproduciendo'] else []

            video_reproduciendo = None
            for entry in reproduciendo:
                if entry.get('curso') == nombre_curso:
                    video_reproduciendo = entry.get('video')
                    break

            # Preparar la lista de videos para el frontend
            videos_lista = [
                {
                    'nombre': video['nombre'],
                    'url': video['url'],  # Usar el url directamente desde la base de datos
                    'descripcion': video['descripcion'] or '',  # Valor por defecto si es None
                    'terminado': f"{nombre_curso}/{video['nombre']}" in videos_terminados
                }
                for video in videos
            ]

            total_videos = len(videos_lista)
            videos_terminados_count = sum(1 for video in videos_lista if video['terminado'])
            progreso = (videos_terminados_count / total_videos * 100) if total_videos > 0 else 0

            conn.commit()
            print(f"Lista de videos obtenida de la base de datos: {videos_lista}")
            return render_template('componentes/lista_de_videos.html', 
                                 videos=videos_lista, 
                                 nombre_curso=nombre_curso,
                                 progreso=progreso,
                                 id_usuario=id_usuario,
                                 total_videos=total_videos,
                                 videos_terminados=videos_terminados_count,
                                 video_reproduciendo=video_reproduciendo)
    except sqlite3.Error as e:
        print(f"Error en la base de datos: {e}")
        return f"Error en la base de datos: {e}", 500

# Nueva ruta para actualizar el campo reproduciendo
@app.route('/reproduciendo', methods=['POST'])
def reproduciendo():
    data = request.get_json()
    curso = data.get('curso')
    video = data.get('video')
    id_usuario = data.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return jsonify({'error': 'Faltan datos: curso, video o id_usuario'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Obtener el usuario
            cursor.execute('SELECT reproduciendo FROM users WHERE id = ?', (id_usuario,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'Usuario no encontrado'}), 404

            # Inicializar reproduciendo como lista vacía si es None
            reproduciendo = json.loads(user['reproduciendo']) if user['reproduciendo'] else []
            
            # Crear la nueva entrada
            new_entry = {'curso': curso, 'video': video}
            
            # Eliminar cualquier entrada existente con el mismo curso
            reproduciendo = [entry for entry in reproduciendo if entry['curso'] != curso]
            
            # Añadir la nueva entrada
            reproduciendo.append(new_entry)
            
            # Actualizar la base de datos
            cursor.execute('UPDATE users SET reproduciendo = ? WHERE id = ?', 
                          (json.dumps(reproduciendo), id_usuario))
            conn.commit()

            return jsonify({'status': 'success', 'reproduciendo': reproduciendo})
    except sqlite3.Error as e:
        return jsonify({'error': f"Error en la base de datos: {e}"}), 500

# Ruta para marcar un video como terminado
@app.route('/marcar_video_terminado', methods=['POST'])
def marcar_video_terminado():
    data = request.get_json()
    curso = data.get('curso')
    video = data.get('video')
    id_usuario = data.get('id_usuario')
    duracion = data.get('duracion')

    # Validar datos requeridos
    if not all([curso, video, id_usuario]):
        print(f"Faltan datos: curso={curso}, video={video}, id_usuario={id_usuario}, duracion={duracion}")
        return jsonify({'error': 'Faltan datos: curso, video o id_usuario'}), 400

    # Log de la duración recibida
    print(f"Duración recibida: {duracion}, tipo: {type(duracion)}")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Obtener tiempo visto y duración del video
            cursor.execute('SELECT tiempo_visto, duracion FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                print(f"Video {video} no encontrado en curso {curso}")
                return jsonify({'error': 'Video no encontrado'}), 404

            tiempo_visto_db = json.loads(video_data['tiempo_visto']) if video_data['tiempo_visto'] else []
            tiempo_visto_usuario = next((float(entry['tiempo']) for entry in tiempo_visto_db if entry.get('id_user') == str(id_usuario)), 0.0)
            duracion_db = video_data['duracion']

            # Manejar duración
            if duracion_db is None and duracion is not None:
                try:
                    duracion_db = str(float(duracion))  # Guardar como texto para coincidir con el esquema
                    cursor.execute('UPDATE videos SET duracion = ? WHERE nombre = ? AND curso = ?', 
                                  (duracion_db, video, curso))
                    conn.commit()
                    print(f"Duración actualizada en DB: {duracion_db}")
                except (ValueError, TypeError) as e:
                    print(f"Error al convertir duración recibida: {duracion}, error: {e}")
                    return jsonify({'error': f"Duración no válida: {duracion}"}), 400
            elif duracion_db is None:
                print(f"Duración no disponible ni en DB ni en solicitud para video {video}, curso {curso}")
                return jsonify({'error': 'Duración del video no disponible'}), 400

            # Convertir duración a float para cálculos
            try:
                duracion_db = float(duracion_db)
            except (ValueError, TypeError) as e:
                print(f"Error al convertir duración de DB: {duracion_db}, error: {e}")
                return jsonify({'error': f"Formato de duración en base de datos inválido: {duracion_db}"}), 400

            # Obtener videos terminados del usuario
            cursor.execute('SELECT videos_terminados FROM users WHERE id = ?', (id_usuario,))
            user = cursor.fetchone()
            if not user:
                print(f"Usuario {id_usuario} no encontrado")
                return jsonify({'error': 'Usuario no encontrado'}), 404

            videos_terminados = json.loads(user['videos_terminados']) if user['videos_terminados'] else []
            video_id = f"{curso}/{video}"

            # Validar si el usuario ha visto al menos el 80% del video
            umbral = duracion_db * 0.8
            print(f"Validando: tiempo_visto={tiempo_visto_usuario}, umbral={umbral}, duracion_db={duracion_db}")
            if tiempo_visto_usuario < umbral:
                return jsonify({
                    'status': 'insufficient_time',
                    'videos_terminados': videos_terminados,
                    'tiempo_visto': tiempo_visto_usuario,
                    'duracion': duracion_db,
                    'umbral': umbral
                }), 200

            # Marcar el video como terminado si no está ya en la lista
            if video_id not in videos_terminados:
                videos_terminados.append(video_id)
                cursor.execute('UPDATE users SET videos_terminados = ? WHERE id = ?', 
                              (json.dumps(videos_terminados), id_usuario))
                conn.commit()
                print(f"Video {video_id} marcado como terminado para id_usuario={id_usuario}")

            # Verificar si todos los videos del curso están marcados como terminados
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
        print(f"Error en la base de datos: {e}")
        return jsonify({'error': f"Error en la base de datos: {e}"}), 500
    except Exception as e:
        print(f"Error inesperado: {e}")
        return jsonify({'error': f"Error inesperado: {e}"}), 500

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
        print(f"Faltan datos: id_usuario={id_usuario}, nombre_curso={nombre_curso}, video={video}")
        return jsonify({'error': 'Faltan datos'}), 400

    # Log de la duración recibida en POST
    if request.method == 'POST':
        print(f"Duración recibida en /tiempo_visto: {duracion}, tipo: {type(duracion)}")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT tiempo_visto, tiempo_continuar, duracion FROM videos WHERE nombre = ? AND curso = ?', 
                          (video, nombre_curso))
            video_data = cursor.fetchone()

            if not video_data:
                print(f"Video {video} no encontrado en curso {nombre_curso}, insertando...")
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
                # Actualizar tiempo_visto sumando el incremento real
                usuario_encontrado = False
                for i, entry in enumerate(tiempo_visto_db):
                    if entry.get('id_user') == str(id_usuario):
                        tiempo_visto_db[i]['tiempo'] = float(entry.get('tiempo', 0)) + tiempo_incremento
                        usuario_encontrado = True
                        break
                if not usuario_encontrado:
                    tiempo_visto_db.append({'id_user': str(id_usuario), 'tiempo': tiempo_incremento})

                # Actualizar tiempo_continuar si se proporciona
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

                # Actualizar duración si se proporciona desde el frontend
                if duracion_db is None and duracion is not None:
                    try:
                        duracion_db = str(float(duracion))  # Guardar como texto para coincidir con el esquema
                        cursor.execute('UPDATE videos SET duracion = ? WHERE nombre = ? AND curso = ?', 
                                      (duracion_db, video, nombre_curso))
                        print(f"Duración actualizada en DB: {duracion_db}")
                    except (ValueError, TypeError) as e:
                        print(f"Error al convertir duración recibida: {duracion}, error: {e}")
                        return jsonify({'error': f"Duración no válida: {duracion}"}), 400

                cursor.execute('UPDATE videos SET tiempo_visto = ?, tiempo_continuar = ? WHERE nombre = ? AND curso = ?', 
                              (json.dumps(tiempo_visto_db), json.dumps(tiempo_continuar_db), video, nombre_curso))
                conn.commit()
                print(f"Tiempo visto incrementado en {tiempo_incremento} segundos para id_usuario={id_usuario} en video={video}, curso={nombre_curso}")
                return '', 204
            else:
                # Devolver tiempo_continuar y duración para el usuario específico
                tiempo_continuar_usuario = next((float(entry['currentTime']) for entry in tiempo_continuar_db if entry.get('id_user') == str(id_usuario)), 0.0)
                try:
                    duracion_float = float(duracion_db) if duracion_db else None
                except (ValueError, TypeError) as e:
                    print(f"Error al convertir duración de DB: {duracion_db}, error: {e}")
                    duracion_float = None
                print(f"Devolviendo tiempo_continuar={tiempo_continuar_usuario}, duracion={duracion_float} para id_usuario={id_usuario}")
                return jsonify({
                    'tiempo_continuar': tiempo_continuar_usuario,
                    'duracion': duracion_float
                })

    except sqlite3.Error as e:
        print(f"Error en la base de datos: {e}")
        return jsonify({'error': f"Error en la base de datos: {e}"}), 500
    except Exception as e:
        print(f"Error inesperado: {e}")
        return jsonify({'error': f"Error inesperado: {e}"}), 500

# Ruta para mostrar el formulario de nuevo video (si autorizado)
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
            return render_template('componentes/formulario_nuevo_video.html', cursos=cursos_lista )
    except sqlite3.Error as e:
        return f"Error en la base de datos: {e}", 500

# Ruta para procesar el nuevo video
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
                return render_template('componentes/error_nuevo_video.html', mensaje="Faltan datos requeridos (nombre y curso)"), 400

            if video_source == 'upload' and video and video.filename:
                if not allowed_file(video.filename):
                    return render_template('componentes/error_nuevo_video.html', mensaje="Formato de video no permitido. Usa mp4, avi, mov o mkv."), 400
                video_filename = secure_filename(video.filename)
                video_path = os.path.join('static/videos', video_filename)
                video.save(video_path)
                final_url = f'/static/videos/{video_filename}'
            elif video_source == 'url' and video_url:
                final_url = video_url
            else:
                return render_template('componentes/error_nuevo_video.html', mensaje="Debes subir un video o proporcionar una URL válida"), 400

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
        return f"Error en la base de datos: {e}", 500
    
@app.route('/editar_video', methods=['GET'])
def editar_video():
    curso = request.args.get('curso')
    video = request.args.get('video')
    id_usuario = request.args.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Faltan datos: curso, video o id_usuario"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nombre, url, descripcion FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video no encontrado"), 404

            return render_template('componentes/formulario_editar_video.html',
                                 curso=curso,
                                 video=video_data['nombre'],
                                 url=video_data['url'],
                                 descripcion=video_data['descripcion'] or '',
                                 id_usuario=id_usuario)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Error en la base de datos: {e}"), 500    

@app.route('/borrar_video', methods=['GET'])
def borrar_video():
    curso = request.args.get('curso')
    video = request.args.get('video')
    id_usuario = request.args.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Faltan datos: curso, video o id_usuario"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nombre FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video no encontrado"), 404

            return render_template('componentes/formulario_borrar_video.html',
                                 curso=curso,
                                 video=video,
                                 id_usuario=id_usuario)
    except sqlite3.Error as e:
        return render_template('componentes/error.html', mensaje=f"Error en la base de datos: {e}"), 500

@app.route('/actualizar_video', methods=['POST'])
def actualizar_video():
    curso = request.form.get('curso')
    video_original = request.form.get('video_original')
    nombre = request.form.get('nombre')
    url = request.form.get('url')
    descripcion = request.form.get('descripcion')
    id_usuario = request.form.get('id_usuario')

    if not all([curso, video_original, nombre, url, id_usuario]):
        return render_template('componentes/error.html', mensaje="Faltan datos requeridos"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE videos SET nombre = ?, url = ?, descripcion = ? WHERE nombre = ? AND curso = ?',
                          (nombre, url, descripcion, video_original, curso))
            if cursor.rowcount == 0:
                return render_template('componentes/error.html', mensaje="Video no encontrado"), 404

            # Obtener la lista de videos actualizada
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (curso,)).fetchall()
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "Usuario no encontrado", 404
            
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
        return render_template('componentes/error.html', mensaje=f"Error en la base de datos: {e}"), 500


@app.route('/eliminar_video', methods=['POST'])
def eliminar_video():
    curso = request.form.get('curso')
    video = request.form.get('video')
    id_usuario = request.form.get('id_usuario')

    if not all([curso, video, id_usuario]):
        return render_template('componentes/error.html', mensaje="Faltan datos requeridos"), 400

    if int(id_usuario) != 1:
        return render_template('componentes/no_autorizado.html'), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT url FROM videos WHERE nombre = ? AND curso = ?', (video, curso))
            video_data = cursor.fetchone()
            if not video_data:
                return render_template('componentes/error.html', mensaje="Video no encontrado"), 404

            # Eliminar archivo si está en static/videos
            url = video_data['url']
            if url.startswith('/static/videos/'):
                video_path = os.path.join(app.static_folder, 'videos', os.path.basename(url))
                if os.path.exists(video_path):
                    os.remove(video_path)

            # Eliminar el video de la tabla de videos
            cursor.execute('DELETE FROM videos WHERE nombre = ? AND curso = ?', (video, curso))

            # Limpiar referencias en videos_terminados y reproduciendo
            cursor.execute('SELECT id, videos_terminados, reproduciendo FROM users')
            users = cursor.fetchall()
            for user in users:
                videos_terminados = json.loads(user['videos_terminados']) if user['videos_terminados'] else []
                reproduciendo = json.loads(user['reproduciendo']) if user['reproduciendo'] else []
                video_id = f"{curso}/{video}"
                
                # Eliminar el video de videos_terminados
                if video_id in videos_terminados:
                    videos_terminados.remove(video_id)
                    cursor.execute('UPDATE users SET videos_terminados = ? WHERE id = ?', 
                                  (json.dumps(videos_terminados), user['id']))
                
                # Eliminar el video de reproduciendo
                reproduciendo = [entry for entry in reproduciendo if not (entry.get('curso') == curso and entry.get('video') == video)]
                cursor.execute('UPDATE users SET reproduciendo = ? WHERE id = ?', 
                              (json.dumps(reproduciendo), user['id']))

            # Obtener la lista de videos actualizada
            videos = cursor.execute('SELECT nombre, url, descripcion, tiempo_visto, tiempo_continuar FROM videos WHERE curso = ? ORDER BY nombre ASC', 
                                   (curso,)).fetchall()
            usuario = cursor.execute('SELECT videos_terminados, reproduciendo FROM users WHERE id = ?', 
                                    (id_usuario,)).fetchone()
            if not usuario:
                return "Usuario no encontrado", 404
            
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
        return render_template('componentes/error.html', mensaje=f"Error en la base de datos: {e}"), 500
    except Exception as e:
        print(f"Error inesperado: {e}")
        return render_template('componentes/error.html', mensaje=f"Error inesperado: {e}"), 500
    
# Rutas estáticas
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

if __name__ == '__main__':
    app.run()