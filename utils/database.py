import sqlite3
import os

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'db', 'database.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def crear_db():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'db', 'database.db')
    db_dir = os.path.dirname(db_path)

    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                cursos TEXT,
                videos_terminados TEXT,
                reproduciendo TEXT,
                session_token TEXT,
                foto TEXT
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS cursos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT UNIQUE NOT NULL,
                carpeta TEXT UNIQUE NOT NULL,
                inscritos INTEGER DEFAULT 0
            )''')
            cursos_iniciales = [("html", "videos/html", 0), ("css", "videos/css", 0), ("javascript", "videos/javascript", 0)]
            cursor.executemany('INSERT OR IGNORE INTO cursos (nombre, carpeta, inscritos) VALUES (?, ?, ?)', cursos_iniciales)

            # Nueva definición con UNIQUE constraint
            cursor.execute('''CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                url TEXT NOT NULL,
                descripcion TEXT,
                curso TEXT NOT NULL,
                tiempo_visto TEXT,
                duracion TEXT,
                tiempo_continuar TEXT,
                UNIQUE(nombre, curso)
            )''')

            # Nueva tabla para sesiones de Flask-Session
            cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                expiry TIMESTAMP
            )''')

            conn.commit()
    except sqlite3.Error as e:
        raise

if __name__ == "__main__":
    crear_db()