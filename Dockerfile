# Usa una imagen base de Python
FROM python:3.9-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia todo el proyecto al contenedor
COPY . .

# Instala dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Crea la carpeta para la base de datos (si no existe)
RUN mkdir -p db

# Permisos de escritura para la carpeta db (opcional, pero útil)
RUN chmod a+w db

# Define el volumen para persistir la base de datos
VOLUME /app/db

# Comando para ejecutar la app (usando Gunicorn como servidor)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]