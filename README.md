# Contador y Analizador de Intentos de Login

Sistema en **Python** diseñado para procesar archivos de logs de autenticación, contabilizar cuántos intentos de inicio de sesión fueron **exitosos** y cuántos **fallidos**, realizar un **análisis de datos detallado** y detectar posibles ataques de fuerza bruta.

---

## Características Principales

- **Conteo Automatizado**: Identifica y separa eventos de login (`EXITOSO` vs. `FALLIDO`) ignorando líneas de eventos generales del sistema (`[SYSTEM]`, backups, etc.).
- **Soporte Multi-formato**:
  1. **Logs estructurados (`key=value`)**: `ip=... user=... status=SUCCESS|FAILED`.
  2. **Logs de Linux SSH (`auth.log`)**: `Accepted password` / `Failed password`.
  3. **Logs genéricos**: Detección por palabras clave y extracción de IP/usuario mediante expresiones regulares (`regex`).
- **Análisis de Datos Integrado**:
  - Tasas porcentuales de éxito y fallo.
  - Desglose de intentos por **usuario** y porcentaje de error individual.
  - Desglose de intentos por **dirección IP**.
  - Clasificación y ranking de **motivos de fallo** (contraseña incorrecta, usuario inexistente, token 2FA expirado, cuenta bloqueada, etc.).
  - Distribución horaria con **gráfico de barras ASCII** en consola.
- **Seguridad / Detección de Fuerza Bruta**: Alerta automática sobre direcciones IP y cuentas de usuario que superan un umbral configurable de intentos fallidos.
- **Exportación de Datos**:
  - `reporte_intentos.csv`: Dataset tabular limpio listo para abrir en Excel, Google Sheets, Power BI o analizar con `pandas`.
  - `resumen_analisis.json`: Resumen estadístico estructurado en formato JSON.
- **Cero Dependencias Externas**: Funciona directamente con la librería estándar de Python 3 (`re`, `collections`, `csv`, `json`, `dataclasses`, `logging`, `argparse`).

---

## Estructura del Proyecto

```text
contador de intentos de login/
├── analizador_login.py     # Script principal de lectura, conteo y análisis de datos
├── generador_logs.py       # Simulador de tráfico de login usando el módulo logging
├── accesos.log             # Archivo de logs de ejemplo para pruebas
├── reporte_intentos.csv    # Dataset exportado con cada intento de login procesado
├── resumen_analisis.json   # Métricas agregadas, conteos y alertas en formato JSON
└── README.md               # Documentación del sistema
```

---

## Requisitos

- **Python 3.7 o superior** instalado en el sistema.
- No requiere instalar paquetes adicionales con `pip`.

---

## Uso del Sistema

### 1. Ejecutar el analizador de logs

Para analizar el archivo `accesos.log` incluido por defecto:

```bash
python analizador_login.py
```

#### Opciones avanzadas por línea de comandos:

```bash
# Analizar un archivo de log específico
python analizador_login.py ruta/a/otro_archivo.log

# Cambiar el umbral de fallos para la alerta de fuerza bruta (por defecto: 3)
python analizador_login.py accesos.log --umbral 5

# Personalizar los nombres de los archivos exportados
python analizador_login.py accesos.log --csv mi_reporte.csv --json mi_resumen.json
```

---

### 2. Generar nuevos registros de prueba (`generador_logs.py`)

Si deseas simular más tráfico (accesos legítimos y ataques desde IPs externas) para probar el análisis con mayor volumen de datos:

```bash
# Agrega 25 nuevos intentos simulados a accesos.log
python generador_logs.py

# Agrega 100 nuevos intentos simulados a un archivo específico
python generador_logs.py --archivo accesos.log --cantidad 100
```

Después de generar nuevos logs, vuelve a ejecutar `python analizador_login.py` para ver cómo se actualizan las estadísticas y los archivos CSV/JSON.

---

## Cómo Funciona Internamente

El flujo de procesamiento en `analizador_login.py` se divide en 4 etapas:

1. **Lectura y Filtrado (`parsear_linea_log`)**:
   Lee el archivo línea por línea y evalúa expresiones regulares para identificar si la línea corresponde a un evento de autenticación. Si es un mensaje administrativo del sistema, lo contabiliza como evento ignorado.
2. **Estructuración (`IntentoLogin`)**:
   Cada evento válido se convierte en un objeto `IntentoLogin` con los campos:
   - `linea_num`: Número de línea en el archivo original.
   - `fecha_hora` y `hora`: Marca temporal y franja horaria (`HH:00`).
   - `ip`: Dirección IP de origen.
   - `usuario`: Nombre de usuario involucrado.
   - `estado`: Normalizado a `EXITOSO` o `FALLIDO`.
   - `motivo`: Razón del éxito o causa del rechazo.
3. **Agregación y Análisis (`analizar_archivo_logs`)**:
   Utiliza `collections.defaultdict` y `collections.Counter` para agrupar métricas por usuario, IP, hora y causa de fallo, calculando porcentajes y filtrando las IPs que igualan o superan el umbral de intentos fallidos.
4. **Reporte y Exportación (`imprimir_reporte_consola` / `exportar_resultados`)**:
   Imprime las tablas en consola y guarda los resultados en `reporte_intentos.csv` y `resumen_analisis.json`.

---

## Formatos de Logs Soportados

### 1. Formato Estructurado (Recomendado)
```text
2026-11-06 08:01:12 [INFO] ip=192.168.1.10 user=admin status=SUCCESS msg="Inicio de sesion exitoso"
2026-11-06 08:05:19 [WARN] ip=192.168.1.22 user=maria.gomez status=FAILED reason="Contrasena incorrecta"
```

### 2. Formato Linux SSH (`auth.log`)
```text
Nov  6 08:05:19 server sshd[1234]: Failed password for invalid user admin from 192.168.1.22 port 5521
Nov  6 08:05:42 server sshd[1234]: Accepted password for maria from 192.168.1.22 port 5522
```

---

## Integración con Pandas (Opcional)

Como el sistema genera automáticamente `reporte_intentos.csv`, puedes cargarlo directamente en un Jupyter Notebook o script con `pandas` para análisis adicionales:

```python
import pandas as pd

df = pd.read_csv("reporte_intentos.csv")

# Conteo rápido de exitosos y fallidos
print(df["estado"].value_counts())

# Tabla cruzada de usuarios vs estado
print(pd.crosstab(df["usuario"], df["estado"], margins=True))
```

