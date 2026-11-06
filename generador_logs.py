#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generador y Simulador de Logs de Login (usando el módulo logging de Python).

Permite registrar nuevos intentos de inicio de sesión (exitosos y fallidos)
en 'accesos.log' para probar el analizador de datos con distintos volúmenes.
"""

import argparse
import logging
import random
from datetime import datetime, timedelta


USUARIOS_EXITO = [
    ("admin", "192.168.1.10"),
    ("carlos.perez", "192.168.1.15"),
    ("maria.gomez", "192.168.1.22"),
    ("ana.torres", "192.168.1.30"),
    ("luis.ramirez", "192.168.1.18"),
    ("sofia.mendez", "192.168.1.40"),
]

IPS_ATACANTES = ["45.33.32.156", "185.220.101.7", "203.0.113.88", "91.198.174.192"]
USUARIOS_ATACADOS = ["root", "admin", "guest", "support", "test", "carlos.perez"]
MOTIVOS_FALLO = [
    "Contrasena incorrecta",
    "Usuario inexistente",
    "Token 2FA expirado",
    "Cuenta bloqueada temporalmente",
    "Usuario no permitido",
]


def configurar_logger(ruta_archivo: str) -> logging.Logger:
    """Configura el logger de Python para escribir en el archivo de logs."""
    logger = logging.getLogger("LoginLogger")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    handler = logging.FileHandler(ruta_archivo, mode="a", encoding="utf-8")
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def simular_eventos(ruta_archivo: str, cantidad: int = 25, probabilidad_exito: float = 0.55) -> None:
    """Genera 'cantidad' de eventos de login simulados y los añade al archivo."""
    logger = configurar_logger(ruta_archivo)
    tiempo_base = datetime.now() - timedelta(hours=3)

    exitosos_generados = 0
    fallidos_generados = 0

    for _ in range(cantidad):
        tiempo_base += timedelta(seconds=random.randint(15, 360))
        fecha_str = tiempo_base.strftime("%Y-%m-%d %H:%M:%S")

        if random.random() < probabilidad_exito:
            usuario, ip = random.choice(USUARIOS_EXITO)
            linea = f'{fecha_str} [INFO] ip={ip} user={usuario} status=SUCCESS msg="Inicio de sesion exitoso"'
            logger.info(linea)
            exitosos_generados += 1
        else:
            # 60% de probabilidad de que venga de una IP externa sospechosa
            if random.random() < 0.6:
                ip = random.choice(IPS_ATACANTES)
                usuario = random.choice(USUARIOS_ATACADOS)
            else:
                usuario, ip = random.choice(USUARIOS_EXITO)

            motivo = random.choice(MOTIVOS_FALLO)
            linea = f'{fecha_str} [WARN] ip={ip} user={usuario} status=FAILED reason="{motivo}"'
            logger.warning(linea)
            fallidos_generados += 1

    print(f"Se agregaron {cantidad} nuevos registros en '{ruta_archivo}':")
    print(f"  - Exitosos generados : {exitosos_generados}")
    print(f"  - Fallidos generados : {fallidos_generados}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generador de logs de intentos de login para pruebas y análisis de datos."
    )
    parser.add_argument(
        "--archivo",
        default="accesos.log",
        help="Archivo de logs donde agregar los eventos (por defecto: accesos.log)",
    )
    parser.add_argument(
        "--cantidad",
        type=int,
        default=25,
        help="Cantidad de intentos de login a simular (por defecto: 25)",
    )
    args = parser.parse_args()
    simular_eventos(args.archivo, args.cantidad)


if __name__ == "__main__":
    main()

