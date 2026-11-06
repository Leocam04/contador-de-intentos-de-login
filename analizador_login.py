#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contador y Analizador de Intentos de Login en Archivos de Logs.

Este programa lee un archivo de logs, identifica todos los intentos de inicio
de sesión (exitosos y fallidos), realiza un análisis de datos detallado
(por usuario, dirección IP, motivo de fallo y franja horaria) y exporta
los resultados a CSV y JSON.
"""

import argparse
import csv
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class IntentoLogin:
    """Representa un evento de intento de login extraído del archivo de logs."""
    linea_num: int
    fecha_hora: Optional[str]
    hora: Optional[str]
    ip: str
    usuario: str
    estado: str          # "EXITOSO" o "FALLIDO"
    motivo: str          # Mensaje o razón del fallo/éxito
    linea_original: str


# =====================================================================
# EXPRESIONES REGULARES PARA DISTINTOS FORMATOS DE LOGS
# =====================================================================

# 1. Formato estructurado (key=value), ej:
# 2026-11-06 08:01:12 [INFO] ip=192.168.1.10 user=admin status=SUCCESS msg="Inicio de sesion exitoso"
PATRON_ESTRUCTURADO = re.compile(
    r"^(?P<fecha>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<nivel>\w+)\]\s+"
    r"ip=(?P<ip>[\d\.a-fA-F:]+)\s+"
    r"user=(?P<usuario>\S+)\s+"
    r"status=(?P<estado>SUCCESS|FAILED|EXITOSO|FALLIDO)"
    r"(?:\s+(?:msg|reason)=\"(?P<motivo>[^\"]*)\")?",
    re.IGNORECASE,
)

# 2. Formato Linux SSH / auth.log, ej:
# Nov  6 08:05:19 server sshd[1234]: Failed password for invalid user admin from 192.168.1.22 port 5521
# Nov  6 08:05:42 server sshd[1234]: Accepted password for maria from 192.168.1.22 port 5522
PATRON_SSH = re.compile(
    r"^(?P<fecha>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?"
    r"(?P<estado>Accepted|Failed)\s+\S+\s+for\s+(?:invalid\s+user\s+)?"
    r"(?P<usuario>\S+)\s+from\s+(?P<ip>[\d\.a-fA-F:]+)",
    re.IGNORECASE,
)

# 3. Formato genérico por palabras clave (fallback para otros logs simples)
PATRON_FECHA_GENERICA = re.compile(r"(?P<fecha>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
PATRON_IP_GENERICA = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATRON_USER_GENERICO = re.compile(r"(?:user|usuario|usr)[=:\s]+([a-zA-Z0-9._-]+)", re.IGNORECASE)

PALABRAS_EXITO = ("status=success", "status=exitoso", "login exitoso", "login successful", "accepted password", "acceso concedido")
PALABRAS_FALLO = ("status=failed", "status=fallido", "login fallido", "login failed", "failed password", "acceso denegado", "invalid credentials")


def extraer_hora(fecha_str: Optional[str]) -> str:
    """Extrae la franja horaria (HH:00) a partir de una cadena de fecha."""
    if not fecha_str:
        return "Desconocida"
    match_hora = re.search(r"(\d{2}):\d{2}:\d{2}", fecha_str)
    if match_hora:
        return f"{match_hora.group(1)}:00"
    return "Desconocida"


def parsear_linea_log(linea: str, num_linea: int) -> Optional[IntentoLogin]:
    """
    Analiza una línea de log y devuelve un objeto IntentoLogin si corresponde
    a un evento de inicio de sesión, o None si es otro tipo de evento.
    """
    linea_limpia = linea.strip()
    if not linea_limpia:
        return None

    # Intento 1: Formato estructurado (como accesos.log)
    m = PATRON_ESTRUCTURADO.match(linea_limpia)
    if m:
        datos = m.groupdict()
        estado_raw = datos["estado"].upper()
        estado = "EXITOSO" if estado_raw in ("SUCCESS", "EXITOSO") else "FALLIDO"
        motivo = datos.get("motivo") or ("Inicio de sesion exitoso" if estado == "EXITOSO" else "Fallo de autenticacion")
        fecha_hora = datos["fecha"]
        return IntentoLogin(
            linea_num=num_linea,
            fecha_hora=fecha_hora,
            hora=extraer_hora(fecha_hora),
            ip=datos["ip"],
            usuario=datos["usuario"],
            estado=estado,
            motivo=motivo,
            linea_original=linea_limpia,
        )

    # Intento 2: Formato Linux auth.log / SSH
    m_ssh = PATRON_SSH.match(linea_limpia)
    if m_ssh:
        datos = m_ssh.groupdict()
        es_exito = datos["estado"].lower() == "accepted"
        estado = "EXITOSO" if es_exito else "FALLIDO"
        es_invalido = "invalid user" in linea_limpia.lower()
        motivo = (
            "Inicio de sesion SSH exitoso"
            if es_exito
            else ("Usuario inexistente" if es_invalido else "Contrasena incorrecta")
        )
        fecha_hora = datos["fecha"]
        return IntentoLogin(
            linea_num=num_linea,
            fecha_hora=fecha_hora,
            hora=extraer_hora(fecha_hora),
            ip=datos["ip"],
            usuario=datos["usuario"],
            estado=estado,
            motivo=motivo,
            linea_original=linea_limpia,
        )

    # Intento 3: Detección genérica por palabras clave
    linea_lower = linea_limpia.lower()
    es_exito = any(palabra in linea_lower for palabra in PALABRAS_EXITO)
    es_fallo = any(palabra in linea_lower for palabra in PALABRAS_FALLO)

    if not (es_exito or es_fallo):
        return None

    estado = "EXITOSO" if es_exito else "FALLIDO"
    m_fecha = PATRON_FECHA_GENERICA.search(linea_limpia)
    fecha_hora = m_fecha.group("fecha") if m_fecha else None

    m_ip = PATRON_IP_GENERICA.search(linea_limpia)
    ip = m_ip.group(0) if m_ip else "Desconocida"

    m_user = PATRON_USER_GENERICO.search(linea_limpia)
    usuario = m_user.group(1) if m_user else "Desconocido"

    return IntentoLogin(
        linea_num=num_linea,
        fecha_hora=fecha_hora,
        hora=extraer_hora(fecha_hora),
        ip=ip,
        usuario=usuario,
        estado=estado,
        motivo="Evento detectado por patron generico",
        linea_original=linea_limpia,
    )


def analizar_archivo_logs(ruta_archivo: str, umbral_fuerza_bruta: int = 3) -> Dict[str, Any]:
    """
    Lee el archivo de logs completo, cuenta los intentos exitosos y fallidos,
    y calcula métricas de análisis de datos.
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"No se encontró el archivo de logs: {ruta_archivo}")

    intentos: List[IntentoLogin] = []
    total_lineas = 0
    lineas_no_login = 0

    with open(ruta_archivo, mode="r", encoding="utf-8", errors="replace") as archivo:
        for num_linea, linea in enumerate(archivo, start=1):
            if not linea.strip():
                continue
            total_lineas += 1
            evento = parsear_linea_log(linea, num_linea)
            if evento:
                intentos.append(evento)
            else:
                lineas_no_login += 1

    # Contadores principales
    total_intentos = len(intentos)
    exitosos = sum(1 for i in intentos if i.estado == "EXITOSO")
    fallidos = sum(1 for i in intentos if i.estado == "FALLIDO")

    tasa_exito = round((exitosos / total_intentos) * 100, 2) if total_intentos > 0 else 0.0
    tasa_fallo = round((fallidos / total_intentos) * 100, 2) if total_intentos > 0 else 0.0

    # Agrupación por usuario
    stats_usuarios: Dict[str, Dict[str, int]] = defaultdict(lambda: {"EXITOSO": 0, "FALLIDO": 0, "TOTAL": 0})
    # Agrupación por IP
    stats_ips: Dict[str, Dict[str, int]] = defaultdict(lambda: {"EXITOSO": 0, "FALLIDO": 0, "TOTAL": 0})
    # Agrupación por hora
    stats_horas: Dict[str, Dict[str, int]] = defaultdict(lambda: {"EXITOSO": 0, "FALLIDO": 0, "TOTAL": 0})
    # Motivos de fallo
    motivos_fallo = Counter()

    for ev in intentos:
        stats_usuarios[ev.usuario][ev.estado] += 1
        stats_usuarios[ev.usuario]["TOTAL"] += 1

        stats_ips[ev.ip][ev.estado] += 1
        stats_ips[ev.ip]["TOTAL"] += 1

        stats_horas[ev.hora][ev.estado] += 1
        stats_horas[ev.hora]["TOTAL"] += 1

        if ev.estado == "FALLIDO":
            motivos_fallo[ev.motivo] += 1

    # Detección de IPs sospechosas (posible fuerza bruta)
    ips_sospechosas = {
        ip: datos["FALLIDO"]
        for ip, datos in stats_ips.items()
        if datos["FALLIDO"] >= umbral_fuerza_bruta
    }

    # Usuarios con más fallos
    usuarios_en_riesgo = {
        user: datos["FALLIDO"]
        for user, datos in stats_usuarios.items()
        if datos["FALLIDO"] >= umbral_fuerza_bruta
    }

    return {
        "archivo": os.path.abspath(ruta_archivo),
        "resumen": {
            "total_lineas_leidas": total_lineas,
            "eventos_sistema_ignorados": lineas_no_login,
            "total_intentos_login": total_intentos,
            "intentos_exitosos": exitosos,
            "intentos_fallidos": fallidos,
            "tasa_exito_pct": tasa_exito,
            "tasa_fallo_pct": tasa_fallo,
        },
        "por_usuario": dict(stats_usuarios),
        "por_ip": dict(stats_ips),
        "por_hora": dict(sorted(stats_horas.items())),
        "motivos_fallo": dict(motivos_fallo.most_common()),
        "alertas_seguridad": {
            "umbral_fallos": umbral_fuerza_bruta,
            "ips_sospechosas": ips_sospechosas,
            "usuarios_en_riesgo": usuarios_en_riesgo,
        },
        "intentos_detalle": intentos,
    }


def imprimir_reporte_consola(resultado: Dict[str, Any]) -> None:
    """Muestra en consola el informe completo de conteo y análisis de datos."""
    res = resultado["resumen"]
    sep = "=" * 68

    print(sep)
    print("      REPORTE DE ANALISIS DE LOGS - CONTADOR DE INTENTOS DE LOGIN")
    print(sep)
    print(f"Archivo analizado : {os.path.basename(resultado['archivo'])}")
    print(f"Lineas totales    : {res['total_lineas_leidas']} (Eventos de sistema: {res['eventos_sistema_ignorados']})")
    print("-" * 68)

    # 1. CONTEO PRINCIPAL
    print("\n[1] CONTEO GENERAL DE INTENTOS DE LOGIN")
    print(f"  • Total de intentos analizados : {res['total_intentos_login']}")
    print(f"  • Intentos EXITOSOS            : {res['intentos_exitosos']}  ({res['tasa_exito_pct']}%)")
    print(f"  • Intentos FALLIDOS            : {res['intentos_fallidos']}  ({res['tasa_fallo_pct']}%)")

    # 2. DESGLOSE POR USUARIO
    print("\n[2] ANALISIS POR USUARIO")
    print(f"  {'USUARIO':<18} | {'EXITOSOS':>9} | {'FALLIDOS':>9} | {'TOTAL':>7} | {'% FALLO':>8}")
    print("  " + "-" * 60)
    usuarios_ordenados = sorted(
        resultado["por_usuario"].items(),
        key=lambda x: (x[1]["FALLIDO"], x[1]["TOTAL"]),
        reverse=True,
    )
    for usuario, datos in usuarios_ordenados:
        pct_fallo = (datos["FALLIDO"] / datos["TOTAL"] * 100) if datos["TOTAL"] else 0.0
        print(
            f"  {usuario:<18} | {datos['EXITOSO']:>9} | {datos['FALLIDO']:>9} | "
            f"{datos['TOTAL']:>7} | {pct_fallo:>7.1f}%"
        )

    # 3. DESGLOSE POR DIRECCIÓN IP
    print("\n[3] ANALISIS POR DIRECCION IP")
    print(f"  {'DIRECCION IP':<18} | {'EXITOSOS':>9} | {'FALLIDOS':>9} | {'TOTAL':>7} | {'ESTADO'}")
    print("  " + "-" * 62)
    ips_ordenadas = sorted(
        resultado["por_ip"].items(),
        key=lambda x: (x[1]["FALLIDO"], x[1]["TOTAL"]),
        reverse=True,
    )
    ips_sospechosas = resultado["alertas_seguridad"]["ips_sospechosas"]
    for ip, datos in ips_ordenadas:
        alerta = "[!] SOSPECHOSA" if ip in ips_sospechosas else "OK"
        print(
            f"  {ip:<18} | {datos['EXITOSO']:>9} | {datos['FALLIDO']:>9} | "
            f"{datos['TOTAL']:>7} | {alerta}"
        )

    # 4. MOTIVOS DE FALLO
    if resultado["motivos_fallo"]:
        print("\n[4] CAUSAS DE INTENTOS FALLIDOS")
        for motivo, cantidad in resultado["motivos_fallo"].items():
            pct = (cantidad / res["intentos_fallidos"] * 100) if res["intentos_fallidos"] else 0
            print(f"  • {motivo:<32}: {cantidad:>3} ({pct:.1f}%)")

    # 5. DISTRIBUCIÓN HORARIA (GRÁFICO ASCII)
    if resultado["por_hora"]:
        print("\n[5] DISTRIBUCION POR HORA (Actividad de Login)")
        print("  Leyenda: [+] Exitoso   [x] Fallido")
        for hora, datos in resultado["por_hora"].items():
            barra_exito = "+" * datos["EXITOSO"]
            barra_fallo = "x" * datos["FALLIDO"]
            barra = f"{barra_exito}{barra_fallo}"
            print(
                f"  {hora:<8} | {barra:<20} "
                f"(Total: {datos['TOTAL']:>2} | Exitos: {datos['EXITOSO']:>2}, Fallos: {datos['FALLIDO']:>2})"
            )

    # 6. ALERTAS DE SEGURIDAD
    print("\n[6] ALERTAS DE SEGURIDAD (Deteccion de Fuerza Bruta)")
    umbral = resultado["alertas_seguridad"]["umbral_fallos"]
    if ips_sospechosas:
        print(f"  Se detectaron IPs con >= {umbral} intentos fallidos:")
        for ip, cant in ips_sospechosas.items():
            print(f"    [ALERTA] IP {ip} acumula {cant} intentos fallidos.")
    else:
        print(f"  No se detectaron IPs que superen el umbral de {umbral} fallos.")

    print(sep)


def exportar_resultados(resultado: Dict[str, Any], ruta_csv: str, ruta_json: str) -> None:
    """Exporta los eventos detallados a CSV y el resumen analítico a JSON."""
    # Exportar detalle a CSV (ideal para abrir en Excel o Pandas)
    campos_csv = ["linea_num", "fecha_hora", "hora", "ip", "usuario", "estado", "motivo"]
    with open(ruta_csv, mode="w", newline="", encoding="utf-8") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=campos_csv)
        writer.writeheader()
        for intento in resultado["intentos_detalle"]:
            fila = asdict(intento)
            fila.pop("linea_original", None)
            writer.writerow(fila)

    # Exportar resumen a JSON
    datos_json = {k: v for k, v in resultado.items() if k != "intentos_detalle"}
    datos_json["fecha_analisis"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ruta_json, mode="w", encoding="utf-8") as f_json:
        json.dump(datos_json, f_json, indent=4, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Contador y analizador de intentos de login exitosos y fallidos en logs."
    )
    parser.add_argument(
        "archivo_log",
        nargs="?",
        default="accesos.log",
        help="Ruta del archivo de logs a analizar (por defecto: accesos.log)",
    )
    parser.add_argument(
        "--umbral",
        type=int,
        default=3,
        help="Umbral de intentos fallidos para marcar una IP como sospechosa (por defecto: 3)",
    )
    parser.add_argument(
        "--csv",
        default="reporte_intentos.csv",
        help="Archivo CSV de salida con los datos estructurados (por defecto: reporte_intentos.csv)",
    )
    parser.add_argument(
        "--json",
        default="resumen_analisis.json",
        help="Archivo JSON de salida con el resumen estadístico (por defecto: resumen_analisis.json)",
    )

    args = parser.parse_args()

    resultado = analizar_archivo_logs(args.archivo_log, umbral_fuerza_bruta=args.umbral)
    imprimir_reporte_consola(resultado)
    exportar_resultados(resultado, args.csv, args.json)
    print(f"Archivos exportados correctamente:\n  - CSV  : {args.csv}\n  - JSON : {args.json}\n")


if __name__ == "__main__":
    main()
