#!/usr/bin/env python3
"""
Instalador maestro para:
  - Docker 28.0.3 + Swarm + red overlay
  - Traefik v3 + Portainer detrás de Traefik (Let's Encrypt)
  - Base de datos pgvector (desplegada vía API de Portainer v3, ownership=public)
  - Limpieza total del sistema Docker mediante clean.sh
"""

import os
import sys
import time
import re
import argparse
import subprocess
import getpass
import secrets
import string
import json
import urllib.request
import urllib.error
import ssl
from pathlib import Path

# Contexto SSL que ignora verificación (para certificados self-signed de Portainer)
ssl_ctx = ssl._create_unverified_context()

# Variables globales para recordar Portainer en esta ejecución
LAST_PORTAINER_URL = None
LAST_PORTAINER_PASSWORD = None


# ─────────────────────────── Utilidades generales ───────────────────────────

def sh(cmd: str, check: bool = True, quiet: bool = False):
    """Ejecuta un comando del sistema con shell=True."""
    if not quiet:
        print(f"→ {cmd}")
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def ask(prompt: str, validator=None, secret: bool = False):
    """Pide entrada al usuario (con validación opcional)."""
    while True:
        if secret:
            val = getpass.getpass(prompt + " ")
        else:
            val = input(prompt + " ").strip()
        if not val:
            print("⚠️  El valor no puede estar vacío.")
            continue
        if validator:
            ok, msg = validator(val)
            if not ok:
                print("⚠️ ", msg)
                continue
        return val


def validate_email(v: str):
    return (bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v)), "Email inválido")


def validate_fqdn(v: str):
    return (bool(re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", v)), "FQDN inválido")


def escape_dollars(s: str) -> str:
    """Escapa los signos $ para Docker/Compose/Stacks."""
    return s.replace("$", "$$")


def ensure_overlay_network(name: str, quiet: bool = False):
    """Crea red overlay si no existe (si ya existe, solo informa)."""
    result = sh("docker network ls --format '{{.Name}}'", check=False, quiet=True)
    existing = result.stdout.strip().splitlines() if result.stdout else []
    if name in existing:
        if not quiet:
            print(f"ℹ️  La red '{name}' ya existe (se reutiliza).")
        return
    print(f"→ Creando red overlay attachable '{name}'…")
    sh(f"docker network create -d overlay --attachable {name}", check=True, quiet=quiet)
    print(f"✅ Red '{name}' creada.")


def choose_overlay_network() -> str:
    """Lista redes disponibles y permite elegir una o crear nueva."""
    print("\n📡 Redes disponibles:")
    rows = sh("docker network ls --format '{{.Name}}|{{.Driver}}|{{.Scope}}'", check=False).stdout.strip().splitlines()
    if not rows:
        name = ask("No hay redes. Nombre de la red overlay a crear:")
        ensure_overlay_network(name)
        return name
    print("    (Nombre | Driver | Scope)")
    for r in rows:
        print("  -", r)
    name = ask("\n👉 Escribe el NOMBRE exacto de la red overlay a usar (o uno nuevo para crearla):")
    ensure_overlay_network(name)
    return name


def generate_password(length: int = 16) -> str:
    """Genera una password estilo API key con longitud dada."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ─────────────────────────── Template Traefik + Portainer ───────────────────────────

COMPOSE_TEMPLATE_TRAEFIK = """version: "3.7"

services:
  traefik:
    image: ghcr.io/traefik/traefik:v3.6.0
    command:
      - "--api.insecure=false"
      - "--providers.docker.endpoint=unix:///var/run/docker.sock"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.docker.network={OVERLAY}"
      - "--providers.swarm=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      - "--entrypoints.web.http.redirections.entrypoint.permanent=true"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.transport.respondingTimeouts.idleTimeout=3600"
      - "--certificatesresolvers.letsencryptresolver.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencryptresolver.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencryptresolver.acme.storage=/etc/traefik/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencryptresolver.acme.email={LE_EMAIL}"
      - "--log.level=INFO"
      - "--accesslog=true"
      - "--accesslog.filepath=/var/log/traefik/access.log"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "vol_certificates:/etc/traefik/letsencrypt"
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - {OVERLAY}
    deploy:
      placement:
        constraints:
          - node.role == manager
      labels:
        - "traefik.enable=false"

  portainer:
    image: portainer/portainer-ce:latest
    command:
      - "-H"
      - "unix:///var/run/docker.sock"
      - "--admin-password={PORTAINER_HASH_ESCAPED}"
    volumes:
      - portainer_data:/data
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - {OVERLAY}
    deploy:
      placement:
        constraints:
          - node.role == manager
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.portainer.rule=Host(`{PORTAINER_HOST}`)"
        - "traefik.http.routers.portainer.entrypoints=websecure"
        - "traefik.http.routers.portainer.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.portainer.loadbalancer.server.port=9000"

volumes:
  vol_certificates:
    external: true
    name: volume_swarm_certificates

  portainer_data:

networks:
  {OVERLAY}:
    external: true
    attachable: true
"""


def ensure_bcrypt():
    """Instala bcrypt si no está presente (para Portainer)."""
    try:
        import bcrypt  # noqa
    except ImportError:
        print("→ Instalando paquete 'bcrypt' con pip…")
        sh("python3 -m pip install --upgrade pip", check=False)
        sh("python3 -m pip install bcrypt", check=True)


def bcrypt_hash(password: str) -> str:
    """Genera hash bcrypt."""
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def write_compose_traefik(stack_dir: Path, overlay: str, le_email: str,
                          portainer_host: str, portainer_hash: str) -> Path:
    portainer_hash_escaped = escape_dollars(portainer_hash)
    content = COMPOSE_TEMPLATE_TRAEFIK.format(
        OVERLAY=overlay,
        LE_EMAIL=le_email,
        PORTAINER_HOST=portainer_host,
        PORTAINER_HASH_ESCAPED=portainer_hash_escaped,
    )

    stack_dir.mkdir(parents=True, exist_ok=True)
    (stack_dir / "letsencrypt").mkdir(parents=True, exist_ok=True)
    acme = stack_dir / "letsencrypt" / "acme.json"
    if not acme.exists():
        acme.touch()
        os.chmod(acme, 0o600)

    compose_path = stack_dir / "docker-stack.yml"
    compose_path.write_text(content)
    return compose_path


def deploy_traefik_portainer(overlay: str,
                             quiet: bool = False,
                             le_email: str = None,
                             portainer_host: str = None,
                             admin_password: str = None):
    """Despliega Traefik + Portainer usando la red overlay dada."""
    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD

    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    ensure_bcrypt()
    ensure_overlay_network(overlay, quiet=quiet)

    # Si faltan datos críticos, preguntar interactivo:
    if not le_email:
        le_email = ask("Email para Let's Encrypt (Traefik):", validator=validate_email)
    if not portainer_host:
        portainer_host = ask("FQDN para Portainer (ej: portainer.midominio.com):", validator=validate_fqdn)
    if not admin_password:
        admin_password = ask("Clave ADMIN inicial de Portainer:", secret=True)

    portainer_hash = bcrypt_hash(admin_password)

    stack_dir = Path("/opt/docker-config/infra")
    compose_path = write_compose_traefik(
        stack_dir=stack_dir,
        overlay=overlay,
        le_email=le_email,
        portainer_host=portainer_host,
        portainer_hash=portainer_hash,
    )

    print(f"\n→ Desplegando stack 'infra' desde {compose_path}…")
    sh(f"docker stack deploy -c {compose_path} infra", quiet=quiet)

    # Guardamos URL y password para usos posteriores (pgvector)
    LAST_PORTAINER_URL = f"https://{portainer_host}"
    LAST_PORTAINER_PASSWORD = admin_password

    print("\n🎉 Traefik + Portainer desplegados:")
    print(f" - Portainer:  https://{portainer_host}")
    print("⏳ Espera 1–2 minutos mientras Let's Encrypt emite el certificado.\n")


# ─────────────────────────── Template PGVector ───────────────────────────

COMPOSE_TEMPLATE_PGVECTOR = """version: "3.8"

services:

  pgvector:
    image: pgvector/pgvector:pg16
    command: >
      postgres
      -c max_connections=500
      -c shared_buffers=512MB

    volumes:
      - pgvector:/var/lib/postgresql/data

    networks:
      - {OVERLAY}

    # Descomente las líneas abajo para acceso externo
    #ports:
    #  - 5432:5432

    environment:
      # Password del usuario postgres
      - POSTGRES_PASSWORD={PG_PASSWORD_ESCAPED}

      # Timezone
      - TZ=UTC

    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
      resources:
        limits:
          cpus: "1"
          memory: 1024M

volumes:
  pgvector:
    external: true
    name: pgvector

networks:
  {OVERLAY}:
    external: true
    name: {OVERLAY}
"""


def build_pgvector_stack_content(overlay: str, pg_password: str) -> str:
    """Genera el contenido del stack (YAML) para PGVector."""
    pg_password_escaped = escape_dollars(pg_password)
    return COMPOSE_TEMPLATE_PGVECTOR.format(
        OVERLAY=overlay,
        PG_PASSWORD_ESCAPED=pg_password_escaped,
    )


# ─────────────────────────── Portainer API (vía HTTP) ───────────────────────────

def portainer_api_login(base_url: str, admin_password: str) -> str:
    """Hace login en la API de Portainer y devuelve el JWT."""
    url = base_url.rstrip("/") + "/api/auth"
    payload = {"Username": "admin", "Password": admin_password}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8")
            obj = json.loads(body)
            token = obj.get("jwt") or obj.get("token")
            if not token:
                raise RuntimeError("Respuesta de /api/auth sin campo 'jwt'")
            return token
    except urllib.error.HTTPError as e:
        print(f"❌ Error HTTP al autenticar en Portainer: {e.code} {e.reason}")
        try:
            print(e.read().decode("utf-8"))
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error al autenticar en Portainer: {e}")
        sys.exit(1)


def portainer_get_endpoint_id(base_url: str, jwt: str) -> int:
    """Obtiene el ID del endpoint a usar (primer endpoint de la lista)."""
    url = base_url.rstrip("/") + "/api/endpoints"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {jwt}"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8")
            endpoints = json.loads(body)
            if not endpoints:
                raise RuntimeError("No se encontraron endpoints en Portainer.")
            ep = endpoints[0]
            endpoint_id = ep.get("Id") or ep.get("ID") or ep.get("id")
            if not endpoint_id:
                raise RuntimeError("No se pudo determinar el ID del endpoint.")
            return int(endpoint_id)
    except Exception as e:
        print(f"❌ Error al obtener endpoints de Portainer: {e}")
        sys.exit(1)


def portainer_get_swarm_id(base_url: str, jwt: str, endpoint_id: int) -> str:
    """Obtiene el SwarmID del cluster Docker asociado al endpoint."""
    url = base_url.rstrip("/") + f"/api/endpoints/{endpoint_id}/docker/swarm"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {jwt}"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8")
            swarm = json.loads(body)
            swarm_id = swarm.get("ID") or swarm.get("Id")
            if not swarm_id:
                raise RuntimeError("No se encontró campo 'ID' en la respuesta de /docker/swarm")
            return swarm_id
    except Exception as e:
        print(f"❌ Error al obtener SwarmID desde Portainer: {e}")
        sys.exit(1)


def portainer_create_swarm_stack_from_string(base_url: str, jwt: str,
                                             endpoint_id: int, name: str,
                                             stack_content: str,
                                             swarm_id: str,
                                             ownership: str = "public"):
    """
    Crea un stack Swarm en Portainer v3 a partir de un stackFileContent (string).
    POST /api/stacks/create/swarm/string?endpointId=X&ownership=public
    """
    query = f"?endpointId={endpoint_id}&ownership={ownership}"
    url = base_url.rstrip("/") + f"/api/stacks/create/swarm/string{query}"

    payload = {
        "name": name,
        "stackFileContent": stack_content,
        "swarmID": swarm_id,
        "fromAppTemplate": False,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt}",
    }
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8")
            if resp.status not in (200, 201):
                print(f"⚠️ Respuesta inesperada al crear stack: {resp.status}")
                print(body)
            return body
    except urllib.error.HTTPError as e:
        print(f"❌ Error HTTP al crear stack en Portainer: {e.code} {e.reason}")
        try:
            print(e.read().decode("utf-8"))
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error al crear stack en Portainer: {e}")
        sys.exit(1)


def deploy_pgvector_via_portainer_api(overlay: str,
                                      portainer_url: str,
                                      admin_password: str,
                                      quiet: bool = False,
                                      password: str = None,
                                      length: int = 16):
    """
    Despliega el stack 'pgvector' vía API de Portainer v3, ownership=public.
    NO toca la red (se asume que ya existe).
    """
    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    # Aquí NO volvemos a crear la red, solo asumimos que existe.
    # ensure_overlay_network(overlay, quiet=quiet)  # <- evitamos mensajes redundantes

    if not password:
        password = generate_password(length)

    # 1) Autenticación API Portainer
    print("🔐 Autenticando en Portainer API como usuario 'admin'…")
    jwt = portainer_api_login(portainer_url, admin_password)

    # 2) Obtener endpointId
    print("📍 Obteniendo endpointId…")
    endpoint_id = portainer_get_endpoint_id(portainer_url, jwt)

    # 3) Obtener SwarmID
    print("🌀 Obteniendo SwarmID…")
    swarm_id = portainer_get_swarm_id(portainer_url, jwt, endpoint_id)

    # 4) Construir contenido de stack
    stack_content = build_pgvector_stack_content(overlay, password)

    # 5) Crear stack via API con ownership=public
    print("📦 Creando stack 'pgvector' vía Portainer API (ownership=public)…")
    portainer_create_swarm_stack_from_string(
        base_url=portainer_url,
        jwt=jwt,
        endpoint_id=endpoint_id,
        name="pgvector",
        stack_content=stack_content,
        swarm_id=swarm_id,
        ownership="public",
    )

    print("\n🎉 PGVector desplegado correctamente vía Portainer.")
    print("   Nombre del stack: pgvector")
    print("\n🔐 IMPORTANTE - Password de PostgreSQL (usuario 'postgres'):")
    print(f"   {password}")
    print("   Guárdala en un lugar seguro.\n")


# ─────────────────────────── Instalador Docker 28.0.3 ───────────────────────────

class Docker28Installer:
    """
    Instalador completo para Docker 28.0.3 en Ubuntu.
    • Elimina versiones previas y datos
    • Instala Docker 28.x y bloquea versión
    • Inicializa Docker Swarm SIEMPRE (reinicia o recrea si ya existe)
    • Crea red overlay attachable (nombre interactivo o parametrizado)
    • Guarda log en /var/log/docker_installer.log
    """

    def __init__(self, quiet: bool = False, overlay_name: str = None):
        self.target_version = "5:28.0.3"
        self.log_file = "/var/log/docker_installer.log"
        self.quiet = quiet
        self.overlay_name = overlay_name
        self._init_log()

    # ─────────────────────────── UTILIDADES ───────────────────────────
    def _init_log(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        with open(self.log_file, "w") as log:
            log.write(f"==== INSTALACIÓN DOCKER 28.0.3 ({time.ctime()}) ====\n")

    def log(self, msg: str):
        with open(self.log_file, "a") as log:
            log.write(f"[{time.ctime()}] {msg}\n")

    def run_command(self, command: str, shell: bool = False, check: bool = True):
        try:
            if not self.quiet:
                print(f"→ {command}")
            result = subprocess.run(
                command if shell else command.split(),
                shell=shell, check=check,
                capture_output=True, text=True
            )
            self.log(f"CMD: {command}\n{result.stdout.strip()}\n")
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = f"ERROR en '{command}': {e.stderr.strip()}"
            print(f"❌ {error_msg}")
            self.log(error_msg)
            if check:
                print(f"📄 Revise el log en: {self.log_file}")
                sys.exit(1)
            return None

    # ───────────────────────── INSTALACIÓN ──────────────────────────
    def get_current_docker_version(self):
        output = self.run_command("docker --version", shell=True, check=False)
        match = re.search(r"(\d+\.\d+\.\d+)", output or "")
        return match.group(1) if match else None

    def remove_current_docker(self):
        print("🗑️  Eliminando versiones anteriores de Docker...")
        cmds = [
            "sudo systemctl stop docker docker.socket containerd",
            "sudo systemctl disable docker docker.socket containerd",
            "sudo apt-get remove -y docker docker-engine docker.io docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
            "sudo apt-get autoremove -y --purge",
            "sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker /root/.docker /var/run/docker.sock",
            "sudo rm -f /etc/apt/sources.list.d/docker.list",
            "sudo rm -f /usr/share/keyrings/docker-archive-keyring.gpg",
            "sudo rm -f /etc/apt/keyrings/docker.gpg",
        ]
        for cmd in cmds:
            self.run_command(cmd, shell=True, check=False)
        self.log("Docker y datos previos eliminados correctamente.")

    def install_docker_28(self):
        print(f"🐳 Instalando Docker {self.target_version}...")
        deps = "apt-transport-https ca-certificates curl gnupg lsb-release"
        self.run_command(f"sudo apt-get update && sudo apt-get install -y {deps}", shell=True)

        # Configurar repositorio oficial
        self.run_command("sudo install -m 0755 -d /etc/apt/keyrings", shell=True, check=False)
        self.run_command(
            "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | "
            "sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
            shell=True
        )
        arch = self.run_command("dpkg --print-architecture", shell=True)
        codename = self.run_command("lsb_release -cs", shell=True)
        self.run_command(
            f'echo "deb [arch={arch} signed-by=/etc/apt/keyrings/docker.gpg] '
            f'https://download.docker.com/linux/ubuntu {codename} stable" | '
            f'sudo tee /etc/apt/sources.list.d/docker.list > /dev/null',
            shell=True
        )
        self.run_command("sudo apt-get update", shell=True)
        versions = self.run_command("apt-cache madison docker-ce | grep '5:28'", shell=True, check=False)
        version_match = re.findall(r"5:28\.\d+\.\d+[-~\w.]*", versions or "")
        version = version_match[0] if version_match else self.target_version
        self.run_command(
            f"sudo apt-get install -y docker-ce={version} docker-ce-cli={version} containerd.io",
            shell=True
        )
        self.run_command("sudo apt-mark hold docker-ce docker-ce-cli containerd.io", shell=True)
        self.log(f"Docker {version} instalado y bloqueado.")

    def configure_docker(self):
        print("⚙️  Configurando servicio Docker...")
        user = os.getenv("SUDO_USER") or os.getenv("USER")
        if user and user != "root":
            self.run_command(f"sudo usermod -aG docker {user}", shell=True)
            print(f"👤 Usuario '{user}' agregado al grupo docker.")
        self.run_command("sudo systemctl enable docker", shell=True)
        self.run_command("sudo systemctl start docker", shell=True)

        print("⏳ Esperando que Docker inicie...")
        for _ in range(10):
            status = self.run_command("sudo systemctl is-active docker", shell=True, check=False)
            if "active" in (status or ""):
                print("✅ Docker activo y en ejecución.")
                return
            time.sleep(2)
        print("❌ Docker no inició correctamente. Revise el log.")
        self.log("ERROR: Docker no se activó.")
        sys.exit(1)

    # ─────────────────────── SWARM Y RED OVERLAY ───────────────────────
    def force_swarm_init(self):
        """Inicializa Swarm incluso si ya está activo."""
        print("\n🌐 Inicializando Docker Swarm (forzado)...")
        self.run_command("docker swarm leave --force", shell=True, check=False)
        self.run_command("docker swarm init", shell=True)
        print("✅ Docker Swarm inicializado (forzado).")
        self.log("Swarm reiniciado e inicializado exitosamente.")

    def create_overlay_network(self) -> str:
        """Crea red overlay attachable (interactiva o por flag) y devuelve el nombre."""
        print("\n🕸️  Creación de red overlay attachable")
        if self.overlay_name:
            name = self.overlay_name.strip()
        else:
            while True:
                name = input("👉 Ingrese el nombre de la red overlay: ").strip()
                if name:
                    break
                print("⚠️  El nombre no puede estar vacío.")
        existing = self.run_command("docker network ls --format '{{.Name}}'", shell=True, check=False)
        if existing and name in (existing.splitlines() if existing else []):
            print(f"ℹ️  La red '{name}' ya existe, se omite la creación.")
            self.log(f"Red '{name}' ya existente.")
        else:
            self.run_command(f"docker network create -d overlay --attachable {name}", shell=True)
            print(f"✅ Red overlay '{name}' creada correctamente.")
            self.log(f"Red overlay '{name}' creada correctamente.")
        self.overlay_name = name
        return name

    # ─────────────────────────── EJECUCIÓN ───────────────────────────
    def run(self) -> str:
        """Ejecuta el flujo completo y devuelve el nombre de la red overlay usada."""
        if os.geteuid() != 0:
            print("🔒 Ejecute este script como root (sudo).")
            sys.exit(1)
        print("🔧 Instalador de Docker 28.0.3 + Swarm + Overlay\n")
        print("📄 Log detallado en /var/log/docker_installer.log\n")

        current = self.get_current_docker_version()
        if current:
            print(f"📋 Versión actual detectada: {current}")
            print("🔄 Eliminando versión previa...\n")
            self.remove_current_docker()

        self.install_docker_28()
        self.configure_docker()
        self.verify_installation()
        self.force_swarm_init()
        overlay = self.create_overlay_network()

        print("\n🎉 Instalación completada con éxito.")
        print("💡 Use 'newgrp docker' o reinicie sesión para aplicar permisos.")
        print(f"📜 Log completo: {self.log_file}")
        return overlay

    def verify_installation(self):
        print("🔍 Verificando instalación...")
        version = self.run_command("docker --version", shell=True)
        api = self.run_command("docker version --format '{{.Client.APIVersion}}'", shell=True)
        daemon = self.run_command("docker info --format '{{.ServerVersion}}'", shell=True)
        self.run_command("docker ps", shell=True)
        print(f"✅ Docker instalado: {version.strip()}")
        print(f"   API: {api.strip()} | Daemon: {daemon.strip()}")
        self.log(f"Instalación verificada: {version}, API {api}, Daemon {daemon}")


# ─────────────────────────── Limpieza con clean.sh ───────────────────────────

def run_clean_script():
    """Ejecuta el script clean.sh ubicado junto a este archivo."""
    script_path = Path(__file__).with_name("clean.sh")
    if not script_path.exists():
        print(f"❌ No se encontró '{script_path}'. Coloque clean.sh en la misma carpeta.")
        return
    print("\n========================================")
    print("     LIMPIEZA TOTAL DEL SISTEMA DOCKER  ")
    print("========================================\n")
    os.chmod(script_path, 0o755)
    subprocess.run([str(script_path)], check=False)
    print("\n✅ Limpieza finalizada.\n")


# ─────────────────────────── CLI / Menú ───────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Instalador maestro Docker 28 + Swarm + Overlay + Traefik + Portainer + PGVector"
    )
    parser.add_argument("--quiet", action="store_true", help="Ejecutar en modo silencioso (solo errores)")
    parser.add_argument("--overlay", type=str, help="Nombre de la red overlay a usar/crear")
    parser.add_argument("--install-docker", action="store_true", help="Solo instalar Docker + Swarm + overlay")
    parser.add_argument("--install-traefik", action="store_true", help="Solo desplegar Traefik + Portainer")
    parser.add_argument("--install-pgvector", action="store_true", help="Solo desplegar PGVector vía API Portainer")
    parser.add_argument("--install-all", action="store_true", help="Instalar Docker + Traefik + Portainer")
    parser.add_argument("--le-email", type=str, help="Email para Let's Encrypt (modo no interactivo)")
    parser.add_argument("--portainer-fqdn", type=str, help="FQDN para Portainer (ej: portainer.midominio.com)")
    parser.add_argument("--portainer-url", type=str, help="URL base de Portainer (ej: https://portainer.midominio.com)")
    parser.add_argument("--portainer-password", type=str, help="Clave ADMIN de Portainer (para hash y API)")
    parser.add_argument("--pgvector-password", type=str, help="Password explícita para PGVector (opcional)")
    return parser.parse_args()


def run_menu(default_overlay: str = None):
    """Menú interactivo principal."""
    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD
    overlay = default_overlay  # para reutilizar la red entre opciones

    while True:
        print("===========================================")
        print("        INSTALADOR DOCKER + TRAEFIK        ")
        print("===========================================")
        print("1) Instalar Docker 28 + Swarm + red overlay")
        print("2) Instalar Traefik + Portainer (requiere Swarm)")
        print("3) Instalar TODO (1 + 2)")
        print("4) Limpiar sistema (ejecuta clean.sh)")
        print("6) Instalar base de datos pgvector (via API Portainer)")
        print("")
        print("0) Salir")
        print("-------------------------------------------")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            installer = Docker28Installer(quiet=False, overlay_name=overlay)
            overlay = installer.run()

        elif opcion == "2":
            if not overlay:
                print("ℹ️ No hay red overlay registrada de la opción 1.")
                overlay = choose_overlay_network()
            deploy_traefik_portainer(overlay)

        elif opcion == "3":
            installer = Docker28Installer(quiet=False, overlay_name=overlay)
            overlay = installer.run()
            deploy_traefik_portainer(overlay)

        elif opcion == "4":
            run_clean_script()

        elif opcion == "6":
            if not overlay:
                print("ℹ️ No hay red overlay registrada de la opción 1.")
                overlay = choose_overlay_network()

            # Si ya instalamos Portainer en esta sesión, reutilizamos URL + password
            if LAST_PORTAINER_URL and LAST_PORTAINER_PASSWORD:
                portainer_url = LAST_PORTAINER_URL
                admin_pwd = LAST_PORTAINER_PASSWORD
            else:
                portainer_url = ask("URL base de Portainer (ej: https://portainer.midominio.com):")
                admin_pwd = ask("Password ADMIN de Portainer (la misma que usas en el login web):", secret=True)

            deploy_pgvector_via_portainer_api(
                overlay=overlay,
                portainer_url=portainer_url,
                admin_password=admin_pwd,
            )

        elif opcion == "0":
            print("👋 Saliendo...")
            break

        else:
            print("⚠️ Opción inválida. Intente de nuevo.\n")


def main():
    if os.geteuid() != 0:
        print("🔒 Ejecute este script como root (sudo).")
        sys.exit(1)

    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD
    args = parse_args()

    # Si no hay flags de acción, entrar a menú
    if not (args.install_docker or args.install_traefik or args.install_all or args.install_pgvector):
        run_menu()
        return

    overlay = args.overlay

    # Construir URL de Portainer si hace falta
    portainer_url = args.portainer_url
    if not portainer_url and args.portainer_fqdn:
        portainer_url = f"https://{args.portainer_fqdn}"

    # Flujo por flags
    if args.install_all:
        installer = Docker28Installer(quiet=args.quiet, overlay_name=overlay)
        overlay = installer.run()
        deploy_traefik_portainer(
            overlay=overlay,
            quiet=args.quiet,
            le_email=args.le_email,
            portainer_host=args.portainer_fqdn,
            admin_password=args.portainer_password,
        )
        # deploy_traefik_portainer ya setea LAST_PORTAINER_URL/PASSWORD

    elif args.install_docker:
        installer = Docker28Installer(quiet=args.quiet, overlay_name=overlay)
        overlay = installer.run()

    elif args.install_traefik:
        if not overlay:
            overlay = choose_overlay_network()
        deploy_traefik_portainer(
            overlay=overlay,
            quiet=args.quiet,
            le_email=args.le_email,
            portainer_host=args.portainer_fqdn,
            admin_password=args.portainer_password,
        )

    elif args.install_pgvector:
        if not overlay:
            overlay = choose_overlay_network()

        # Prioridad: parámetros CLI -> variables globales -> prompt
        if not portainer_url and LAST_PORTAINER_URL:
            portainer_url = LAST_PORTAINER_URL
        if not portainer_url:
            portainer_url = ask("URL base de Portainer (ej: https://portainer.midominio.com):")

        admin_pwd = args.portainer_password or LAST_PORTAINER_PASSWORD
        if not admin_pwd:
            admin_pwd = ask("Password ADMIN de Portainer (la misma que usas en el login web):", secret=True)

        deploy_pgvector_via_portainer_api(
            overlay=overlay,
            portainer_url=portainer_url,
            admin_password=admin_pwd,
            password=args.pgvector_password,
            length=16,
        )


if __name__ == "__main__":
    main()
