#!/usr/bin/env python3
# =====================================================================
#  ████████╗██████╗ ██╗███████╗██╗  ██╗███████╗██╗     
#  ╚══██╔══╝██╔══██╗██║██╔════╝██║  ██║██╔════╝██║     
#     ██║   ██████╔╝██║███████╗███████║█████╗  ██║     
#     ██║   ██╔══██╗██║╚════██║██╔══██║██╔══╝  ██║     
#     ██║   ██║  ██║██║███████║██║  ██║███████╗███████╗
#     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
#
#               TRISKEL INSTALLER v3.0.0 ✔️ Stable
#    Docker • Traefik • Portainer • PGVector • Evolution • Chatwoot
# =====================================================================

"""
Instalador maestro para:
  - Docker 28.0.3 + Swarm + red overlay
  - Traefik v3 + Portainer detrás de Traefik (Let's Encrypt)
  - Portainer Agent para consola en servicios Swarm
  - PGVector desplegado vía API Portainer v3 (ownership=public)
  - Evolution API desplegado vía API Portainer v3 (ownership=public)
  - Chatwoot desplegado vía API Portainer v3 (ownership=public)
  - Limpieza total mediante clean.sh
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
from urllib.parse import urlparse

# Contexto SSL que ignora verificación (para certificados self-signed de Portainer)
ssl_ctx = ssl._create_unverified_context()

# Variables globales para recordar Portainer en esta ejecución
LAST_PORTAINER_URL = None
LAST_PORTAINER_PASSWORD = None

# Secretos de PGVector (persistentes entre sesiones)
PGVECTOR_SECRET_DIR = "/opt/triskel/secrets"
PGVECTOR_SECRET_FILE = os.path.join(PGVECTOR_SECRET_DIR, "pgvector_password")
LAST_PGVECTOR_PASSWORD = None

BANNER = """
🔱 TRISKEL INSTALLER v3.0.0

Docker · Traefik · Portainer · PGVector · Evolution API · Chatwoot
"""

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

def normalize_url(raw_url: str):
    """
    Normaliza y valida URLs para Portainer / Evolution / Chatwoot / etc.
    Devuelve:
       - url_normalizada (con https://)
       - fqdn (host sin esquema, sin puerto)
    Si es inválida → devuelve (None, None).
    """
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return None, None

    # Agregar https:// si falta
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception:
        return None, None

    if not parsed.netloc:
        return None, None

    # tomar solo host sin puerto
    fqdn = parsed.netloc.split(":")[0]

    # FQDN mínimo decente tipo algo.algo
    if not re.match(r"^(?=.{4,253}$)(?!-)([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$", fqdn):
        return None, None

    scheme = parsed.scheme or "https"
    url_normalizada = f"{scheme}://{fqdn}"

    return url_normalizada, fqdn

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
    print("📡 Redes disponibles:")
    rows = sh("docker network ls --format '{{.Name}}|{{.Driver}}|{{.Scope}}'", check=False).stdout.strip().splitlines()
    if not rows:
        name = ask("No hay redes. Nombre de la red overlay a crear:")
        ensure_overlay_network(name)
        return name
    print("    (Nombre | Driver | Scope)")
    for r in rows:
        print("  -", r)
    name = ask("👉 Escribe el NOMBRE exacto de la red overlay a usar (o uno nuevo para crearla):")
    ensure_overlay_network(name)
    return name


def generate_password(length: int = 16) -> str:
    """Genera una password estilo API key con longitud dada."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_secret_key_base() -> str:
    """Genera SECRET_KEY_BASE para Chatwoot / Rails."""
    return secrets.token_hex(64)


def save_pgvector_password(password: str):
    """Guarda la contraseña de PGVector en un archivo seguro para futuras sesiones."""
    os.makedirs(PGVECTOR_SECRET_DIR, exist_ok=True)
    with open(PGVECTOR_SECRET_FILE, "w") as f:
        f.write(password.strip() + "\n")
    os.chmod(PGVECTOR_SECRET_FILE, 0o600)


def load_pgvector_password():
    """Carga la contraseña de PGVector desde el archivo seguro, si existe."""
    if not os.path.exists(PGVECTOR_SECRET_FILE):
        return None
    try:
        with open(PGVECTOR_SECRET_FILE, "r") as f:
            pw = f.readline().strip()
            return pw or None
    except Exception:
        return None


# ─────────────────────────── Template Traefik + Portainer (Agent) ───────────────────────────

COMPOSE_TEMPLATE_TRAEFIK = """version: "3.8"

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

  agent:
    image: portainer/agent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/lib/docker/volumes:/var/lib/docker/volumes
    networks:
      - {OVERLAY}
    deploy:
      mode: global
      placement:
        constraints:
          - node.platform.os == linux

  portainer:
    image: portainer/portainer-ce:latest
    command: >
      -H tcp://tasks.agent:9001
      --tlsskipverify
      --admin-password={PORTAINER_HASH_ESCAPED}
    volumes:
      - portainer_data:/data
    networks:
      - {OVERLAY}
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.portainer.rule=Host(`{PORTAINER_HOST}`)"
        - "traefik.http.routers.portainer.entrypoints=websecure"
        - "traefik.http.routers.portainer.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.portainer.loadbalancer.server.port=9000"
        - "traefik.docker.network={OVERLAY}"

volumes:
  vol_certificates:
    external: true
    name: volume_swarm_certificates

  portainer_data:

networks:
  {OVERLAY}:
    external: true
    name: {OVERLAY}
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


# ─────────────────────────── Portainer API helpers ───────────────────────────

def portainer_api_login(base_url: str, admin_password: str) -> str:
    """Hace login en la API de Portainer y devuelve el JWT."""
    
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    url = base_url.rstrip("/") + "/api/auth"
    payload = {"Username": "admin", "Password": admin_password}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
        body = resp.read().decode("utf-8")
        obj = json.loads(body)
        token = obj.get("jwt") or obj.get("token")
        if not token:
            raise RuntimeError("Respuesta de /api/auth sin campo 'jwt'")
        return token


def portainer_get_endpoint_id(base_url: str, jwt: str) -> int:
    """Obtiene el ID del endpoint a usar (primer endpoint de la lista)."""
    url = base_url.rstrip("/") + "/api/endpoints"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {jwt}"})
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
        body = resp.read().decode("utf-8")
        endpoints = json.loads(body)
    if not endpoints:
        raise RuntimeError("No se encontraron endpoints en Portainer.")
    ep = endpoints[0]
    endpoint_id = ep.get("Id") or ep.get("ID") or ep.get("id")
    if not endpoint_id:
        raise RuntimeError("No se pudo determinar el ID del endpoint.")
    return int(endpoint_id)


def portainer_get_swarm_id(base_url: str, jwt: str, endpoint_id: int) -> str:
    """Obtiene el SwarmID del cluster Docker asociado al endpoint."""
    url = base_url.rstrip("/") + f"/api/endpoints/{endpoint_id}/docker/swarm"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {jwt}"})
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
        body = resp.read().decode("utf-8")
        swarm = json.loads(body)
    swarm_id = swarm.get("ID") or swarm.get("Id")
    if not swarm_id:
        raise RuntimeError("No se encontró campo 'ID' en la respuesta de /docker/swarm")
    return swarm_id


def portainer_create_swarm_stack_from_string(base_url: str, jwt: str,
                                             endpoint_id: int, name: str,
                                             stack_content: str,
                                             swarm_id: str,
                                             ownership: str = "public"):
    """
    Crea un stack Swarm en Portainer a partir de un stackFileContent (string).
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
    with urllib.request.urlopen(req, timeout=60, context=ssl_ctx) as resp:
        body = resp.read().decode("utf-8")
        if resp.status not in (200, 201):
            print(f"⚠️ Respuesta inesperada al crear stack: {resp.status}")
            print(body)
        return body


def portainer_create_agent_endpoint(base_url: str, jwt: str):
    """
    Corrige el problema de 'Environment disconnected' en Portainer CE.
    1. Espera a que Portainer esté listo
    2. Verifica si ya existe un endpoint
    3. Si no existe → crea EndpointType=2 (Agent)
    4. Espera a que el Agent se conecte
    """
    import time
    from urllib.parse import urlparse

    # Normalizar base_url
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    # 1. Esperar a que la API esté arriba
    status_url = base_url + "/api/status"
    print("⏳ Esperando a que Portainer esté completamente operativo...")

    for i in range(60):
        try:
            req = urllib.request.Request(status_url)
            urllib.request.urlopen(req, timeout=3, context=ssl_ctx)
            print("✅ Portainer responde.")
            break
        except:
            time.sleep(1)
    else:
        print("❌ Portainer no está respondiendo después de 60 segundos.")
        return False

    # 2. Obtener endpoints existentes
    endpoints_url = base_url + "/api/endpoints"
    req = urllib.request.Request(endpoints_url, headers={"Authorization": f"Bearer {jwt}"})

    try:
        with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as resp:
            endpoints = json.loads(resp.read().decode())
    except Exception as e:
        print(f"❌ Error al consultar endpoints: {e}")
        return False

    # 3. Revisar si ya existe un endpoint Agent
    for ep in endpoints:
        ep_type = ep.get("Type") or ep.get("EndpointType")
        ep_url = ep.get("URL")

        if ep_type == 2 or ep_url == "tcp://tasks.agent:9001":
            print(f"ℹ️ Endpoint Agent ya existe: {ep.get('Name')} (ID {ep.get('Id')})")
            return True

    # 4. Crear endpoint Agent
    print("🔧 Creando endpoint Agent en Portainer...")

    payload = {
        "Name": "agent",
        "URL": "tcp://tasks.agent:9001",
        "EndpointType": 2,
        "TLS": False,
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        endpoints_url,
        data=data,
        headers={
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
        },
    )

    try:
        urllib.request.urlopen(req, timeout=10, context=ssl_ctx)
        print("✅ Endpoint Agent creado exitosamente.")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print("ℹ️ El endpoint ya existía (409). Se reutilizará.")
            return True
        print(f"❌ Error creando endpoint Agent: {e.read().decode()}")
        return False

    # 5. Esperar que el Agent se conecte
    print("⏳ Esperando que el Agent se conecte al endpoint...")
    for i in range(20):
        try:
            req = urllib.request.Request(endpoints_url, headers={"Authorization": f"Bearer {jwt}"})
            with urllib.request.urlopen(req, timeout=5, context=ssl_ctx) as resp:
                eps = json.loads(resp.read().decode())
                for ep in eps:
                    if ep.get("URL") == "tcp://tasks.agent:9001":
                        if ep.get("Status") == 1:  # 1 = up
                            print("🚀 Agent conectado correctamente.")
                            return True
            time.sleep(1)
        except:
            time.sleep(1)

    print("⚠️ Agent creado pero no se conectó a tiempo.")
    return False


# ─────────────────────────── Deploy Traefik + Portainer ───────────────────────────

def deploy_traefik_portainer(overlay: str,
                             quiet: bool = False,
                             le_email: str = None,
                             portainer_host: str = None,
                             admin_password: str = None):
    """Despliega Traefik + Portainer (con Agent) usando la red overlay dada."""
    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD

    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    ensure_bcrypt()
    ensure_overlay_network(overlay, quiet=quiet)

    # Pedir datos si faltan
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

    print(f"→ Desplegando stack 'infra' desde {compose_path}…")
    sh(f"docker stack deploy -c {compose_path} infra", quiet=quiet)

    # Guardamos URL y password para PGVector / Evolution / Chatwoot
    LAST_PORTAINER_URL = f"https://{portainer_host}"
    LAST_PORTAINER_PASSWORD = admin_password

    print("⏳ Esperando a que Portainer inicie...")
    portainer_status_url = f"https://{portainer_host}/api/status"
    for i in range(30):
        try:
            req = urllib.request.Request(portainer_status_url)
            urllib.request.urlopen(req, timeout=3, context=ssl_ctx)
            print("✅ Portainer está activo.")
            break
        except Exception:
            time.sleep(1)
    else:
        print("❌ Portainer no respondió después de 30 segundos.")
        sys.exit(1)

    print("🔐 Autenticando en Portainer para crear endpoint Agent…")

    jwt = portainer_api_login(f"https://{portainer_host}", admin_password)

    portainer_create_agent_endpoint(
        base_url=f"https://{portainer_host}",
        jwt=jwt
    )

    print("🎉 Traefik + Portainer (con Agent) desplegados:")
    print(f"   - Portainer:  https://{portainer_host}")
    print("   - Endpoint Agent configurado correctamente.")


# ─────────────────────────── Template PGVector ───────────────────────────

COMPOSE_TEMPLATE_PGVECTOR = """version: "3.8"

services:

  pgvector:
    image: pgvector/pgvector:pg16
    stdin_open: true
    tty: true
    command: >
      postgres
      -c max_connections=500
      -c shared_buffers=512MB

    volumes:
      - pgvector:/var/lib/postgresql/data

    networks:
      - {OVERLAY}

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


def deploy_pgvector_via_portainer_api(overlay: str,
                                      portainer_url: str,
                                      admin_password: str,
                                      quiet: bool = False,
                                      password: str = None,
                                      length: int = 16):
    """
    Despliega el stack 'pgvector' vía API de Portainer, ownership=public.
    Además guarda la contraseña en memoria y en archivo para futuras integraciones.
    """
    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    if not password:
        password = generate_password(length)

    global LAST_PGVECTOR_PASSWORD
    LAST_PGVECTOR_PASSWORD = password
    save_pgvector_password(password)

    print("🔐 Autenticando en Portainer API como usuario 'admin'…")
    jwt = portainer_api_login(portainer_url, admin_password)

    print("📍 Obteniendo endpointId…")
    endpoint_id = portainer_get_endpoint_id(portainer_url, jwt)

    print("🌀 Obteniendo SwarmID…")
    swarm_id = portainer_get_swarm_id(portainer_url, jwt, endpoint_id)

    stack_content = build_pgvector_stack_content(overlay, password)

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

    print("🎉 PGVector desplegado correctamente vía Portainer.")
    print("   Nombre del stack: pgvector")
    print("🔐 IMPORTANTE - Password de PostgreSQL (usuario 'postgres'):")
    print(f"   {password}")
    print("   Guárdala en un lugar seguro.")


# ─────────────────────────── Template Evolution API ───────────────────────────

COMPOSE_TEMPLATE_EVOLUTION = """version: "3.8"

services:

  evolution_api:
    image: evoapicloud/evolution-api:v2.3.6

    volumes:
      - evolution_instances:/evolution/instances

    networks:
      - {OVERLAY}

    environment:
      ## ⚙️ Configuraciones Generales
      - SERVER_URL={EVOLUTION_SERVER_URL}
      - AUTHENTICATION_API_KEY={EVOLUTION_API_KEY_ESCAPED}
      - AUTHENTICATION_EXPOSE_IN_FETCH_INSTANCES=true
      - DEL_INSTANCE=false
      - QRCODE_LIMIT=1902
      - LANGUAGE=es-CO
      - TZ=UTC

      ## 📱 Configuración del Cliente
      - CONFIG_SESSION_PHONE_CLIENT=Evolution
      - CONFIG_SESSION_PHONE_NAME=Chrome

      ## 🗄️ Configuración de la Base de Datos
      - DATABASE_ENABLED=true
      - DATABASE_PROVIDER=postgresql
      - DATABASE_CONNECTION_URI=postgresql://postgres:{PG_PASSWORD_ESCAPED}@pgvector:5432/evolution
      - DATABASE_CONNECTION_CLIENT_NAME=evolution
      - DATABASE_SAVE_DATA_INSTANCE=true
      - DATABASE_SAVE_DATA_NEW_MESSAGE=true
      - DATABASE_SAVE_MESSAGE_UPDATE=true
      - DATABASE_SAVE_DATA_CONTACTS=true
      - DATABASE_SAVE_DATA_CHATS=true
      - DATABASE_SAVE_DATA_LABELS=true
      - DATABASE_SAVE_DATA_HISTORIC=true

      ## 🤖 Integraciones habilitadas
      - N8N_ENABLED=true
      - EVOAI_ENABLED=true
      - OPENAI_ENABLED=true
      - DIFY_ENABLED=true

      ## 💬 Typebot
      - TYPEBOT_ENABLED=true
      - TYPEBOT_API_VERSION=latest

      ## 🗣️ Chatwoot
      - CHATWOOT_ENABLED=true
      - CHATWOOT_MESSAGE_READ=true
      - CHATWOOT_MESSAGE_DELETE=true
      - CHATWOOT_IMPORT_DATABASE_CONNECTION_URI=postgresql://postgres:{PG_PASSWORD_ESCAPED}@pgvector:5432/chatwoot?sslmode=disable
      - CHATWOOT_IMPORT_PLACEHOLDER_MEDIA_MESSAGE=false

      ## 🧊 Redis Cache
      - CACHE_REDIS_ENABLED=true
      - CACHE_REDIS_URI=redis://evolution_redis:6379/1
      - CACHE_REDIS_PREFIX_KEY=evolution
      - CACHE_REDIS_SAVE_INSTANCES=false
      - CACHE_LOCAL_ENABLED=false

      ## ☁️ S3 (deshabilitado)
      - S3_ENABLED=false
      - S3_ACCESS_KEY=
      - S3_SECRET_KEY=
      - S3_BUCKET=evolution
      - S3_PORT=443
      - S3_ENDPOINT=
      - S3_USE_SSL=true

      ## 💼 WhatsApp Business
      - WA_BUSINESS_TOKEN_WEBHOOK=evolution
      - WA_BUSINESS_URL=https://graph.facebook.com
      - WA_BUSINESS_VERSION=v21.0
      - WA_BUSINESS_LANGUAGE=pt_BR

      ## 📊 Telemetría
      - TELEMETRY=false
      - TELEMETRY_URL=

      ## 🌐 WebSocket
      - WEBSOCKET_ENABLED=false
      - WEBSOCKET_GLOBAL_EVENTS=false

      ## 🔌 Provider
      - PROVIDER_ENABLED=false
      - PROVIDER_HOST=127.0.0.1
      - PROVIDER_PORT=5656
      - PROVIDER_PREFIX=evolution

    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
        - node.role == manager
      labels:
        - traefik.enable=1
        - traefik.http.routers.evolution.rule=Host(`{EVOLUTION_HOST}`)
        - traefik.http.routers.evolution.entrypoints=websecure
        - traefik.http.routers.evolution.priority=1
        - traefik.http.routers.evolution.tls.certresolver=letsencryptresolver
        - traefik.http.routers.evolution.service=evolution
        - traefik.http.services.evolution.loadbalancer.server.port=8080
        - traefik.http.services.evolution.loadbalancer.passHostHeader=true

  evolution_redis:
    image: redis:latest
    command: [
        "redis-server",
        "--appendonly",
        "yes",
        "--port",
        "6379"
      ]

    volumes:
      - evolution_redis:/data

    networks:
      - {OVERLAY}

    deploy:
      placement:
        constraints:
          - node.role == manager
      resources:
        limits:
          cpus: "1"
          memory: 1024M

volumes:
  evolution_instances:
    external: true
    name: evolution_instances
  evolution_redis:
    external: true
    name: evolution_redis

networks:
  {OVERLAY}:
    external: true
    name: {OVERLAY}
"""


def build_evolution_stack_content(overlay: str,
                                  evolution_server_url: str,
                                  evolution_host: str,
                                  evolution_api_key: str,
                                  pg_password: str) -> str:
    """Genera el contenido del stack (YAML) para Evolution API."""
    api_key_escaped = escape_dollars(evolution_api_key)
    pg_password_escaped = escape_dollars(pg_password)
    return COMPOSE_TEMPLATE_EVOLUTION.format(
        OVERLAY=overlay,
        EVOLUTION_SERVER_URL=evolution_server_url,
        EVOLUTION_HOST=evolution_host,
        EVOLUTION_API_KEY_ESCAPED=api_key_escaped,
        PG_PASSWORD_ESCAPED=pg_password_escaped,
    )


def deploy_evolution_via_portainer_api(overlay: str,
                                       portainer_url: str,
                                       admin_password: str,
                                       evolution_server_url: str,
                                       evolution_host: str,
                                       pg_password: str = None,
                                       evolution_api_key: str = None,
                                       length: int = 16):
    """
    Despliega el stack 'evolution' vía API de Portainer, ownership=public.
    Reutiliza el password de PGVector (archivo o memoria).
    """
    global LAST_PGVECTOR_PASSWORD

    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    # Resolver password de PGVector
    if not pg_password:
        if LAST_PGVECTOR_PASSWORD:
            pg_password = LAST_PGVECTOR_PASSWORD
        else:
            pg_password = load_pgvector_password()
        if not pg_password:
            pg_password = ask("Password PostgreSQL de PGVector (usuario 'postgres'):", secret=True)

    # API key para Evolution
    if not evolution_api_key:
        evolution_api_key = generate_password(length)

    # Crear volúmenes externos requeridos
    sh("docker volume create evolution_instances", check=False, quiet=True)
    sh("docker volume create evolution_redis", check=False, quiet=True)

    print("🔐 Autenticando en Portainer API como usuario 'admin'…")
    jwt = portainer_api_login(portainer_url, admin_password)

    print("📍 Obteniendo endpointId…")
    endpoint_id = portainer_get_endpoint_id(portainer_url, jwt)

    print("🌀 Obteniendo SwarmID…")
    swarm_id = portainer_get_swarm_id(portainer_url, jwt, endpoint_id)

    stack_content = build_evolution_stack_content(
        overlay=overlay,
        evolution_server_url=evolution_server_url,
        evolution_host=evolution_host,
        evolution_api_key=evolution_api_key,
        pg_password=pg_password,
    )

    print("📦 Creando stack 'evolution' vía Portainer API (ownership=public)…")
    portainer_create_swarm_stack_from_string(
        base_url=portainer_url,
        jwt=jwt,
        endpoint_id=endpoint_id,
        name="evolution",
        stack_content=stack_content,
        swarm_id=swarm_id,
        ownership="public",
    )

    print("🎉 Evolution API desplegado correctamente vía Portainer.")
    print("   Nombre del stack: evolution")
    print("🔐 Datos importantes:")
    print(f"   - Evolution API KEY: {evolution_api_key}")
    print(f"   - PostgreSQL (usuario 'postgres'): {pg_password}")
    print("   Guárdalos en un lugar seguro.")


# ─────────────────────────── Template Chatwoot ───────────────────────────

COMPOSE_TEMPLATE_CHATWOOT = """version: "3.7"
services:

  chatwoot_app:
    image: ghcr.io/fazer-ai/chatwoot:latest
    command: >
      sh -c "echo 'Rails.application.config.active_storage.variant_processor = :mini_magick' > /app/config/initializers/active_storage.rb && bundle exec rails s -p 3000 -b 0.0.0.0"
    entrypoint: docker/entrypoints/rails.sh

    volumes:
      - chatwoot_storage:/app/storage
      - chatwoot_public:/app/public
      - chatwoot_mailer:/app/app/views/devise/mailer
      - chatwoot_mailers:/app/app/views/mailers

    networks:
      - {OVERLAY}
    
    environment:
      - INSTALLATION_NAME={COMPANY_NAME}
      - SECRET_KEY_BASE={SECRET_KEY_BASE}
      - FRONTEND_URL={CHATWOOT_URL}
      - FORCE_SSL=true
      - DEFAULT_LOCALE=es_CO
      - TZ=UTC

      - REDIS_URL=redis://chatwoot_redis:6379

      - POSTGRES_HOST=pgvector
      - POSTGRES_USERNAME=postgres
      - POSTGRES_PASSWORD={PG_PASSWORD_ESCAPED}
      - POSTGRES_DATABASE=chatwoot

      - ACTIVE_STORAGE_SERVICE=local

      - MAILER_SENDER_EMAIL={MAILER_SENDER_EMAIL}
      - SMTP_DOMAIN={SMTP_DOMAIN}
      - SMTP_ADDRESS={SMTP_ADDRESS}
      - SMTP_PORT={SMTP_PORT}
      - SMTP_SSL={SMTP_SSL}
      - SMTP_USERNAME={SMTP_USERNAME}
      - SMTP_PASSWORD={SMTP_PASSWORD_ESCAPED}
      - SMTP_AUTHENTICATION=login
      - SMTP_ENABLE_STARTTLS_AUTO=true
      - SMTP_OPENSSL_VERIFY_MODE=peer
      - MAILER_INBOUND_EMAIL_DOMAIN={MAILER_INBOUND_DOMAIN}

      - SIDEKIQ_CONCURRENCY=10
      - RACK_TIMEOUT_SERVICE_TIMEOUT=0
      - RAILS_MAX_THREADS=5
      - WEB_CONCURRENCY=2
      - ENABLE_RACK_ATTACK=false
      - RAILS_TIME_ZONE=UTC

      - NODE_ENV=production
      - RAILS_ENV=production
      - INSTALLATION_ENV=docker
      - RAILS_LOG_TO_STDOUT=true
      - USE_INBOX_AVATAR_FOR_BOT=true
      - ENABLE_ACCOUNT_SIGNUP=false

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
      labels:
        - traefik.enable=true
        - traefik.http.routers.chatwoot_app.rule=Host(`{CHATWOOT_HOST}`)
        - traefik.http.routers.chatwoot_app.entrypoints=websecure
        - traefik.http.routers.chatwoot_app.tls.certresolver=letsencryptresolver
        - traefik.http.routers.chatwoot_app.priority=1
        - traefik.http.routers.chatwoot_app.service=chatwoot_app
        - traefik.http.services.chatwoot_app.loadbalancer.server.port=3000
        - traefik.http.services.chatwoot_app.loadbalancer.passHostHeader=true
        - traefik.http.middlewares.sslheader.headers.customrequestheaders.X-Forwarded-Proto=https
        - traefik.http.routers.chatwoot_app.middlewares=sslheader


  chatwoot_sidekiq:
    image: ghcr.io/fazer-ai/chatwoot:latest
    command: bundle exec sidekiq -C config/sidekiq.yml

    volumes:
      - chatwoot_storage:/app/storage
      - chatwoot_public:/app/public
      - chatwoot_mailer:/app/app/views/devise/mailer
      - chatwoot_mailers:/app/app/views/mailers

    networks:
      - {OVERLAY}

    environment:
      - INSTALLATION_NAME={COMPANY_NAME}
      - SECRET_KEY_BASE={SECRET_KEY_BASE}
      - FRONTEND_URL={CHATWOOT_URL}
      - FORCE_SSL=true
      - DEFAULT_LOCALE=es_CO
      - TZ=UTC

      - REDIS_URL=redis://chatwoot_redis:6379

      - POSTGRES_HOST=pgvector
      - POSTGRES_USERNAME=postgres
      - POSTGRES_PASSWORD={PG_PASSWORD_ESCAPED}
      - POSTGRES_DATABASE=chatwoot

      - ACTIVE_STORAGE_SERVICE=local

      - MAILER_SENDER_EMAIL={MAILER_SENDER_EMAIL}
      - SMTP_DOMAIN={SMTP_DOMAIN}
      - SMTP_ADDRESS={SMTP_ADDRESS}
      - SMTP_PORT={SMTP_PORT}
      - SMTP_SSL={SMTP_SSL}
      - SMTP_USERNAME={SMTP_USERNAME}
      - SMTP_PASSWORD={SMTP_PASSWORD_ESCAPED}
      - SMTP_AUTHENTICATION=login
      - SMTP_ENABLE_STARTTLS_AUTO=true
      - SMTP_OPENSSL_VERIFY_MODE=peer
      - MAILER_INBOUND_EMAIL_DOMAIN={MAILER_INBOUND_DOMAIN}

      - SIDEKIQ_CONCURRENCY=10
      - RACK_TIMEOUT_SERVICE_TIMEOUT=0
      - RAILS_MAX_THREADS=5
      - WEB_CONCURRENCY=2
      - ENABLE_RACK_ATTACK=false
      - RAILS_TIME_ZONE=UTC

      - NODE_ENV=production
      - RAILS_ENV=production
      - INSTALLATION_ENV=docker
      - RAILS_LOG_TO_STDOUT=true
      - USE_INBOX_AVATAR_FOR_BOT=true
      - ENABLE_ACCOUNT_SIGNUP=false

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


  chatwoot_redis:
    image: redis:latest
    command: [
        "redis-server",
        "--appendonly",
        "yes",
        "--port",
        "6379"
      ]

    volumes:
      - chatwoot_redis:/data

    networks:
      - {OVERLAY}

    deploy:
      placement:
        constraints:
          - node.role == manager
      resources:
        limits:
          cpus: "1"
          memory: 2048M


volumes:
  chatwoot_storage:
    external: true
    name: chatwoot_storage
  chatwoot_public:
    external: true
    name: chatwoot_public
  chatwoot_mailer:
    external: true
    name: chatwoot_mailer
  chatwoot_mailers:
    external: true
    name: chatwoot_mailers
  chatwoot_redis:
    external: true
    name: chatwoot_redis

networks:
  {OVERLAY}:
    external: true
    name: {OVERLAY}
"""


def build_chatwoot_stack_content(overlay: str,
                                 chatwoot_host: str,
                                 company_name: str,
                                 secret_key_base: str,
                                 pg_password: str,
                                 email: str,
                                 email_domain: str,
                                 smtp_address: str,
                                 smtp_port: str,
                                 smtp_ssl: str,
                                 smtp_username: str,
                                 smtp_password: str) -> str:
    """Genera el contenido del stack (YAML) para Chatwoot."""
    pg_password_escaped = escape_dollars(pg_password)
    smtp_password_escaped = escape_dollars(smtp_password)
    mailer_sender_email = f"{email} <{email}>"
    chatwoot_url = f"https://{chatwoot_host}"

    return COMPOSE_TEMPLATE_CHATWOOT.format(
        OVERLAY=overlay,
        CHATWOOT_HOST=chatwoot_host,
        COMPANY_NAME=company_name,
        SECRET_KEY_BASE=secret_key_base,
        PG_PASSWORD_ESCAPED=pg_password_escaped,
        MAILER_SENDER_EMAIL=mailer_sender_email,
        SMTP_DOMAIN=email_domain,
        SMTP_ADDRESS=smtp_address,
        SMTP_PORT=smtp_port,
        SMTP_SSL=smtp_ssl,
        SMTP_USERNAME=smtp_username,
        SMTP_PASSWORD_ESCAPED=smtp_password_escaped,
        MAILER_INBOUND_DOMAIN=email,
        CHATWOOT_URL=chatwoot_url,
    )


def deploy_chatwoot_via_portainer_api(overlay: str,
                                      portainer_url: str,
                                      admin_password: str,
                                      pg_password: str = None,
                                      chatwoot_host: str = None,
                                      company_name: str = None,
                                      email: str = None,
                                      email_domain: str = None,
                                      smtp_address: str = None,
                                      smtp_port: str = None,
                                      smtp_ssl: str = None,
                                      smtp_username: str = None,
                                      smtp_password: str = None):
    """
    Despliega el stack 'chatwoot' vía API de Portainer, ownership=public.
    Reutiliza el password de PGVector.
    """
    global LAST_PGVECTOR_PASSWORD

    if not overlay:
        print("❌ No se proporcionó nombre de red overlay.")
        sys.exit(1)

    # Resolver password de PGVector
    if not pg_password:
        if LAST_PGVECTOR_PASSWORD:
            pg_password = LAST_PGVECTOR_PASSWORD
        else:
            pg_password = load_pgvector_password()
        if not pg_password:
            pg_password = ask("Password PostgreSQL de PGVector (usuario 'postgres'):", secret=True)

    # Pedir parámetros si faltan
    if not chatwoot_host:
        chatwoot_host = ask("Dominio (FQDN) para Chatwoot (ej: empresa.midominio.com):", validator=validate_fqdn)
    if not company_name:
        company_name = ask("Nombre de la empresa para Chatwoot (INSTALLATION_NAME):")
    if not email:
        email = ask("Email remitente SMTP para Chatwoot (ej: soporte@midominio.com):", validator=validate_email)
    if not email_domain:
        email_domain = ask("Dominio SMTP (ej: midominio.com):")
    if not smtp_address:
        smtp_address = ask("Host SMTP (ej: smtp.midominio.com):")
    if not smtp_port:
        smtp_port = ask("Puerto SMTP (465, 587, etc):")
    if not smtp_ssl:
        smtp_ssl = ask("¿Usa SSL puro? (true para 465, false para 587):")
    if not smtp_username:
        smtp_username = ask("Usuario SMTP:")
    if not smtp_password:
        smtp_password = ask("Password SMTP:", secret=True)

    secret_key_base = generate_secret_key_base()

    # Crear volúmenes externos requeridos
    sh("docker volume create chatwoot_storage", check=False, quiet=True)
    sh("docker volume create chatwoot_public", check=False, quiet=True)
    sh("docker volume create chatwoot_mailer", check=False, quiet=True)
    sh("docker volume create chatwoot_mailers", check=False, quiet=True)
    sh("docker volume create chatwoot_redis", check=False, quiet=True)

    print("🔐 Autenticando en Portainer API como usuario 'admin'…")
    jwt = portainer_api_login(portainer_url, admin_password)

    print("📍 Obteniendo endpointId…")
    endpoint_id = portainer_get_endpoint_id(portainer_url, jwt)

    print("🌀 Obteniendo SwarmID…")
    swarm_id = portainer_get_swarm_id(portainer_url, jwt, endpoint_id)

    stack_content = build_chatwoot_stack_content(
        overlay=overlay,
        chatwoot_host=chatwoot_host,
        company_name=company_name,
        secret_key_base=secret_key_base,
        pg_password=pg_password,
        email=email,
        email_domain=email_domain,
        smtp_address=smtp_address,
        smtp_port=smtp_port,
        smtp_ssl=smtp_ssl,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
    )

    print("📦 Creando stack 'chatwoot' vía Portainer API (ownership=public)…")
    portainer_create_swarm_stack_from_string(
        base_url=portainer_url,
        jwt=jwt,
        endpoint_id=endpoint_id,
        name="chatwoot",
        stack_content=stack_content,
        swarm_id=swarm_id,
        ownership="public",
    )

    print("🎉 Chatwoot desplegado correctamente vía Portainer.")
    print("   Nombre del stack: chatwoot")
    print(f"   URL: https://{chatwoot_host}")


# ─────────────────────────── Instalador Docker 28.0.3 ───────────────────────────

class Docker28Installer:
    """
    Instalador completo para Docker 28.0.3 en Ubuntu.
    • Elimina versiones previas
    • Instala Docker 28.x y bloquea versión
    • Inicializa Swarm
    • Crea red overlay
    """

    def __init__(self, quiet: bool = False, overlay_name: str = None):
        self.target_version = "5:28.0.3"
        self.log_file = "/var/log/docker_installer.log"
        self.quiet = quiet
        self.overlay_name = overlay_name
        self._init_log()

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

    def force_swarm_init(self):
        print("🌐 Inicializando Docker Swarm (forzado)...")
        self.run_command("docker swarm leave --force", shell=True, check=False)
        self.run_command("docker swarm init", shell=True)
        print("✅ Docker Swarm inicializado.")

    def create_overlay_network(self) -> str:
        print("🕸️  Creación de red overlay attachable")
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
            print(f"ℹ️  La red '{name}' ya existe, se reutiliza.")
        else:
            self.run_command(f"docker network create -d overlay --attachable {name}", shell=True)
            print(f"✅ Red overlay '{name}' creada.")
        self.overlay_name = name
        return name

    def run(self) -> str:
        if os.geteuid() != 0:
            print("🔒 Ejecute este script como root (sudo).")
            sys.exit(1)

        print(BANNER)
        print("🔧 Instalador de Docker 28.0.3 + Swarm + Overlay")
        print("📄 Log detallado en /var/log/docker_installer.log")

        current = self.get_current_docker_version()
        if current:
            print(f"📋 Versión actual detectada: {current}")
            print("🔄 Eliminando versión previa...")
            self.remove_current_docker()

        self.install_docker_28()
        self.configure_docker()
        self.force_swarm_init()
        overlay = self.create_overlay_network()

        print("🎉 Instalación completada con éxito.")
        print("💡 Use 'newgrp docker' o reinicie sesión para aplicar permisos.")
        print(f"📜 Log completo: {self.log_file}")
        return overlay

    def verify_installation(self):
        pass


# ─────────────────────────── Limpieza con clean.sh ───────────────────────────

def run_clean_script():
    script_path = Path(__file__).with_name("clean.sh")
    if not script_path.exists():
        print(f"❌ No se encontró '{script_path}'. Coloque clean.sh en la misma carpeta.")
        return
    print("========================================")
    print("     LIMPIEZA TOTAL DEL SISTEMA DOCKER  ")
    print("========================================")
    os.chmod(script_path, 0o755)
    subprocess.run([str(script_path)], check=False)
    print("✅ Limpieza finalizada.")


# ─────────────────────────── CLI / Menú ───────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Instalador maestro TRISKEL v3.0.0")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso")
    parser.add_argument("--overlay", type=str, help="Nombre de la red overlay")
    parser.add_argument("--install-docker", action="store_true", help="Instalar Docker + Swarm + overlay")
    parser.add_argument("--install-traefik", action="store_true", help="Desplegar Traefik + Portainer")
    parser.add_argument("--install-pgvector", action="store_true", help="Desplegar PGVector vía Portainer")
    parser.add_argument("--install-evolution", action="store_true", help="Desplegar Evolution API vía Portainer")
    parser.add_argument("--install-chatwoot", action="store_true", help="Desplegar Chatwoot vía Portainer")
    parser.add_argument("--le-email", type=str, help="Email para Let's Encrypt")
    parser.add_argument("--portainer-fqdn", type=str, help="FQDN para Portainer")
    parser.add_argument("--portainer-url", type=str, help="URL base de Portainer")
    parser.add_argument("--portainer-password", type=str, help="Clave ADMIN de Portainer")
    parser.add_argument("--pgvector-password", type=str, help="Password explícita para PGVector (opcional)")
    parser.add_argument("--evolution-url", type=str, help="URL pública Evolution API (https://...)")
    parser.add_argument("--evolution-host", type=str, help="FQDN Evolution API (ej: evo.midominio.com)")
    parser.add_argument("--evolution-api-key", type=str, help="API key de Evolution (opcional)")
    parser.add_argument("--chatwoot-host", type=str, help="FQDN Chatwoot (empresa.midominio.com)")
    parser.add_argument("--chatwoot-company", type=str, help="Nombre empresa Chatwoot")
    parser.add_argument("--smtp-email", type=str, help="Email remitente SMTP")
    parser.add_argument("--smtp-domain", type=str, help="Dominio SMTP")
    parser.add_argument("--smtp-address", type=str, help="Host SMTP")
    parser.add_argument("--smtp-port", type=str, help="Puerto SMTP")
    parser.add_argument("--smtp-ssl", type=str, help="SSL SMTP (true/false)")
    parser.add_argument("--smtp-username", type=str, help="Usuario SMTP")
    parser.add_argument("--smtp-password", type=str, help="Password SMTP")
    return parser.parse_args()


def run_menu(default_overlay: str = None):
    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD
    overlay = default_overlay

    while True:
        print(BANNER)
        print("1) Instalar Docker 28 + Swarm + red overlay")
        print("2) Instalar Traefik + Portainer (con Agent)")
        print("3) Instalar base de datos PGVector (via API Portainer)")
        print("4) Instalar Evolution API (via API Portainer)")
        print("5) Instalar Chatwoot (via API Portainer)")
        print("6) Limpiar sistema (clean.sh)")
        print("")
        print("0) Salir")
        print("-------------------------------------------")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            installer = Docker28Installer(quiet=False, overlay_name=overlay)
            overlay = installer.run()

        elif opcion == "2":
            if not overlay:
                overlay = choose_overlay_network()
            deploy_traefik_portainer(overlay)

        elif opcion == "3":
            if not overlay:
                overlay = choose_overlay_network()

            if LAST_PORTAINER_URL and LAST_PORTAINER_PASSWORD:
                portainer_url = LAST_PORTAINER_URL
                admin_pwd = LAST_PORTAINER_PASSWORD
            else:
                while True:
                    raw = ask("URL base de Portainer (ej: https://portainer.midominio.com):")
                    portainer_url, _ = normalize_url(raw)
                    if portainer_url:
                        break
                    print("❌ URL inválida. Debe ser algo como https://portainer.midominio.com\n")
                admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

            deploy_pgvector_via_portainer_api(
                overlay=overlay,
                portainer_url=portainer_url,
                admin_password=admin_pwd,
            )

        elif opcion == "4":
            if not overlay:
                overlay = choose_overlay_network()

            if LAST_PORTAINER_URL and LAST_PORTAINER_PASSWORD:
                portainer_url = LAST_PORTAINER_URL
                admin_pwd = LAST_PORTAINER_PASSWORD
            else:
                while True:
                    raw = ask("URL base de Portainer (ej: https://portainer.midominio.com):")
                    portainer_url, _ = normalize_url(raw)
                    if portainer_url:
                        break
                    print("❌ URL inválida. Debe ser algo como https://portainer.midominio.com\n")
                admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

            evolution_host = ask("Dominio (FQDN) para Evolution API (sin https, ej: evo.midominio.com):", validator=validate_fqdn)
            evolution_server_url = f"https://{evolution_host}"

            deploy_evolution_via_portainer_api(
                overlay=overlay,
                portainer_url=portainer_url,
                admin_password=admin_pwd,
                evolution_server_url=evolution_server_url,
                evolution_host=evolution_host,
            )

        elif opcion == "5":
            if not overlay:
                overlay = choose_overlay_network()

            if LAST_PORTAINER_URL and LAST_PORTAINER_PASSWORD:
                portainer_url = LAST_PORTAINER_URL
                admin_pwd = LAST_PORTAINER_PASSWORD
            else:
                while True:
                    raw = ask("URL base de Portainer (ej: https://portainer.midominio.com):")
                    portainer_url, _ = normalize_url(raw)
                    if portainer_url:
                        break
                    print("❌ URL inválida. Debe ser algo como https://portainer.midominio.com\n")
                admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

            deploy_chatwoot_via_portainer_api(
                overlay=overlay,
                portainer_url=portainer_url,
                admin_password=admin_pwd,
            )

        elif opcion == "6":
            run_clean_script()

        elif opcion == "0":
            print("👋 Saliendo...")
            break

        else:
            print("⚠️ Opción inválida.")


def main():
    if os.geteuid() != 0:
        print("🔒 Ejecute este script como root.")
        sys.exit(1)

    global LAST_PORTAINER_URL, LAST_PORTAINER_PASSWORD
    args = parse_args()

    if not (args.install_docker or args.install_traefik or args.install_pgvector or
            args.install_evolution or args.install_chatwoot):
        run_menu()
        return

    overlay = args.overlay

    portainer_url = args.portainer_url
    if not portainer_url and args.portainer_fqdn:
        portainer_url = f"https://{args.portainer_fqdn}"

    if args.install_docker:
        installer = Docker28Installer(quiet=args.quiet, overlay_name=overlay)
        overlay = installer.run()

    if args.install_traefik:
        if not overlay:
            overlay = choose_overlay_network()
        deploy_traefik_portainer(
            overlay=overlay,
            quiet=args.quiet,
            le_email=args.le_email,
            portainer_host=args.portainer_fqdn,
            admin_password=args.portainer_password,
        )

    if args.install_pgvector:
        if not overlay:
            overlay = choose_overlay_network()

        if not portainer_url and LAST_PORTAINER_URL:
            portainer_url = LAST_PORTAINER_URL
        if not portainer_url:
            portainer_url = ask("URL base de Portainer (ej: https://portainer.midominio.com):")

        admin_pwd = args.portainer_password or LAST_PORTAINER_PASSWORD
        if not admin_pwd:
            admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

        deploy_pgvector_via_portainer_api(
            overlay=overlay,
            portainer_url=portainer_url,
            admin_password=admin_pwd,
            password=args.pgvector_password,
        )

    if args.install_evolution:
        if not overlay:
            overlay = choose_overlay_network()

        if not portainer_url and LAST_PORTAINER_URL:
            portainer_url = LAST_PORTAINER_URL
        if not portainer_url:
            portainer_url = ask("URL base de Portainer (ej: https://portainer.midominio.com):")

        admin_pwd = args.portainer_password or LAST_PORTAINER_PASSWORD
        if not admin_pwd:
            admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

        evolution_host = args.evolution_host
        if not evolution_host:
            evolution_host = ask("Dominio (FQDN) para Evolution API (sin https, ej: evo.midominio.com):", validator=validate_fqdn)
        evolution_url = args.evolution_url or f"https://{evolution_host}"

        deploy_evolution_via_portainer_api(
            overlay=overlay,
            portainer_url=portainer_url,
            admin_password=admin_pwd,
            evolution_server_url=evolution_url,
            evolution_host=evolution_host,
            pg_password=args.pgvector_password,
            evolution_api_key=args.evolution_api_key,
        )

    if args.install_chatwoot:
        if not overlay:
            overlay = choose_overlay_network()

        if not portainer_url and LAST_PORTAINER_URL:
            portainer_url = LAST_PORTAINER_URL
        if not portainer_url:
            portainer_url = ask("URL base de Portainer (ej: https://portainer.midominio.com):")

        admin_pwd = args.portainer_password or LAST_PORTAINER_PASSWORD
        if not admin_pwd:
            admin_pwd = ask("Password ADMIN de Portainer:", secret=True)

        deploy_chatwoot_via_portainer_api(
            overlay=overlay,
            portainer_url=portainer_url,
            admin_password=admin_pwd,
            pg_password=args.pgvector_password,
            chatwoot_host=args.chatwoot_host,
            company_name=args.chatwoot_company,
            email=args.smtp_email,
            email_domain=args.smtp_domain,
            smtp_address=args.smtp_address,
            smtp_port=args.smtp_port,
            smtp_ssl=args.smtp_ssl,
            smtp_username=args.smtp_username,
            smtp_password=args.smtp_password,
        )


if __name__ == "__main__":
    main()
