# Hydra-n8n-Auditor

**MCP Server for Agentic n8n Workflow Auditing & Auto-Patching**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)

Un servidor MCP (Model Context Protocol) que actúa como sensor y actuador agéntico para auditar y auto-parchear flujos de trabajo (workflows) en una instancia de n8n. Implementa los conceptos de **Inmunidad Activa** y **Autodefensa Agéntica**: el LLM (via OpenCode) actúa como sistema inmunológico digital, leyendo, auditando y mutando workflows sin downtime.

---

## Arquitectura

```
┌──────────────┐   stdio (JSON-RPC)   ┌──────────────────────┐   HTTP REST    ┌───────────┐
│              │ ◄──────────────────► │                      │ ◄────────────► │           │
│   OpenCode   │                      │  Hydra-n8n-Auditor   │                │    n8n    │
│  (LLM MCP)   │                      │  (FastMCP + httpx)   │   X-N8N-API-KEY│  :5678    │
│              │                      │                      │                │           │
└──────────────┘                      └──────────────────────┘                └───────────┘
```

- **Transporte**: `stdio` — integración nativa con OpenCode, sin exponer puertos HTTP.
- **Autenticación**: `N8N_API_KEY` vía header `X-N8N-API-KEY`.
- **Clientes HTTP**: `httpx.AsyncClient` con timeout de 30s y manejo de errores capa por capa.

---

## Herramientas (Tools)

| Tool | Tipo | Endpoint HTTP | Propósito |
|---|---|---|---|
| `list_active_workflows` | Sensor | `GET /workflows` | Lista solo los flujos activos (id, name, updatedAt) |
| `get_workflow_definition` | Sensor | `GET /workflows/{id}` | Devuelve el JSON completo con instrucciones de auditoría de seguridad |
| `patch_workflow` | Actuador | `PUT /workflows/{id}` | Aplica mutaciones al workflow. Soporta modo `dry_run` para validación previa |
| `deactivate_workflow` | Kill-Switch | `GET + PUT /workflows/{id}` | Desactiva un workflow en emergencia: fetch → `active=false` → PUT |

### Ejemplos de detección de vulnerabilidades

El LLM analiza el JSON de `get_workflow_definition` buscando:

1. **Webhooks sin autenticación** — nodos `n8n-nodes-base.webhook` con `authentication: "none"`.
2. **RCE via executeCommand** — nodos `n8n-nodes-base.executeCommand` que interpolan datos de usuario.
3. **Secretos hardcodeados** — parámetros con API keys, tokens o passwords en texto plano.
4. **SSRF en HttpRequest** — URLs a `169.254.169.254` (metadata cloud) o IPs internas.

---

## Prerequisitos

- **Python 3.10+**
- Una instancia de **n8n** en funcionamiento
- Una **API key de n8n** (Settings → API → Create Key)
- **OpenCode** instalado para usar el servidor MCP

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Owito/Hydra-n8n-Auditor.git
cd Hydra-n8n-Auditor

# Crear y activar entorno virtual
python -m venv .venv

# Windows
.venv\Scripts\Activate

# macOS / Linux
# source .venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## Configuración

### Variables de entorno

| Variable | Requerida | Default | Descripción |
|---|---|---|---|
| `N8N_API_KEY` | **Sí** | — | API key de tu instancia n8n |
| `N8N_BASE_URL` | No | `http://localhost:5678/api/v1` | URL base de la API REST de n8n |

### Registro en OpenCode

Agrega este bloque dentro del objeto `"mcp"` en tu `opencode.jsonc`:

```jsonc
"n8n-hydra": {
    "type": "local",
    "command": [
        "python",
        "D:/MCP de n8n/n8n_hydra_mcp.py"
    ],
    "env": {
        "N8N_BASE_URL": "http://localhost:5678/api/v1",
        "N8N_API_KEY": "tu-api-key-aqui"
    },
    "enabled": true
}
```

> Reemplaza la ruta y `N8N_API_KEY` con tus valores reales. Al reiniciar OpenCode, el servidor se levantará automáticamente via stdio.

---

## Flujo de auditoría típico

El LLM en OpenCode usa las herramientas en esta secuencia:

```
1. list_active_workflows()
   └─ ¿Qué flujos están corriendo actualmente?

2. get_workflow_definition("abc123")
   └─ Analiza nodos en busca de vulnerabilidades

3. patch_workflow("abc123", new_json, dry_run=True)
   └─ Valida el parche ANTES de aplicarlo

4. patch_workflow("abc123", new_json, dry_run=False)
   └─ Aplica solo si dry_run fue exitoso

5. (opcional) deactivate_workflow("abc123")
   └─ Kill-switch si se detecta una vulnerabilidad crítica inmediata
```

---

## Estructura del proyecto

```
D:\MCP de n8n\
├── .gitignore
├── README.md
├── n8n_hydra_mcp.py    ← Servidor MCP principal (~340 líneas)
└── requirements.txt     ← Dependencias: fastmcp, httpx
```

---

## Licencia

MIT
