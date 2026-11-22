# Win-DiagKit

**Win-DiagKit** (`v2.0.0`) es una herramienta portable de auditoría, diagnóstico heurístico e inspección en vivo para **Windows 10/11 (x64)**, empaquetada en un único script de PowerShell (`diagkit.ps1`) compatible con **Windows PowerShell 5.1+** y diseñada para ejecutarse de forma remota o local sin dejar rastro tras su limpieza.

---

## Inicio rápido

### Ejecución remota directa (recomendado)

Abre **PowerShell** (preferiblemente como Administrador) y ejecuta:

```powershell
irm "https://raw.githubusercontent.com/moralesguasca99/win-diagkit/main/diagkit.ps1" | iex
```

> Si se ejecuta sin permisos de Administrador, el script detectará el modo limitado y ofrecerá relanzarse automáticamente con elevación UAC.

### Ejecución local

```powershell
git clone https://github.com/moralesguasca99/win-diagkit.git
cd win-diagkit
powershell -NoProfile -ExecutionPolicy Bypass -File .\diagkit.ps1
```

---

## Requisitos

- **Sistema operativo:** Windows 10 u 11 (x64)
- **Intérprete:** Windows PowerShell 5.1 o superior
- **Permisos:** Administrador recomendado (requerido por Windows para leer contadores S.M.A.R.T., `C:\Windows\Minidump` y eventos `WHEA-Logger` / `Kernel-Power`)
- **Conexión a Internet:** Opcional (necesaria únicamente para descargar Specify y Sysinternals; la opción `[4]` opera 100% offline)

---

## Menú interactivo

| Opción | Nombre | Descripción |
| :---: | :--- | :--- |
| **`[1]`** | **Instalar / Actualizar kit portable** | Crea `C:\WinDiagKit\Bin` (fuera de OneDrive) y descarga la última versión de **Specify** (`noring0`), **Process Explorer (x64)** y **Autoruns (x64)** mediante descarga atómica, validación de tamaño y firma digital de Microsoft en Sysinternals. |
| **`[2]`** | **Diagnóstico completo** | Ejecuta Specify en modo local (*Don't Upload*), cruza el JSON resultante con telemetría nativa (S.M.A.R.T., volúmenes, minidumps y Visor de Eventos), muestra un resumen en consola y genera un reporte HTML en el Escritorio. |
| **`[3]`** | **Inspección en vivo (Sysinternals)** | Permite lanzar **Process Explorer** (`procexp64.exe`) o **Autoruns** (`autoruns64.exe`), descargándolos y validando su firma automáticamente si aún no están presentes. |
| **`[4]`** | **Auditoría rápida nativa (Offline)** | Ejecuta el mismo motor heurístico y genera el reporte HTML sin descargar ningún binario externo, usando exclusivamente CIM/WMI, Registro, módulos de almacenamiento nativos y `Get-WinEvent`. |
| **`[5]`** | **Limpieza integral** | Previa confirmación (`S/N`), detiene procesos del kit, elimina `C:\WinDiagKit`, borra los reportes `Diagnostico_PC_*.html` del Escritorio y limpia únicamente las subclaves de registro de Process Explorer y Autoruns. |
| **`[0]`** | **Salir** | Finaliza el script dejando la sesión interactiva de PowerShell limpia. |

---

## Motor heurístico

Tanto el modo completo con Specify (`[2]`) como la auditoría nativa offline (`[4]`) alimentan un esquema canónico unificado evaluado por reglas deterministas:

- **Memoria RAM (Single Channel y XMP/DOCP):** detecta equipos operando con un solo módulo (evitando falsos positivos en RAM soldada LPDDR4/LPDDR5) y módulos corriendo por debajo de su frecuencia nominal (incluye soporte para nomenclatura DDR4/DDR5 y Kingston Fury).
- **Estabilidad y BSOD:** analiza archivos en `C:\Windows\Minidump` y eventos de los últimos 14 días en el registro `System` (`BugCheck 1001`, `Kernel-Power 41` y errores físicos/corregidos de `WHEA-Logger` IDs `17`, `18`, `19` y `20`).
- **Uptime e Inicio Rápido:** alerta cuando el kernel acumula `>= 48 horas` sin reinicio real, verificando el estado de `HiberbootEnabled`.
- **Presión de RAM y Top 10 procesos:** alerta si `Memory Compression >= 400 MB` o la RAM física libre es `< 15%`, y agrupa procesos multi-instancia para mostrar los 10 mayores consumidores reales.
- **Antivirus, bloatware y acceso remoto:** identifica suites pesadas/bloatware y Windows Defender en modo pasivo; informa si hay múltiples clientes de acceso remoto activos simultáneamente (`AnyDesk`, `RustDesk`, `TeamViewer`, `ScreenConnect`).
- **Arranque de Windows:** alerta si hay más de `6` programas configurados al inicio y sugiere aplicaciones no esenciales candidatas a deshabilitar.
- **Almacenamiento (S.M.A.R.T. y volúmenes):** evalúa salud degradada (`CRITICAL`), errores de lectura/escritura, desgaste `>= 85%`, temperatura `>= 60 °C` y particiones con `< 20%` de espacio libre.
- **Extensiones de navegador** *(con Specify)*: detecta extensiones sin nombre instaladas en perfiles de navegadores.
- **Actualizaciones pendientes:** verifica las claves `RebootPending` / `RebootRequired` de CBS y Windows Update.

---

## Reporte HTML y rutas de trabajo

- **Reporte visual:** generado en el Escritorio como `Diagnostico_PC_<EQUIPO>_<yyyyMMdd_HHmmss>.html` (autocontenido en tema oscuro, UTF-8 sin BOM, con resumen de hardware, tarjetas de hallazgos por severidad, Top 10 de RAM y secciones desplegables de discos, eventos críticos y arranque).
- **Directorio portable:** `C:\WinDiagKit\Bin` (aislado fuera de OneDrive para evitar bloqueos de sincronización durante las capturas).

---

## Seguridad y privacidad

- **Ejecución local y sin telemetría:** la auditoría nativa (`[4]`) no realiza ninguna conexión de red; en el modo completo (`[2]`) se indica activar *Don't Upload* en Specify para mantener los datos únicamente en el equipo.
- **Integridad de binarios:** `procexp64.exe` y `autoruns64.exe` se descargan desde `live.sysinternals.com` con verificación obligatoria de firma digital Authenticode emitida por Microsoft.
- **Aislamiento de sesión:** todo el script se ejecuta encapsulado en `& { ... }` sin variables globales ni de script, evitando contaminar la consola del usuario.
- **Limpieza segura:** la opción `[5]` exige confirmación explícita, detiene solo procesos propios del kit y conserva cualquier otra clave preexistente en `HKCU:\Software\Sysinternals`.

---

## Estructura del repositorio

- [`diagkit.ps1`](diagkit.ps1) — Script monolítico en 6 capas (*Functional Core / Imperative Shell*).
- [`AGENTS.md`](AGENTS.md) — Guía técnica, invariantes de compatibilidad y checklist de verificación.
- [`README.md`](README.md) — Documentación principal.
