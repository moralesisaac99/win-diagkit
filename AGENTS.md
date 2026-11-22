# AGENTS.md — Win-DiagKit

Guia operativa y de arquitectura para agentes y colaboradores que trabajen en `win-diagkit`.

## 1. Vision general del proyecto

`win-diagkit` es una herramienta portable de auditoria, diagnostico heuristico e inspeccion en vivo para Windows 10/11 (x64), empaquetada en un unico script PowerShell (`diagkit.ps1`, v2.0.0) compatible con **Windows PowerShell 5.1+** y ejecucion directa remota mediante:

```powershell
irm "https://raw.githubusercontent.com/moralesguasca99/win-diagkit/main/diagkit.ps1" | iex
```

### Estructura del repositorio
- `diagkit.ps1`: Script monolitico organizado en 6 capas (unica fuente de logica ejecutable).
- `README.md`: Instrucciones de ejecucion rapida.
- `.gitignore`: Ignora binarios y capturas (`*.exe`, `*.zip`, `*.json`, `*.xml`). Tampoco deben commitearse reportes `Diagnostico_PC_*.html`.
- `AGENTS.md`: Este documento.

---

## 2. Arquitectura de `diagkit.ps1`

El script sigue el patron **Functional Core / Imperative Shell**, envuelto en un bloque `& { ... }` para aislar su ejecucion:

1. **Capa 1 — Configuracion (`$Config`):** Single Source of Truth con version, `SelfUrl`, rutas (`C:\WinDiagKit`, `C:\WinDiagKit\Bin`, Escritorio), URLs (GitHub API de Specify y binarios directos x64 de Sysinternals), umbrales heuristicos y firmas de deteccion.
2. **Capa 2 — Utilidades e Imperativa:**
   - `Test-IsAdmin` y `Request-ElevationIfNeeded` (elevacion UAC local o remota).
   - `Get-SafeProp`, `ConvertTo-HtmlSafe`, `Get-ToolPath`.
   - `Invoke-VerifiedDownload` (descarga atomica, validacion de tamano minimo y firma Authenticode de Microsoft).
   - `Get-NativeStorageAndEvents` (CIM/WMI, registro, discos fisicos + `Get-StorageReliabilityCounter`, volumenes, minidumps y `Get-WinEvent`).
3. **Capa 3 — Adaptadores Canonicos:**
   - `ConvertFrom-SpecifyToCanonical`: Normaliza el JSON de Specify + enriquecimiento nativo.
   - `New-NativeOnlyCanonical`: Construye el mismo esquema canonico 100% offline sin descargas.
4. **Capa 4 — Motor Heuristico (puro/determinista):**
   - `New-Finding`, `Get-AggregatedTopProcesses`, `Invoke-HeuristicAnalysis`.
   - Reglas actuales:
     - **Regla 1:** RAM Single Channel (con deteccion de RAM soldada/LPDDR) y XMP/DOCP.
     - **Regla 2:** BSOD, Minidumps, `Kernel-Power 41` y errores fisicos/corregidos `WHEA-Logger`.
     - **Regla 3:** Uptime prolongado (`>= 48h`) + Inicio Rapido (`HiberbootEnabled`).
     - **Regla 4:** Presion de RAM (`Memory Compression >= 400 MB` o RAM libre `< 15%`).
     - **Regla 5 / 5B:** Antivirus pesados/bloatware/Defender pasivo y multiples herramientas de acceso remoto activas.
     - **Regla 6:** Arranque sobrecargado (`> 6` tareas) con sugerencia de apps no esenciales.
     - **Regla 7:** Almacenamiento — salud S.M.A.R.T. degradada (`CRITICAL`), errores R/W, desgaste (`>= 85%`), temperatura (`>= 60 C`) y volumenes con `< 20%` libre.
     - **Regla 8:** Extensiones de navegador sin nombre (cuando hay JSON de Specify).
     - **Regla 9:** Reinicio pendiente de Windows Update / CBS.
5. **Capa 5 — Presentacion:**
   - `Show-ConsoleSummary`: Resumen ejecutivo en terminal.
   - `Export-HtmlReport`: Reporte autocontenido en tema oscuro (UTF-8 sin BOM) guardado en el Escritorio como `Diagnostico_PC_<HOST>_<yyyyMMdd_HHmmss>.html`.
6. **Capa 6 — Casos de uso y menu interactivo:**
   - `[1]` `Invoke-InstallKit`
   - `[2]` `Invoke-FullDiagnostic`
   - `[3]` `Invoke-LiveInspection` (Process Explorer / Autoruns)
   - `[4]` `Invoke-NativeOfflineAudit`
   - `[5]` `Invoke-ForensicCleanup`

---

## 3. Reglas e invariantes obligatorias

Cualquier cambio en `diagkit.ps1` debe respetar estrictamente las siguientes reglas:

### Compatibilidad con Windows PowerShell 5.1 y `irm | iex`
- **Solo ASCII en `diagkit.ps1`:** No introducir tildes, `ñ`, comillas tipograficas ni emojis en strings o comentarios. En PowerShell 5.1, `Invoke-RestMethod` sobre `raw.githubusercontent.com` decodifica sin charset como Windows-1252/ISO-8859-1 y corrompe UTF-8.
- **Sin sintaxis exclusiva de PowerShell 7+:** Prohibido usar `??`, `?.`, operador ternario `?:`, operadores de cadena `&&`/`||` o `ForEach-Object -Parallel`.
- **Aislamiento de sesion:** Mantener `#Requires -Version 5.1` y el encabezado `<# ... #>` fuera de `& { ... }`, y toda la logica y `$Config` dentro de `& { ... }`. No usar `$Script:` ni `$Global:` para no contaminar la sesion interactiva del usuario.
- **TLS sin degradacion:** Habilitar TLS 1.2 siempre con `-bor`:
  `[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12`.
  Al relanzar con UAC en modo `irm | iex`, anteponer esa misma linea dentro del `-Command` antes de `irm`.
- **Salida limpia al elevar:** No llamar `exit 0` dentro de `Request-ElevationIfNeeded` (mataria la terminal del usuario en `iex`); retornar `"ELEVATED"` y finalizar con `return` en el punto de entrada.

### Descargas, integridad y archivos locales
- **Descarga atomica con extension `.exe`:** Usar temporal `.tmp_<nombre>` dentro de `BinDir` (conserva `.exe` para `Get-AuthenticodeSignature` y evita que `Specify*.exe` lo detecte).
- **Firma digital obligatoria en Sysinternals:** Mantener `-RequireMicrosoftSignature` en `procexp64.exe` y `autoruns64.exe` (valida `Status -eq "Valid"` y emisor `*Microsoft*`).
- **Actualizacion limpia de Specify:** `Get-ToolPath` debe ordenar `Specify*.exe` por `LastWriteTime -Descending`, e `Invoke-InstallKit` debe borrar versiones previas solo despues de que el nuevo binario descargue correctamente.
- **Rutas fuera de OneDrive:** Mantener binarios y JSON crudos en `C:\WinDiagKit\Bin` para evitar bloqueos y sincronizaciones de OneDrive.

### Recoleccion de datos y motor heuristico
- **Visor de Eventos (`Get-WinEvent`):** Filtrar `Id` y `StartTime` dentro de `-FilterHashtable` (nunca aplicar `-MaxEvents` antes de filtrar) y validar pares exactos `(ProviderName, Id)` en `Where-Object`, incluyendo warnings corregidos de `WHEA-Logger` (IDs `17`/`19`, Level 3).
- **Paridad entre adaptadores canonicos:** Cualquier campo nuevo usado en reglas o reportes debe poblarse (o tener valor por defecto coherente) tanto en `ConvertFrom-SpecifyToCanonical` como en `New-NativeOnlyCanonical`.
  - Mantener filtro de `desktop.ini` en `StartupTasks` en ambos adaptadores.
  - Usar `[long]` para `CapacityMB` (con conversion defensiva si llega en bytes) y fallback de `RamTotalGB` desde los modulos.
  - Propagar `IsSoldered` para evitar falsos positivos de Single Channel en portatiles con LPDDR4/LPDDR5.
- **Reglas precisas:**
  - En Regla 1 (XMP/DOCP), validar velocidades contra frecuencias estandar DDR4/DDR5 y soportar el formato de 2 digitos de Kingston Fury (`KF[45](\d{2})[CS]`).
  - En Regla 5 (`HeavyAvAndBloat`), usar nombres especificos de proceso/servicio (evitar subcadenas genericas como `AVG`).
  - En Regla 7 (S.M.A.R.T.), ignorar `TempC -le 0` (sensores no soportados que reportan `0`).

### Presentacion, manejo de errores y limpieza
- **Escape HTML obligatorio:** Todo texto proveniente del sistema o JSON debe pasar por `ConvertTo-HtmlSafe` antes de insertarse en el HTML.
- **Valores nulos seguros:** Formatear `CpuLoadPct`, `RamTotalGB`, `RamFreePct`, `UptimeHours`, `TempC`, `WearPct` y `ReadErrors`/`WriteErrors` con `"N/A"` cuando sean `$null` (o `<= 0` en temperatura).
- **Proteger `Start-Process`:** Todo lanzamiento de ejecutables o apertura de reporte HTML debe ir en su propio `try/catch` con `-ErrorAction Stop` (en particular, fallar al abrir el navegador nunca debe reportar fallo en la generacion del HTML).
- **Limpieza integral segura (`Invoke-ForensicCleanup`):**
  - Exigir confirmacion explicita (`S/N`) antes de detener procesos o borrar archivos.
  - Detener unicamente procesos del kit (`Specify*`, `procexp*`, `autoruns*`).
  - Limpiar solo las subclaves `HKCU:\Software\Sysinternals\Process Explorer` y `Autoruns`; eliminar `HKCU:\Software\Sysinternals` unicamente si queda sin subclaves ni propiedades.

---

## 4. Verificacion recomendada tras cada cambio

### Validacion estatica (en Linux o Windows)
Ejecutar antes de hacer commit para asegurar ASCII puro, ausencia de fugas de scope y llaves balanceadas:

```bash
python3 -c '
import re
data = open("diagkit.ps1", "r", encoding="utf-8").read()
non_ascii = [(i+1, l) for i, l in enumerate(data.splitlines()) if any(ord(c) > 127 for c in l)]
assert not non_ascii, f"Non-ASCII found: {non_ascii}"
assert "$Script:" not in data, "Found $Script: scope leak"
cleaned = re.sub(r"@\"\n.*?\n\"@", "\"\"", data, flags=re.S)
txt = "\n".join(l for l in cleaned.splitlines() if not l.lstrip().startswith("#"))
o, c = txt.count("{"), txt.count("}")
assert o == c, f"Unbalanced braces: {o} vs {c}"
print("Static checks OK")
'
```

### Pruebas funcionales en Windows (PowerShell 5.1)
Cuando se modifiquen flujos criticos, verificar en Windows 10/11 x64:
1. Ejecucion sin privilegios de Administrador (aceptando y rechazando elevacion UAC) y confirmando que la sesion del usuario queda limpia al salir (`[0]`).
2. Opcion `[4]` (Auditoria nativa offline) y revision visual del HTML generado en el Escritorio.
3. Opcion `[1]` (descarga de Specify y verificacion de firma Microsoft en Sysinternals) y `[2]` (flujo completo con Specify + JSON).
4. Opcion `[3]` (lanzamiento de Process Explorer / Autoruns y manejo de cancelacion UAC).
5. Opcion `[5]` (cancelacion y confirmacion de limpieza, verificando que no elimine otras claves de Sysinternals preexistentes).
