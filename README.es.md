# react2shell-scanx

Una herramienta de línea de comandos para detectar CVE-2025-55182 y CVE-2025-66478 en aplicaciones Next.js que utilizan React Server Components.

Para detalles técnicos sobre la vulnerabilidad y la metodología de detección, consulta nuestro artículo: https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478

## 🏗️ Arquitectura

Este proyecto ha sido refactorizado con una **arquitectura modular** siguiendo principios SOLID y patrones de diseño. Consulta [ARCHITECTURE.md](ARCHITECTURE.md) para información detallada.

### Estructura del Proyecto

```
react2shell-scanx/
├── src/
│   ├── models/          # Modelos de datos (ScanResult, ScanConfig)
│   ├── core/            # Lógica principal de escaneo
│   ├── network/         # Cliente HTTP y redirecciones
│   ├── utils/           # Utilidades (colores, validadores, I/O)
│   └── cli/             # Interfaz de línea de comandos
├── tests/               # Pruebas unitarias
├── scanner.py           # Punto de entrada principal
└── README.md
```

## Cómo Funciona

Por defecto, el escáner envía una solicitud POST multipart especialmente diseñada que contiene un payload de prueba de concepto RCE que ejecuta una operación matemática determinística (`41*271 = 11111`). Los hosts vulnerables devuelven el resultado en el encabezado de respuesta `X-Action-Redirect` como `/login?a=11111`.

El escáner prueba la ruta raíz (`/`) por defecto. Usa `--path` o `--path-file` para probar rutas personalizadas. Si no es vulnerable, sigue las redirecciones del mismo host (ej: `/` a `/en/`) y prueba el destino de la redirección. No se siguen las redirecciones de origen cruzado.

### Modo de Verificación Segura

La bandera `--safe-check` utiliza un método de detección alternativo que se basa en indicadores de canal lateral (código de estado 500 con resumen de error específico) sin ejecutar código en el objetivo. Usa este modo cuando no se desea la ejecución de RCE.

### Bypass de WAF

La bandera `--waf-bypass` antepone datos basura aleatorios al cuerpo de la solicitud multipart. Esto puede ayudar a evadir la inspección de contenido del WAF que solo analiza la primera porción de los cuerpos de solicitud. El tamaño predeterminado es 128KB, configurable mediante `--waf-bypass-size`. Cuando el bypass de WAF está habilitado, el tiempo de espera se aumenta automáticamente a 20 segundos (a menos que se establezca explícitamente).

### Bypass de WAF de Vercel

La bandera `--vercel-waf-bypass` utiliza una variante de payload alternativa diseñada específicamente para eludir las protecciones del WAF de Vercel. Esto usa una estructura multipart diferente con un campo de formulario adicional.

### Modo Windows

La bandera `--windows` cambia el payload de shell Unix (`echo $((41*271))`) a PowerShell (`powershell -c "41*271"`) para objetivos que se ejecutan en Windows.

## Requisitos

- Python 3.9+
- requests
- tqdm

## Instalación

```
pip install -r requirements.txt
```

## Uso

Escanear un solo host:

```
python3 scanner.py -u https://example.com
```

Escanear una lista de hosts:

```
python3 scanner.py -l hosts.txt
```

Escanear con múltiples hilos y guardar resultados:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Escanear con encabezados personalizados:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Usar detección segura por canal lateral:

```
python3 scanner.py -u https://example.com --safe-check
```

Escanear objetivos Windows:

```
python3 scanner.py -u https://example.com --windows
```

Escanear con bypass de WAF:

```
python3 scanner.py -u https://example.com --waf-bypass
```

Escanear rutas personalizadas:

```
python3 scanner.py -u https://example.com --path /_next
python3 scanner.py -u https://example.com --path /_next --path /api
python3 scanner.py -u https://example.com --path-file paths.txt
```

## Opciones

```
-u, --url         URL única a verificar
-l, --list        Archivo que contiene hosts (uno por línea)
-t, --threads     Número de hilos concurrentes (predeterminado: 10)
--timeout         Tiempo de espera de solicitud en segundos (predeterminado: 10)
-o, --output      Archivo de salida para resultados (JSON)
--all-results     Guardar todos los resultados, no solo hosts vulnerables
-k, --insecure    Deshabilitar verificación de certificado SSL
-H, --header      Encabezado personalizado (puede usarse varias veces)
-v, --verbose     Mostrar detalles de respuesta para hosts vulnerables
-q, --quiet       Solo mostrar hosts vulnerables
--no-color        Deshabilitar salida con colores
--safe-check      Usar detección segura por canal lateral en lugar de RCE PoC
--windows         Usar payload de PowerShell para Windows en lugar de shell Unix
--waf-bypass      Agregar datos basura para eludir la inspección de contenido del WAF
--waf-bypass-size Tamaño de datos basura en KB (predeterminado: 128)
--path            Ruta personalizada a probar (puede usarse varias veces)
--path-file       Archivo que contiene rutas a probar (una por línea)
```

## Créditos

El PoC de RCE fue originalmente divulgado por [@maple3142](https://x.com/maple3142) -- estamos increíblemente agradecidos por su trabajo al publicar un PoC funcional.

Esta herramienta se construyó originalmente como una forma segura de detectar el RCE. Esta funcionalidad todavía está disponible a través de `--safe-check`, el modo de "detección segura".

- Equipo de Investigación de Seguridad de Assetnote - [Adam Kues, Tomais Williamson, Dylan Pindur, Patrik Grobshäuser, Shubham Shah](https://x.com/assetnote)
- [xEHLE_](https://x.com/xEHLE_) - Reflexión de salida RCE en encabezado de respuesta
- [Nagli](https://x.com/galnagli)

## Resultados

Los resultados se imprimen en la terminal. Al usar `-o`, los hosts vulnerables se guardan en un archivo JSON que contiene la solicitud y respuesta HTTP completas para verificación.
