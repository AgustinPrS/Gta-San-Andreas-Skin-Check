# SkinCheck

Analizador estático para revisar skins de GTA San Andreas, archivos .exe y otros archivos en Windows. SkinCheck busca indicadores sospechosos sin ejecutar ni abrir la muestra en un juego o visor.

> **Importante:** es una herramienta heurística de revisión. Una alerta no confirma que un archivo sea malicioso y “Sin señales claras” no significa que sea seguro.

## Inicio rápido

1. Descarga SkinCheck.exe.
2. Abre el programa.
3. Arrastra uno o varios archivos a la ventana, pulsa **Agregar archivos** o usa **Seleccionar carpeta** para importar solo archivos `.dff` y `.txd` de la carpeta y sus subcarpetas.
4. Deja marcados los filtros que quieras usar y pulsa **Analizar lista**.
5. Selecciona un archivo para ver los indicadores encontrados y su hash SHA-256.

La interfaz está disponible en español, inglés y portugués de Brasil.

## Filtros

- **RCE y ejecución de comandos:** busca llamadas y cadenas asociadas con la ejecución de comandos, como ShellExecute, CreateProcess, WinExec, system, execve, PowerShell y shells.
- **Memoria e inyección de procesos:** busca indicadores como VirtualAlloc, VirtualProtect, WriteProcessMemory y CreateRemoteThread.
- **Red, IPs y URLs:** busca direcciones web, dominios, IPv4, IPv6 y cadenas de APIs de red. El programa no se conecta a las direcciones encontradas.
- **Scripts y consola:** busca referencias a intérpretes y herramientas como cmd.exe, PowerShell, rundll32, regsvr32 y mshta.
- **Persistencia:** busca referencias a claves Run/RunOnce, servicios, tareas programadas y ubicaciones de inicio automático.
- **Credenciales:** busca cadenas relacionadas con credenciales y acceso a datos sensibles.
- **PE/ELF camuflado:** identifica ejecutables PE o ELF incrustados y posibles discrepancias entre el contenido y la extensión.
- **Firma Authenticode:** comprueba si un archivo PE contiene un certificado. No valida la cadena de confianza ni demuestra que el archivo sea seguro.
- **Estructura DFF/TXD:** comprueba el identificador inicial y que el tamaño declarado coincida con el tamaño del archivo.
- **Ofuscación y entropía:** busca algunos marcadores de empaquetado u ofuscación y calcula entropía para archivos que no sean DFF/TXD.
- **SHA-256:** calcula una huella local para identificar el archivo.

Los filtros están activados por defecto y se pueden desmarcar individualmente.

## Interpretar el resultado

La puntuación es una combinación heurística de indicadores; **no es una probabilidad**:

| Resultado | Puntuación | Qué significa |
|---|---:|---|
| Sin señales claras | 0–19 | Los filtros no encontraron una combinación suficientemente sospechosa. No certifica que el archivo sea seguro. |
| Revisar | 20–49 | Se encontraron indicadores que conviene investigar. |
| Alerta alta | 50–100 | Se combinaron varios indicadores de riesgo. Mantén el archivo aislado. |

Una URL, una IP, una API de red, una firma ausente o una entropía alta pueden aparecer en archivos legítimos. SkinCheck da más peso a combinaciones, por ejemplo código de ejecución junto con direcciones de red dentro de una skin.

**RCE (ejecución remota de código)** depende de un defecto en el programa que carga un archivo y de que se active la ruta vulnerable. Encontrar una llamada de ejecución o una cadena sospechosa no demuestra por sí solo que el archivo consiga ejecutar código.

## Privacidad

El análisis se realiza localmente. SkinCheck:

- No ejecuta las muestras ni las carga en GTA, un modloader o un visor.
- No sube archivos ni consulta las IPs o URLs que encuentra.
- Solo abre el navegador si el usuario pulsa un enlace del programa.
- Al pulsar **Buscar hash en VirusTotal**, abre la consulta del SHA-256. Envía el hash en la URL, no el archivo.

Los enlaces del programa también están disponibles al final de esta página.

## Límites

- No utiliza una base de firmas antivirus ni un sandbox dinámico.
- No detecta todas las variantes, cargas cifradas, vulnerabilidades ni formas de ofuscación.
- No descomprime ZIP, RAR ni 7Z.
- El análisis está limitado a archivos de hasta 100 MB.
- Una firma digital no garantiza que un programa sea benigno; la ausencia de firma tampoco demuestra que sea malicioso.

Si un archivo da alerta, no lo ejecutes ni lo cargues en un juego o visor. Analízalo también con Microsoft Defender actualizado.

## Enlaces

- Sitio web: [otherclap.net](https://www.otherclap.net)
- GitHub — skins seguras: [Skins de GTA San Andreas 0.3DL](https://github.com/AgustinPrS/Skins-de-GTA-San-Andreas-0.3DL)
- Visor de skins: [skins.otherclap.net](https://skins.otherclap.net)
- Discord: [servidor OtherClap](https://discord.gg/FSwJ63ugXy)
- Comunidad: [SAMP Hispano](https://discord.gg/uJje6ybhZs)

## Licencia

Copyright © 2026 OtherClap. No se permite vender ni comercializar SkinCheck sin autorización escrita de OtherClap. Consulta [LICENSE.txt](LICENSE.txt) para las condiciones completas.
