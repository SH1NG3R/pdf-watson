# PDF Watson - Inspector de Seguridad para PDFs
In English: 
[![en](https://img.shields.io/badge/lang-en-red.svg)](README.MD)

PDF Watson es una herramienta minimalista desarrollada en Python diseñada para escanear archivos PDF en busca de código malicioso. La herramienta extrae metadatos del archivo y busca patrones comunes asociados con códigos maliciosos, JavaScript potencialmente dañino y archivos incrustados peligrosos.

# - IMPORTANTE -
Esta es una prueba de concepto y debe ser usada con precaucion, bajo su propio riesgo y siempre en entornos controlados. No posee ninguna garantia ni responsabilidad

## Índice

1. [PDF Watson - Inspector de Seguridad para PDFs](#pdf-watson---inspector-de-seguridad-para-pdfs)
2. [Nota Importante](#nota-importante)
3. [Características](#características)
4. [Requisitos](#requisitos)
5. [Instalación](#instalación)
6. [Uso Básico](#uso-básico)
   - [Escaneo de PDF](#escaneo-de-pdf)
   - [Escaneo de Directorio](#escaneo-de-directorio)
7. [Resultados](#resultados)
8. [Problemas Comunes](#problemas-comunes)
   - [Falsos Positivos](#falsos-positivos)
   - [Archivo PDF No Abierto](#archivo-pdf-no-abierto)
   - [Errores en la Consola](#errores-en-la-consola)
9. [To-Do](#to-do-list)
10. [Licencia](#licencia)


## Características

- Extracción de Metadatos: Obtiene información sobre el autor, título, fecha de creación, etc.
- Búsqueda de Código Malicioso: Detecta patrones comunes en JavaScript y otros elementos que podrían ser indicativos de códigos maliciosos.
- Detección de Archivos Incrustados Peligrosos: Identifica archivos incrustados dentro del PDF con extensiones potencialmente peligrosas.

Para mas detalles, revisar [documentacion.es.md](documentacion.es.md)

## Requisitos

- Python 3.9 o superior
- Librerías:
    - PyPDF2
    - magic
    - Tkinter

Puedes instalar las librerías necesarias con el siguiente comando:

```bash
pip install -r requirements.txt
```

## Instalación

Clona este repositorio.

```bash
git clone https://github.com/tu_usuario/PDF-Watson.git
cd PDF-Watson
python -m venv watson_env
watson_env\Scripts\activate  # En Windows
# Para macOS/Linux usa: source watson_env/bin/activate
pip install -r requirements.txt
```
## Uso Básico

1. **Ejecutar el Script**:
    ```bash
    python PDF-Watson.py
    ```
   
2. **Interfaz Gráfica**:
   Al ejecutar el script, se abrirá una ventana donde podrás seleccionar un archivo PDF o una carpeta para y realizar la inspeccion.  

    Para seleccionar un archivo haga clic en el "Scan PDF", si desea inspeccionar un directorio con PDFs para una inspeccion en lotes, seleccione "Scan Directory"  

![alt text](/images/main.jpg "Pantalla principal")

   Debajo de los botones se encuentran 4 pestañas con los resultados.
   En "Summary"" muestra un resumen de la inspeccion; En "Metadata" muestra los metadatos, ; En "Security Analysis" condensa la informacion relevante a codigo JavaScript encontrado y en Log el historial de uso de la aplicacion que se almacena en "pdf_watson.log"

Tras realizar una inspeccion es posible exportar los resultados en .txt
   
## Resultados

- **Metadatos del Archivo**: Se mostrarán los metadatos extraídos del archivo PDF como autor, título, fecha de creación, etc.
- **Alertas de Código Malicioso**: Si se detectan patrones maliciosos en el contenido JavaScript, se mostrarán alertas correspondientes.
- **Archivos Incrustados Peligrosos**: Se identificarán archivos incrustados dentro del PDF que podrían ser peligrosos y se generarán alertas si es necesario.
- **Log**: Se documenta las inspecciones realizadas, operaciones y errores de ejecucion.

## Problemas Conocidos

### Falsos Positivos
Si el documento en cuestion es relacionado a la programacion, puede identificar codigo en texto plano como malicioso.

### Archivo PDF No Abierto
Si el archivo no se abre correctamente, asegúrate de:
- Verificar la ruta del archivo.
- Tener permisos para leer el archivo.

### Errores en la Consola
Si encuentras errores al ejecutar el script, consulta el archivo `pdf_watson.log` para obtener más información detallada sobre el error.

## To-Do List

- [ ] Crear una GUI mejorada
- [ ] Dar la capacidad de ignorar el texto plano para no tener falsos positivos
- [ ] Visualizador del Codigo JS en contexto
- [ ] Incorporar lo aprendido en https://blog.didierstevens.com/ 

## Licencia

Este proyecto está licenciado bajo la GNU General Public License.

