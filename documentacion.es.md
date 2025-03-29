# Documentación de PDF Watson

In English: 
[![en](https://img.shields.io/badge/lang-en-red.svg)](documentation.en.md)

PDF Watson es una herramienta desarrollada en Python que permite revisar archivos PDF en busca de posibles amenazas.

# - IMPORTANTE -
Esta es una prueba de concepto y debe ser usada con precaucion, bajo su propio riesgo y siempre en entornos controlados. No posee ninguna garantia ni responsabilidad

## Índice

1. [Documentación de PDF Watson](#documentación-de-pdf-watson)
2. [Estructura del Código](#estructura-del-código)
   - [Clase Metadata](#clase-metadata)
   - [Clase PDFWatson](#clase-pdfwatson)
3. [Funciones Auxiliares](#funciones-auxiliares)
4. [Patrones Maliciosos](#patrones-maliciosos)
5. [Flujo Principal](#flujo-principal)
6. [Registro de Errores](#registro-de-errores)


## Estructura del Código

El código está organizado en dos clases principales: `Metadata` y `PDFWatson`. Además, se utilizan varias funciones auxiliares para realizar las tareas específicas.

### Clase Metadata
Esta clase se encarga de almacenar la metadata del PDF. Los atributos incluyen información sobre el autor, título, fecha de creación, etc.

### Clase PDFWatson
Esta es la clase principal que maneja los procesos de análisis de seguridad y extracción de metadata. La clase contiene métodos para:
- **scan_pdf_javascript**: Busca JavaScript potencialmente malicioso en el archivo.
- **scan_embedded_files**: Detecta archivos incrustados dentro del PDF que podrían ser peligrosos.

## Funciones Auxiliares
Además de las clases, existen funciones auxiliares como `extract_metadata` que se encargan de extraer información del archivo PDF.

### Patrones Maliciosos
PDF Watson utiliza una serie de patrones regulares para identificar posibles amenazas en el contenido JavaScript y otros elementos del PDF. Estos patrones están listados en la variable `malicious_patterns`.

## Flujo Principal

1. **Extracción de Metadatos**: Se extrae información sobre el archivo PDF, como autor, título, etc.
2. **Búsqueda de Código Malicioso**: Se escanean patrones conocidos de código malicioso en el contenido JavaScript del archivo.
3. **Detección de Archivos Incrustados Peligrosos**: Se identifican archivos incrustados dentro del PDF que podrían ser peligrosos.


## Registro de Errores
Todos los errores y excepciones se registran en un archivo llamado `pdf_watson.log` para su posterior análisis o documentacion.