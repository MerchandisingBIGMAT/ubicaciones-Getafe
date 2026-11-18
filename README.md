# BigMat Gestión

App web (PWA) para registrar la ubicación de productos en el almacén escaneando el EAN con la cámara del móvil.

- Eliges **pasillo**, **rack** y **nivel** y escaneas: busca el EAN en la BBDD y registra la línea (la posición se asigna sola).
- Funciona sin conexión una vez cargada y se instala como app (Añadir a pantalla de inicio).
- **Exportar XLSX** con ubicación, artículo, descripción y EAN. **Reiniciar** borra todos los registros.

Los datos van cifrados en data/*.enc (AES-GCM); sin el código de acceso no son legibles.
