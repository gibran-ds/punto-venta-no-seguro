import { useEffect, useState } from 'react'
import cliente from '../api/client'

export default function Diagnostico() {
  const [diagnostico, setDiagnostico] = useState(null)
  const [configuracion, setConfiguracion] = useState([])
  const [pasarela, setPasarela] = useState(null)
  const [salud, setSalud] = useState(null)

  useEffect(() => {
    cliente.get('/diagnostico').then((r) => setDiagnostico(r.data)).catch(() => {})
    cliente.get('/configuracion').then((r) => setConfiguracion(r.data)).catch(() => {})
    cliente.get('/pagos/configuracion').then((r) => setPasarela(r.data)).catch(() => {})
    cliente.get('/salud').then((r) => setSalud(r.data)).catch(() => {})
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h1>Diagnostico del sistema</h1>

      <section>
        <h2>Estado del servicio</h2>
        {salud && <pre>{JSON.stringify(salud, null, 2)}</pre>}
      </section>

      <section>
        <h2>Variables de entorno y conexion</h2>
        {/* VULNERABILIDAD: el servidor expone el entorno, la conexion y la password de MySQL */}
        <pre style={{ background: '#fee2e2', padding: 12 }}>{JSON.stringify(diagnostico, null, 2)}</pre>
      </section>

      <section>
        <h2>Configuracion almacenada</h2>
        {/* VULNERABILIDAD: incluye api keys, secretos JWT y contrasenas de correo */}
        <pre style={{ background: '#fef3c7', padding: 12 }}>{JSON.stringify(configuracion, null, 2)}</pre>
      </section>

      <section>
        <h2>Pasarela de pago</h2>
        <pre style={{ background: '#fee2e2', padding: 12 }}>{JSON.stringify(pasarela, null, 2)}</pre>
      </section>

      <section>
        <h2>Endpoints de Spring Boot Actuator</h2>
        {/* VULNERABILIDAD: actuator expone todos los endpoints sin autenticacion */}
        <p>
          <a href="/actuator" target="_blank" rel="noreferrer">
            /actuator
          </a>
          {' | '}
          <a href="/actuator/env" target="_blank" rel="noreferrer">
            /actuator/env
          </a>
          {' | '}
          <a href="/actuator/configprops" target="_blank" rel="noreferrer">
            /actuator/configprops
          </a>
          {' | '}
          <a href="/actuator/heapdump" target="_blank" rel="noreferrer">
            /actuator/heapdump
          </a>
        </p>
      </section>
    </div>
  )
}