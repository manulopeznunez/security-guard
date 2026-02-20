# Plan: Mejorar approval keys del Network Monitor

## Contexto

El sistema de aprobaciones de MacSecurityGuard tiene una debilidad en el Network Monitor: es el **unico scanner** que usa solo el nombre del proceso como clave de aprobacion. Si apruebas "curl", cualquier binario que se llame "curl" queda aprobado, sin importar su ruta.

| Scanner | Clave de aprobacion | Granularidad |
|---------|---------------------|--------------|
| Process Scanner | `path` completo del ejecutable | OK |
| Persistence | `executablePath` completo | OK |
| App Signature | `appPath` completo | OK |
| Chrome Extensions | `extensionId` unico | OK |
| KnockKnock | `path` completo | OK |
| **Network Monitor** | **solo `processName`** (ej: "curl") | **MAL** |

### Causa raiz

El path completo ya se resuelve en `BackgroundMonitor.swift:237-241` via `ps -p PID -o comm=`, pero se descarta inmediatamente — solo se guarda `lastPathComponent`. El path nunca llega a la DB ni a los modelos.

### Problema secundario: verificacion de firma

`verifyAppSignatures()` busca procesos por nombre con `pgrep -x`. Si el proceso no esta corriendo, intenta `/Applications/<name>.app`. Herramientas como curl, python, node no se encuentran asi — por eso curl aparecio como "NONE" en firma.

---

## Cambios propuestos

### 1. Capturar el path completo en BackgroundMonitor
**Archivo:** `Sources/BackgroundMonitor.swift` (lineas 234-242)

Agregar `pidPathCache: [Int: String]` junto a `pidNameCache`. El path ya se obtiene — solo hay que guardarlo antes de reducirlo a `lastPathComponent`.

Pasar `processPath` al construir `ConnectionSnapshot` (linea 302).

### 2. Agregar `processPath` a ConnectionSnapshot
**Archivo:** `Sources/DatabaseManager.swift` (linea 468)

Agregar `let processPath: String` al struct. Actualizar la unica otra construccion en tests.

### 3. Migracion de DB: columna `process_path`
**Archivo:** `Sources/DatabaseManager.swift` (despues de linea 81)

Agregar migracion (mismo patron existente de ALTER TABLE ADD COLUMN que falla silenciosamente si ya existe):
```sql
ALTER TABLE connections ADD COLUMN process_path TEXT DEFAULT '';
```

Tambien agregar `process_path` al `CREATE TABLE` original (linea 38-51) para instalaciones nuevas.

### 4. Almacenar path en INSERT
**Archivo:** `Sources/DatabaseManager.swift` (linea 112)

Agregar `process_path` al final de la lista de columnas del INSERT y bind en posicion 17. Se pone al final para no re-numerar los 16 bindings existentes.

### 5. Agregar `processPath` a AppSummary y query
**Archivo:** `Sources/DatabaseManager.swift` (lineas 503, 206)

- Agregar `var processPath: String = ""` al struct `AppSummary`
- Agregar `MAX(process_path) as process_path` al SELECT de `topApps()` (mismo patron que `MAX(parent_name)`, etc.)
- Parsear la nueva columna en el loop de resultados

Nota: se mantiene `GROUP BY process_name` — no se cambia a `GROUP BY process_path` porque filas antiguas tendrian path vacio y crearian un grupo separado.

### 6. Actualizar `approvalKey()` para usar path
**Archivo:** `Sources/Views/NetworkHistoryView.swift` (lineas 571-576)

```swift
private func approvalKey(for app: AppSummary) -> String {
    let identifier = app.processPath.isEmpty ? app.processName : app.processPath
    if app.injectionRisk.isEmpty {
        return identifier
    }
    return "\(identifier)|\(app.injectionRisk)"
}
```

### 7. Compatibilidad hacia atras en `isApproved()`
**Archivo:** `Sources/Views/NetworkHistoryView.swift` (lineas 578-581)

Verificar la clave nueva (path-based) primero, y si no existe, verificar la clave legacy (name-based). Asi las aprobaciones existentes de los usuarios siguen funcionando.

En revoke: revocar ambas claves (nueva y legacy) para limpieza completa.

### 8. Actualizar flagged IDs en ViewModel y BackgroundMonitor
**Archivos:**
- `Sources/ViewModels/NetworkHistoryViewModel.swift` (lineas 35-40)
- `Sources/BackgroundMonitor.swift` (lineas 63-84)

Usar path en vez de nombre al construir los IDs de items flaggeados.

### 9. Compatibilidad en `pendingCount()` para `.networkMonitor`
**Archivo:** `Sources/ApprovalManager.swift` (linea 58)

Agregar logica especifica para `.networkMonitor` que tambien verifique claves legacy (extraer `lastPathComponent` del path y chequear).

### 10. Mejorar verificacion de firma con path almacenado
**Archivo:** `Sources/ViewModels/NetworkHistoryViewModel.swift` (lineas 43-79)

Agregar Strategy 1 antes de las existentes: si `processPath` no esta vacio y el archivo existe, verificar directamente con `codesign -v <path>`. Esto arregla el caso de curl/python/node que no se encontraban por nombre.

### 11. Mostrar path en la UI
**Archivo:** `Sources/Views/NetworkHistoryView.swift`

En el popover de detalle de app, mostrar `app.processPath` como texto monoespaciado para que el usuario sepa exactamente que binario esta aprobando.

### 12. Actualizar test
**Archivo:** `Tests/DatabaseManagerTests.swift`

Agregar `processPath` al `ConnectionSnapshot` del test de SQL injection.

---

## Archivos a modificar (resumen)

1. `Sources/DatabaseManager.swift` — schema, INSERT, SELECT, structs ConnectionSnapshot y AppSummary
2. `Sources/BackgroundMonitor.swift` — captura de path, construccion de snapshot, cache de flagged IDs
3. `Sources/Views/NetworkHistoryView.swift` — approvalKey(), isApproved(), revoke, UI
4. `Sources/ViewModels/NetworkHistoryViewModel.swift` — verifyAppSignatures(), refresh()
5. `Sources/ApprovalManager.swift` — pendingCount() para networkMonitor
6. `Tests/DatabaseManagerTests.swift` — actualizar construccion de ConnectionSnapshot

## Verificacion

1. Build sin errores
2. Correr tests existentes (`Tests/DatabaseManagerTests.swift`)
3. Verificar que la migracion de DB funciona (abrir app con DB existente)
4. En Network History > By App: verificar que procesos flaggeados muestran el path
5. Aprobar un proceso y verificar que la clave en UserDefaults usa el path (ej: `network:/usr/bin/curl`)
6. Verificar que aprobaciones legacy (por nombre) siguen funcionando
