/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

interface Record {
  id: string
  data: unknown
}

const _name = 'crescent'
const _version = 1
// eslint-disable-next-line @typescript-eslint/init-declarations
let _db: IDBDatabase | undefined

async function openDatabase (dbName: string, store: string, version: number): Promise<IDBDatabase> {
  return await new Promise((resolve, reject) => {
    const request: IDBOpenDBRequest = indexedDB.open(dbName, version)

    request.onupgradeneeded = (_event: IDBVersionChangeEvent) => {
      const db: IDBDatabase = request.result
      if (!db.objectStoreNames.contains(store)) {
        db.createObjectStore(store, { keyPath: 'id' })
      }
    }

    request.onsuccess = (_event: Event) => {
      _db = request.result
      resolve(_db)
    }

    request.onerror = (_event: Event) => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      reject(domExceptionToError(request.error!))
    }
  })
}

export async function addData<T> (store: string, key: string, data: T): Promise<boolean> {
  if (_db == null) {
    await openDatabase(_name, store, _version)
  }

  return await new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const transaction: IDBTransaction = _db!.transaction([store], 'readwrite')
    const objectStore: IDBObjectStore = transaction.objectStore(store)
    const request: IDBRequest<IDBValidKey> = objectStore.put({ id: key, data })

    request.onsuccess = () => {
      resolve(true)
    }

    request.onerror = (_err) => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      reject(domExceptionToError(request.error!))
    }
  })
}

export async function getData<T> (store: string, key?: string): Promise<T | undefined> {
  if (_db == null) {
    await openDatabase(_name, store, _version)
  }

  return await new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const transaction: IDBTransaction = _db!.transaction([store], 'readonly')
    const objectStore: IDBObjectStore = transaction.objectStore(store)

    if (key != null) {
      const request: IDBRequest<T> = objectStore.get(key)
      request.onsuccess = (_event: Event) => {
        const record = request.result as Record | undefined
        resolve(record?.data as T)
      }
      request.onerror = (_event: Event) => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        reject(domExceptionToError(request.error!))
      }
    }
    else {
      const allItems: T[] = []
      const request = objectStore.openCursor()

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result as IDBCursorWithValue | null
        if (cursor != null) {
          allItems.push(cursor.value as T) // Accumulate each item
          cursor.continue()
        }
        else {
          resolve(allItems as T) // Resolve with all items once complete
        }
      }

      request.onerror = (_event: Event) => {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        reject(domExceptionToError(request.error!))
      }
    }
  })
}

export async function removeData (store: string, key: string): Promise<boolean> {
  if (_db == null) {
    await openDatabase(_name, store, _version)
  }

  return await new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const transaction: IDBTransaction = _db!.transaction([store], 'readwrite')
    const objectStore: IDBObjectStore = transaction.objectStore(store)
    const request: IDBRequest = objectStore.delete(key)

    request.onsuccess = () => {
      resolve(true)
    }

    request.onerror = (_err) => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      reject(domExceptionToError(request.error!))
    }
  })
}

function domExceptionToError (domException: DOMException): Error {
  const error = new Error(domException.message)
  error.name = domException.name
  return error
}
