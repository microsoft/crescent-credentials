/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

interface Record {
    id: string
    data: unknown
}

const _name = 'crecent'
const _version = 1
// eslint-disable-next-line @typescript-eslint/init-declarations
let _db: IDBDatabase | undefined

async function openDatabase(dbName: string, store: string, version: number): Promise<IDBDatabase> {
    return await new Promise((resolve, reject) => {
        const request: IDBOpenDBRequest = indexedDB.open(dbName, version)

        request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
            const db: IDBDatabase = request.result
            if (!db.objectStoreNames.contains(store)) {
                db.createObjectStore(store, { keyPath: 'id' })
            }
        }

        request.onsuccess = (event: Event) => {
            _db = request.result
            resolve(_db)
        }

        request.onerror = (event: Event) => {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            reject(domExceptionToError(request.error!))
        }
    })
}

export async function addData<T>(store: string, key: string, data: T): Promise<string> {
    if (_db == null) {
        await openDatabase(_name, store, _version)
    }

    return await new Promise((resolve, reject) => {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const transaction: IDBTransaction = _db!.transaction([store], 'readwrite')
        const objectStore: IDBObjectStore = transaction.objectStore(store)
        const request: IDBRequest<IDBValidKey> = objectStore.put({ id: key, data })

        request.onsuccess = () => {
            resolve('Data added successfully')
        }

        request.onerror = (event: Event) => {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            reject(domExceptionToError(request.error!))
        }
    })
}

export async function getData<T>(store: string, key: string): Promise<T | undefined> {
    if (_db == null) {
        await openDatabase(_name, store, _version)
    }

    return await new Promise((resolve, reject) => {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const transaction: IDBTransaction = _db!.transaction([store], 'readonly')
        const objectStore: IDBObjectStore = transaction.objectStore(store)
        const request: IDBRequest<T> = objectStore.get(key)

        request.onsuccess = (event: Event) => {
            const record: Record = request.result as Record
            resolve(record.data as T)
        }

        request.onerror = (event: Event) => {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            reject(domExceptionToError(request.error!))
        }
    })
}

function domExceptionToError(domException: DOMException): Error {
    const error = new Error(domException.message)
    error.name = domException.name
    return error
}