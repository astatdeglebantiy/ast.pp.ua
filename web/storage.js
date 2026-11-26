
"use strict";

const ASTMailStorage = (() => {
  const VERSION = 1;
  const PREFIX = "astmail-cache-v1-";

  function open(accountId) {
    if (
      typeof accountId !== "string" ||
      !/^[a-zA-Z0-9_-]{1,128}$/.test(accountId)
    ) {
      return Promise.reject(
        new TypeError("Invalid account ID")
      );
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(
        PREFIX + accountId,
        VERSION
      );

      request.onupgradeneeded = () => {
        const db = request.result;

        if (!db.objectStoreNames.contains("messages")) {
          db.createObjectStore("messages", {
            keyPath: "id",
          });
        }

        if (!db.objectStoreNames.contains("sync_state")) {
          db.createObjectStore("sync_state", {
            keyPath: "key",
          });
        }

        if (!db.objectStoreNames.contains("outbox")) {
          db.createObjectStore("outbox", {
            keyPath: "id",
          });
        }
      };

      request.onsuccess = () => {
        const db = request.result;

        db.onversionchange = () => db.close();
        resolve(db);
      };

      request.onerror = () => reject(request.error);
      request.onblocked = () => {
        console.warn("ASTMail IndexedDB upgrade blocked");
      };
    });
  }

  function run(db, storeName, mode, operation) {
    return new Promise((resolve, reject) => {
      let result;
      let tx;

      try {
        tx = db.transaction(storeName, mode);
        const store = tx.objectStore(storeName);
        operation(store, value => {
          result = value;
        });
      } catch (error) {
        reject(error);
        return;
      }

      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(
        tx.error || new Error("Transaction aborted")
      );
    });
  }

  function saveMessage(db, message) {
    if (
      !message ||
      typeof message.id !== "string" ||
      !message.id
    ) {
      return Promise.reject(
        new TypeError("Message must have an ID")
      );
    }

    return run(db, "messages", "readwrite", store => {
      store.put(message);
    });
  }

  function getMessage(db, id) {
    return run(db, "messages", "readonly", (store, set) => {
      const req = store.get(id);
      req.onsuccess = () => set(req.result ?? null);
    });
  }

  function getMessages(db) {
    return run(db, "messages", "readonly", (store, set) => {
      const req = store.getAll();
      req.onsuccess = () => set(req.result);
    });
  }

  function deleteMessage(db, id) {
    return run(db, "messages", "readwrite", store => {
      store.delete(id);
    });
  }

  function setSyncState(db, key, value) {
    return run(db, "sync_state", "readwrite", store => {
      store.put({ key, value });
    });
  }

  function getSyncState(db, key) {
    return run(db, "sync_state", "readonly", (store, set) => {
      const req = store.get(key);
      req.onsuccess = () => set(req.result?.value ?? null);
    });
  }

  function enqueue(db, operation) {
    if (!operation || typeof operation.id !== "string" ||
        !operation.id) {
      return Promise.reject(
        new TypeError("Operation must have an ID")
      );
    }

    return run(db, "outbox", "readwrite", store => {
      store.put(operation);
    });
  }

  function getOutbox(db) {
    return run(db, "outbox", "readonly", (store, set) => {
      const req = store.getAll();
      req.onsuccess = () => set(req.result);
    });
  }

  function removeOutbox(db, id) {
    return run(db, "outbox", "readwrite", store => {
      store.delete(id);
    });
  }

  function clearAccount(accountId) {
    if (
      typeof accountId !== "string" ||
      !/^[a-zA-Z0-9_-]{1,128}$/.test(accountId)
    ) {
      return Promise.reject(new TypeError("Invalid account ID"));
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(
        PREFIX + accountId
      );

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(
        new Error("Close database connections before deleting")
      );
    });
  }

function replaceSnapshot(db, inbox, sent) {
  if (!Array.isArray(inbox) || !Array.isArray(sent)) {
    return Promise.reject(
      new TypeError("Invalid mailbox snapshot")
    );
  }

  const records = [
    ...inbox.map(message => ({ ...message, folder: "inbox" })),
    ...sent.map(message => ({ ...message, folder: "sent" })),
  ];

  const ids = new Set();

  for (const message of records) {
    if (typeof message.id !== "string" || !message.id) {
      return Promise.reject(
        new TypeError("Snapshot message has invalid ID")
      );
    }

    const key = `${message.folder}:${message.id}`;

    if (ids.has(key)) {
      return Promise.reject(
        new Error("Duplicate message in mailbox snapshot")
      );
    }

    ids.add(key);
  }

  return new Promise((resolve, reject) => {
    let tx;

    try {
      tx = db.transaction("messages", "readwrite");
      const store = tx.objectStore("messages");

      store.clear();

      for (const message of records) {
        store.put({
          ...message,
          id: `${message.folder}:${message.id}`,
          messageId: message.id,
        });
      }

      tx.oncomplete = () => resolve(records.length);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(
        tx.error || new Error("Snapshot transaction aborted")
      );
    } catch (error) {
      if (tx) {
        try { tx.abort(); } catch {}
      }
      reject(error);
    }
  });
}

  return Object.freeze({
      open,
      saveMessage,
      getMessage,
      getMessages,
      deleteMessage,
      replaceSnapshot,
      setSyncState,
      getSyncState,
      enqueue,
      getOutbox,
      removeOutbox,
      clearAccount,
  });
})();

window.ASTMailStorage = ASTMailStorage;
