# Avis de Licences Tiers et Conformité Open Source (`THIRD_PARTY_NOTICES.md`)

Ce document recense les bibliothèques open source tierces utilisées par **FASO-SÉCUR**, leurs licences respectives vérifiées dans les manifestes installés (`package.json` / `requirements.txt`), ainsi que les obligations de distribution associées.

La distribution de **FASO-SÉCUR** et le paquet frontend sont déclarés sous **GPL-3.0-only** (`LICENSE`, `frontend/package.json`). Le code original du projet est également offert sous **MIT** (`LICENSE-MIT`). Les notices ci-dessous concernent les dépendances tierces et ne remplacent pas leurs licences respectives.

---

## 1. Bibliothèque Cryptographique Signal et Dépendances Directes (Frontend)

| Paquet NPM | Version installée | Licence déclarée | Provenance / Dépôt |
| :--- | :--- | :--- | :--- |
| `@privacyresearch/libsignal-protocol-typescript` | `0.0.16` | **`GPL-3.0-only`** | `https://github.com/privacyresearchgroup/libsignal-protocol-typescript` |
| `@privacyresearch/libsignal-protocol-protobuf-ts` | `0.0.9` | **`GPL-3.0-only`** | Dépendance directe de `@privacyresearch/libsignal-protocol-typescript` |
| `@privacyresearch/curve25519-typescript` | `0.0.12` | **`GPL-3.0-only`** | Primitives X25519 / Ed25519 pour `@privacyresearch/libsignal-protocol-typescript` |
| `base64-js` | `1.5.1` | `MIT` | Dépendance de `@privacyresearch/libsignal-protocol-typescript` |
| `ts-proto` | `1.181.2` | `MIT` | Dépendance de `@privacyresearch/libsignal-protocol-protobuf-ts` |

### Périmètre des licences (GPL-3.0-only et permission MIT pour le code original)

1. **Licence de la distribution** : Le dépôt et le paquet frontend sont déclarés GPL-3.0-only. Le texte intégral applicable est dans `LICENSE` ; le code original dispose aussi d'une permission MIT distincte dans `LICENSE-MIT`.
2. **Dépendances** : `@privacyresearch/libsignal-protocol-typescript` et ses paquets GPL restent régis par leurs licences tierces respectives ; leur texte et leurs notices doivent être conservés lors d'une redistribution.
3. **Validation avant redistribution** : Cette documentation décrit les déclarations de licence du dépôt. Toute redistribution, exception ou changement de licence doit être validé par les titulaires des droits et, si nécessaire, par un conseiller juridique.

---

## 2. Autres Dépendances Frontend (`frontend/package.json`)

| Paquet NPM | Version verrouillée dans `package-lock.json` | Licence |
| :--- | :--- | :--- |
| `react` / `react-dom` | `18.3.1` | `MIT` |
| `lucide-react` | `0.454.0` | `ISC` |
| `vite` | `5.4.21` | `MIT` |
| `@vitejs/plugin-react` | `4.7.0` | `MIT` |
| `tailwindcss` / `postcss` / `autoprefixer` | `3.4.19` / `8.5.32` / `10.6.2` | `MIT` |

---

## 3. Dépendances Backend (`backend/requirements.txt`)

| Paquet Python | Version documentée (non verrouillée) | Licence |
| :--- | :--- | :--- |
| `fastapi` | `0.115.5` | `MIT` |
| `uvicorn[standard]` | `0.32.1` | `BSD-3-Clause` |
| `sqlalchemy` | `2.0.36` | `MIT` |
| `pydantic` | `2.10.2` | `MIT` |
| `PyJWT` | `2.10.0` | `MIT` |
| `bcrypt` | `4.2.1` | `Apache-2.0` |
| `cryptography` (PyCA) | `43.0.3` | `Apache-2.0 OR BSD-3-Clause` |
| `psycopg2-binary` | `2.9.10` | `LGPL-3.0-with-linking-exception` |
| `pytest` / `httpx` | `8.3.3` / `0.27.2` | `MIT` / `BSD-3-Clause` |

> Les versions backend ci-dessus sont indicatives : `backend/requirements.txt` utilise des bornes minimales (`>=`) et le dépôt ne contient pas de fichier de verrouillage Python. Une installation ultérieure peut donc résoudre des versions différentes.

---

## 4. Notices de Copyright Requises

```text
@privacyresearch/libsignal-protocol-typescript, @privacyresearch/libsignal-protocol-protobuf-ts,
@privacyresearch/curve25519-typescript
Copyright (C) 2015-2016 Open Whisper Systems
Copyright (C) 2020-2022 Privacy Research, LLC
Licensed under the GNU General Public License v3.0 only (GPL-3.0-only).
See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
```

