# tpaste 🦀

> A secure, full-stack Pastebin clone written in Rust.
> Features a web interface (SSR) and a CLI client for piping command output directly to the cloud.

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)

---

## 📸 Screenshots

| Login Page | Paste View | CLI Usage |
|:---:|:---:|:---:|
| ![Login UI](./screenshots/login.png) | ![Paste UI](./screenshots/paste.png) | ![CLI](./screenshots/cli.png) |

## 🚀 Key Features

* **Full-Stack Rust:** Backend (`Axum`), SSR with Templating (`Askama`), and CLI tool (`Reqwest`) all written in Rust.
* **End-to-End HTTPS:** TLS termination handled directly by the application using `rustls`.
* **Dual-Mode Authentication:**
    * **Web:** JWT stored in **HttpOnly, Secure cookies**.
    * **CLI:** Token-based authentication saved locally for seamless piping.
* **Security First:** Passwords hashed with **Argon2**; SQL injection protection via **SQLx**.

## ☁️ Infrastructure & Deployment

This project supports two environments:

1.  **Development (Local):**
    * Uses **Docker Compose** to spin up a PostgreSQL instance instantly.
    * Self-signed certificates for local HTTPS testing.

2.  **Production (AWS):**
    * **App:** Deployed on **AWS EC2** (systemd service).
    * **Database:** Managed **AWS RDS** (PostgreSQL).
    * **Networking:** Custom DNS Resolution using **DuckDNS** (`tpaste.duckdns.org`) and strict **HTTPS** enforced directly by the application (`rustls`).
    * *Note: The AWS environment is currently paused to optimize costs. The deployment process and infrastructure are fully implemented and can be brought online quickly.*
    
## 🛠️ Architecture

```mermaid
graph TD
    UserBrowser["User (Browser)"] -->|HTTPS / Cookie| AxumServer
    UserCLI["User (CLI)"] -->|HTTPS / Token| AxumServer

    subgraph AWS ["AWS Cloud"]
        AxumServer["Axum Server (EC2)"]
        Postgres[("Postgres DB (RDS)")]

        AxumServer -->|"SQLx (Queries)"| Postgres
    end

```
## Local Setup

### 1) Start Postgres (Docker)

```bash
docker compose up -d
```

This uses the schema in `init.sql`.

### 2) Configure environment

Create a `.env` file in the repo root:

```bash
JWT_SECRET=change_me_to_a_long_random_value
DATABASE_URL=postgres://tpaste_user:rust@localhost:5432/tpaste_db
```

### 3) Create a local TLS cert (development)

The server expects `cert.pem` and `pv_key.pem` in the current working directory.

Example using OpenSSL (self-signed, for local dev only):

```bash
openssl req -x509 -newkey rsa:2048 -keyout pv_key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

### 4) Run the server

```bash
cargo run -p tpaste-server
```

Then open:
- `https://localhost:3000`

Note: with a self-signed cert, your browser will show a warning.

## CLI Client

The CLI is designed to create a paste from stdin (great for piping command output).

### Build

```bash
cargo build -p tpaste-client
```

### Login

```bash
./target/debug/tpaste-client login --name <name> --password <password>
```

### Create a paste (pipe)

```bash
echo "hello" | ./target/debug/tpaste-client
```

If authenticated, it prints a paste URL.
