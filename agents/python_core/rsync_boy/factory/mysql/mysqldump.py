# agents/python_core/rsync_boy/factory/mysql/mysqldump.py
import os
import re
import shlex
import json
import time
import gzip
import hashlib
import tempfile
import subprocess
from dataclasses import dataclass


@dataclass
class SSHCreds:
    ssh_host: str
    ssh_user: str
    ssh_port: int = 22
    auth_type: str = "priv"          # "priv" | "password"
    private_key_pem: str | None = None
    private_key: str | None = None   # optional path fallback
    password: str | None = None
    strict_host_key: bool = False    # if True, do not auto-accept new host keys


class MySQLDumpJob:
    """
    Fire-and-forget MySQL dump job.
    Contract:
      ctx = shared["context"] = { "job_id": str, "credentials": dict, "config": dict }
    """

    def __init__(self, log, shared):
        self.log = log
        self.shared = shared
        self.ctx = shared.get("context", {}) or {}
        self.job_id = self.ctx.get("job_id", "mysql_dump")

    # ---------------------------------------------------------
    def run(self):
        started = time.time()
        try:
            cfg = self.ctx.get("config", {}) or {}

            creds = self._parse_creds(cfg)
            job = self._validate_and_normalize_cfg(cfg)

            self.log(f"[MYSQLDUMP][{self.job_id}] Starting dump for db='{job['database']}'")

            # Preflight
            self._require_binary("mysqldump")
            self._require_binary("rsync")
            self._require_binary("ssh")

            # Dump -> optional gzip -> sha256 -> manifest
            local_file = self._dump_database(job)
            if job["compress"]:
                local_file = self._gzip_file(local_file)

            sha = self._sha256_file(local_file)
            manifest_path = self._write_manifest(job, local_file, sha, started)

            # Remote ensure + upload both dump + manifest
            self._remote_mkdir(creds, job["remote_path"])
            self._rsync_upload(creds, local_file, job["remote_path"])
            self._rsync_upload(creds, manifest_path, job["remote_path"])

            # Optional prune
            prune = job.get("remote_prune", {})
            if prune and int(prune.get("keep_days", 0)) > 0:
                self._remote_prune(creds, job["remote_path"], prune)

            self.shared["result"] = "ok"
            self.shared["finished_at"] = time.time()
            self.log(f"[MYSQLDUMP][{self.job_id}] ✅ Completed in {int(time.time() - started)}s")

        except Exception as e:
            self.shared["result"] = "error"
            self.shared["error"] = str(e)
            self.shared["finished_at"] = time.time()
            self.log(f"[MYSQLDUMP][{self.job_id}][ERROR] {e}", level="ERROR")
            raise

    # ---------------------------------------------------------
    # Parsing / Validation
    # ---------------------------------------------------------
    def _parse_creds(self, cfg: dict) -> SSHCreds:
        ssh = cfg.get("ssh", {}) or {}

        # Accept both naming styles
        host = ssh.get("ssh_host") or ssh.get("host") or ""
        user = ssh.get("ssh_user") or ssh.get("username") or ""
        port = int(ssh.get("ssh_port") or ssh.get("port") or 22)

        if not host or not user:
            raise ValueError("Missing SSH credentials: ssh.host and ssh.username required")

        return SSHCreds(
            ssh_host=host.strip(),
            ssh_user=user.strip(),
            ssh_port=port,
            auth_type=ssh.get("auth_type") or "priv",
            private_key_pem=ssh.get("private_key_pem") or ssh.get("private_key"),
            private_key=ssh.get("private_key"),
            password=ssh.get("password"),
            strict_host_key=bool(ssh.get("strict_host_key") or ssh.get("trusted_host_fingerprint"))
        )

    def _validate_and_normalize_cfg(self, cfg: dict) -> dict:
        mysql = cfg.get("mysql", {}) or {}

        # Accept both naming styles
        db = mysql.get("database", "").strip()
        host = mysql.get("mysql_host") or mysql.get("host") or "localhost"
        port = int(mysql.get("mysql_port") or mysql.get("port") or 3306)
        user = mysql.get("mysql_user") or mysql.get("username") or ""
        pwd = mysql.get("mysql_password") or mysql.get("password") or ""

        if not db:
            raise ValueError("config.mysql.database is required")

        remote_path = (cfg.get("remote_path") or "").strip()
        if not remote_path:
            raise ValueError("config.remote_path is required")

        job = {
            "mysql_host": host,
            "mysql_port": port,
            "mysql_user": user,
            "mysql_password": pwd,
            "database": db,

            # job options living at config.*
            "dump_flags": (cfg.get("dump_flags") or "").strip(),
            "local_tmp": (cfg.get("local_tmp") or "/tmp/mysql_dumps").strip(),
            "remote_path": remote_path,
            "compress": bool(cfg.get("compress", True)),
            "filename_prefix": (cfg.get("filename_prefix") or db).strip(),
            "remote_prune": cfg.get("remote_prune", {}) or {},
        }

        if not job["mysql_user"]:
            raise ValueError("config.mysql.mysql_user is required")
        if not job["mysql_password"]:
            raise ValueError("config.mysql.mysql_password is required")

        if not (1 <= job["mysql_port"] <= 65535):
            raise ValueError("config.mysql.mysql_port out of range")

        os.makedirs(job["local_tmp"], exist_ok=True)
        return job

    # ---------------------------------------------------------
    # Preflight helpers
    # ---------------------------------------------------------
    def _require_binary(self, name: str):
        if subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            raise RuntimeError(f"Required binary not found: {name}")

    # ---------------------------------------------------------
    # Dump & file ops
    # ---------------------------------------------------------
    def _dump_database(self, job: dict) -> str:
        ts = time.strftime("%Y%m%d_%H%M%S")
        fname = f"{job['filename_prefix']}_{ts}.sql"
        out_path = os.path.join(job["local_tmp"], fname)

        # Use env var to avoid password in process list
        env = os.environ.copy()
        env["MYSQL_PWD"] = str(job["mysql_password"])

        # If user specified "all" or "all-databases", switch to --all-databases
        # If user specified "all" or "all-databases", switch to --all-databases
        all_dbs = job["database"].lower() in ("all", "all-databases")

        cmd = [
            "mysqldump",
            "-h", job["mysql_host"],
            "-P", str(job["mysql_port"]),
            "-u", job["mysql_user"],
        ]

        if all_dbs:
            cmd.append("--all-databases")
        else:
            cmd += ["--databases", job["database"]]

        if job["dump_flags"]:
            cmd.extend(shlex.split(job["dump_flags"]))

        self.log(f"[MYSQLDUMP][{self.job_id}] Running mysqldump -> {out_path}")
        with open(out_path, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env)
        if p.returncode != 0:
            err = (p.stderr or b"").decode("utf-8", "ignore")[-3000:]
            raise RuntimeError(f"mysqldump failed (code={p.returncode}): {err}")

        try:
            os.chmod(out_path, 0o600)
        except Exception:
            pass

        return out_path

    def _gzip_file(self, path: str) -> str:
        gz_path = path + ".gz"
        self.log(f"[MYSQLDUMP][{self.job_id}] Compressing -> {gz_path}")

        with open(path, "rb") as src, gzip.open(gz_path, "wb", compresslevel=9) as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)

        try:
            os.remove(path)
        except Exception:
            pass

        try:
            os.chmod(gz_path, 0o600)
        except Exception:
            pass

        return gz_path

    def _sha256_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _write_manifest(self, job: dict, file_path: str, sha: str, started_ts: float) -> str:
        manifest = {
            "job_id": self.job_id,
            "database": job["database"],
            "mysql_host": job["mysql_host"],
            "mysql_port": job["mysql_port"],
            "file": os.path.basename(file_path),
            "sha256": sha,
            "bytes": os.path.getsize(file_path),
            "started_at": int(started_ts),
            "finished_at": int(time.time()),
            "compressed": file_path.endswith(".gz"),
        }

        mf_path = file_path + ".manifest.json"
        with open(mf_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        try:
            os.chmod(mf_path, 0o600)
        except Exception:
            pass

        return mf_path

    # ---------------------------------------------------------
    # SSH / rsync (hardened)
    # ---------------------------------------------------------
    def _ssh_common_opts(self, creds: SSHCreds) -> list[str]:
        opts = []
        if creds.strict_host_key:
            opts += ["-o", "StrictHostKeyChecking=yes"]
        else:
            # accept-new is sane for automation; change if you enforce known_hosts
            opts += ["-o", "StrictHostKeyChecking=accept-new"]
        return opts

    def _start_ssh_agent(self, creds: SSHCreds) -> dict:
        """
        Start a temporary ssh-agent, add private key via stdin (PEM), return env.
        Key NEVER touches disk.
        """
        if creds.auth_type not in ("priv", "key", "private"):
            return os.environ.copy()

        if not creds.private_key_pem and not creds.private_key:
            raise ValueError("auth_type=priv requires private_key_pem (preferred) or private_key path")

        env = os.environ.copy()
        agent = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True, check=True)

        # Parse env exports from ssh-agent output
        for line in agent.stdout.splitlines():
            if line.startswith("SSH_AUTH_SOCK=") or line.startswith("SSH_AGENT_PID="):
                kv = line.split(";", 1)[0]
                k, v = kv.split("=", 1)
                env[k] = v

        # Add key
        if creds.private_key_pem:
            subprocess.run(["ssh-add", "-"], input=creds.private_key_pem, text=True, env=env, check=True)
        else:
            # Path fallback
            subprocess.run(["ssh-add", creds.private_key], env=env, check=True)

        return env

    def _kill_ssh_agent(self, env: dict):
        try:
            pid = env.get("SSH_AGENT_PID")
            if pid:
                subprocess.run(["kill", pid], check=False)
        except Exception:
            pass

    def _remote_mkdir(self, creds: SSHCreds, remote_path: str):
        env = None
        try:
            if creds.auth_type in ("password", "pass"):
                self._require_binary("sshpass")
                cmd = [
                    "sshpass", "-p", creds.password or "",
                    "ssh", "-p", str(creds.ssh_port),
                    *self._ssh_common_opts(creds),
                    f"{creds.ssh_user}@{creds.ssh_host}",
                    f"mkdir -p {shlex.quote(remote_path)}"
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                return

            env = self._start_ssh_agent(creds)
            cmd = [
                "ssh", "-p", str(creds.ssh_port),
                *self._ssh_common_opts(creds),
                f"{creds.ssh_user}@{creds.ssh_host}",
                f"mkdir -p {shlex.quote(remote_path)}"
            ]
            subprocess.run(cmd, check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        finally:
            if env and env.get("SSH_AGENT_PID"):
                self._kill_ssh_agent(env)

    def _rsync_upload(self, creds: SSHCreds, local_file: str, remote_path: str):
        if not os.path.exists(local_file):
            raise FileNotFoundError(local_file)

        remote = f"{creds.ssh_user}@{creds.ssh_host}:{remote_path.rstrip('/')}/"

        # Use stable ssh options
        ssh_cmd = ["ssh", "-p", str(creds.ssh_port), *self._ssh_common_opts(creds)]

        env = None
        try:
            if creds.auth_type in ("password", "pass"):
                self._require_binary("sshpass")
                cmd = [
                    "sshpass", "-p", creds.password or "",
                    "rsync", "-avz", "--partial",
                    "-e", " ".join(ssh_cmd),
                    local_file,
                    remote
                ]
                p = subprocess.run(cmd, capture_output=True, text=True)
            else:
                env = self._start_ssh_agent(creds)
                cmd = [
                    "rsync", "-avz", "--partial",
                    "-e", " ".join(ssh_cmd),
                    local_file,
                    remote
                ]
                p = subprocess.run(cmd, capture_output=True, text=True, env=env)

            if p.returncode != 0:
                err = (p.stderr or "")[-3000:]
                raise RuntimeError(f"rsync failed (code={p.returncode}): {err}")

        finally:
            if env and env.get("SSH_AGENT_PID"):
                self._kill_ssh_agent(env)

    def _remote_prune(self, creds: SSHCreds, remote_path: str, prune_cfg: dict):
        """
        prune_cfg:
          { "keep_days": 7, "pattern": "*.sql.gz" }
        """
        keep_days = int(prune_cfg.get("keep_days", 0))
        pattern = (prune_cfg.get("pattern") or "*.sql*").strip()

        if keep_days <= 0:
            return

        cmd_str = (
            f"find {shlex.quote(remote_path)} -type f "
            f"-name {shlex.quote(pattern)} -mtime +{keep_days} -delete"
        )

        env = None
        try:
            if creds.auth_type in ("password", "pass"):
                self._require_binary("sshpass")
                cmd = [
                    "sshpass", "-p", creds.password or "",
                    "ssh", "-p", str(creds.ssh_port),
                    *self._ssh_common_opts(creds),
                    f"{creds.ssh_user}@{creds.ssh_host}",
                    cmd_str
                ]
                subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return

            env = self._start_ssh_agent(creds)
            cmd = [
                "ssh", "-p", str(creds.ssh_port),
                *self._ssh_common_opts(creds),
                f"{creds.ssh_user}@{creds.ssh_host}",
                cmd_str
            ]
            subprocess.run(cmd, check=False, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        finally:
            if env and env.get("SSH_AGENT_PID"):
                self._kill_ssh_agent(env)
