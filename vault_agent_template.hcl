# Vault Agent template example to render /etc/pasc_pro.env from Vault secrets
exit_after_auth = false
pid_file = "/var/run/vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/vault/role_id",
      secret_id_file_path = "/etc/vault/secret_id",
    }
  }

  sink "file" {
    config = {
      path = "/var/run/vault-approle-token/token"
    }
  }
}

template {
  source = "/etc/vault/templates/pasc_pro_env.tpl"
  destination = "/etc/pasc_pro.env"
  command = "/bin/systemctl restart pasc_gunicorn.service || true"
}
