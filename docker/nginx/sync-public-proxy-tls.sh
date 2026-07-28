#!/usr/bin/env bash
# Compat wrapper — ACME TLS sync covers all bastion FQDNs (not only public_proxy).
exec /sync-acme-tls.sh "$@"
