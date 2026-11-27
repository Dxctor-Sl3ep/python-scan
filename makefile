PYTHON ?= python3
ANSIBLE_VAULT ?= ansible-vault
SCAN_PATH ?= $(HOME)/Downloads

.PHONY: help install vault-encrypt vault-edit integrity-check virustotal-scan

help:
	@printf "Available targets:\n"
	@printf "  install          Install project dependencies\n"
	@printf "  vault-encrypt    Encrypt .env with Ansible Vault\n"
	@printf "  vault-edit       Edit .env with Ansible Vault\n"
	@printf "  integrity-check  Verify configured file hashes\n"
	@printf "  virustotal-scan  Check file hashes under $(SCAN_PATH)\n"

install:
	$(PYTHON) -m pip install -r requirement.txt

vault-encrypt:
	$(ANSIBLE_VAULT) encrypt .env

vault-edit:
	$(ANSIBLE_VAULT) edit .env

integrity-check:
	$(PYTHON) -m tools.integrity_check

virustotal-scan:
	$(PYTHON) -m tools.virustotal_scan "$(SCAN_PATH)"
