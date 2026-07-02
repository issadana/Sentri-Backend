# Sentri / Neural Firewall backend — Docker Compose helper targets.
# Run `make` (or `make help`) to list targets. Docker must be running.

.PHONY: help up start stop restart down logs ps build migrate db-shell clean

.DEFAULT_GOAL := help

help: ## Show this help
	@printf "Usage: make <target>\n\nTargets:\n"
	@awk 'BEGIN {FS=":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Build and start all services in the background
	docker compose up -d --build

start: up ## Alias for 'up'

stop: ## Stop running containers (data is kept)
	docker compose stop

restart: ## Restart all services
	docker compose restart

logs: ## Tail live logs (Ctrl+C to exit, containers keep running)
	docker compose logs -f

ps: ## Show container status
	docker compose ps

build: ## Build (or rebuild) the images without starting
	docker compose build

migrate: ## Run database migrations manually (needs the web container up)
	docker compose exec web flask db upgrade

db-shell: ## Open a psql shell in the Postgres container
	docker compose exec db psql -U sentri -d sentridb

down: ## Stop and remove containers (keeps the DB volume)
	docker compose down

clean: ## Remove containers AND the database volume (DESTRUCTIVE)
	docker compose down -v
