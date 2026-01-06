# Makefile for dspy.Trust Docker Deployment

.PHONY: help build up down logs test clean rebuild

help: ## Show this help message
	@echo "dspy.Trust Docker Deployment"
	@echo "============================="
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image
	docker-compose build

up: ## Start the service
	docker-compose up -d
	@echo "Waiting for service to be ready..."
	@for i in 1 2 3 4 5; do \
		sleep 2; \
		curl -sf http://localhost:8000/health > /dev/null && echo "✓ Service is ready!" && break; \
	done

down: ## Stop the service
	docker-compose down

logs: ## Show service logs
	docker-compose logs -f

test: ## Run integration tests
	python test_deployment.py

example: ## Run client examples
	python client_example.py

health: ## Check service health
	@curl -s http://localhost:8000/health | python -m json.tool

rebuild: down ## Rebuild from scratch
	docker-compose build --no-cache
	$(MAKE) up

clean: down ## Clean up containers and volumes
	docker-compose down -v
	docker system prune -f

dev: ## Run in development mode with hot reload
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

prod: ## Run in production mode
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

scale: ## Scale to 3 instances
	docker-compose up -d --scale dspy-trust=3

status: ## Show container status
	docker-compose ps

shell: ## Open shell in container
	docker-compose exec dspy-trust bash

stats: ## Show resource usage
	docker stats dspy-trust-security
