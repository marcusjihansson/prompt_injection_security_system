# Docker Architecture

This document describes the Docker-specific deployment architecture for dspy.Trust.

For the overall system architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Reference

| Topic | See |
|-------|-----|
| System Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Getting Started | [README.md](README.md) |
| Quick Start Guide | [QUICKSTART.md](QUICKSTART.md) |
| Security Policy | [docs/SECURITY.md](docs/SECURITY.md) |

## Docker Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                        User Applications                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Python     │  │ JavaScript/  │  │     Go       │           │
│  │   Client     │  │  TypeScript  │  │   Client     │  ...      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
└─────────┼──────────────────┼──────────────────┼────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Load Balancer  │ (optional)
                    │     (Nginx)     │
                    └────────┬────────┘
                             │
           ┌──────────────────┴──────────────────┐
           │                                     │
   ┌─────────▼─────────┐              ┌─────────▼─────────┐
   │ dspy-trust-1      │              │ dspy-trust-2      │
   │ (Docker Container)│              │ (Docker Container)│
   └───────────────────┘              └───────────────────┘
           │                                     │
           └──────────────────┬──────────────────┘
                              │
                     ┌────────▼────────┐
                     │  Shared Cache   │ (optional)
                     │     (Redis)     │
                     └─────────────────┘
```

## Key Docker Features

- **Embedded Models**: DSPy GEPA-optimized detectors and Llama-Guard-3-1B-INT4 run locally
- **Multi-layer Caching**: LRU cache + semantic cache + request deduplication
- **Performance**: 8-15ms average latency with proper configuration
- **Scalability**: Horizontal scaling with load balancing support

## Getting Started

```bash
cd deployment
docker-compose build
docker-compose up -d
curl http://localhost:8000/health
```

## See Also

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Complete system architecture
- [QUICKSTART.md](QUICKSTART.md) - 5-minute deployment tutorial
- [README.md](README.md) - Full deployment documentation
