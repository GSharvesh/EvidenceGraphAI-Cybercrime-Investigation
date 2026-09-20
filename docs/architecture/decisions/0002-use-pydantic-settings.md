# ADR 0002: Use Pydantic-Settings for Typed Environment Management

## Status
Accepted

## Context
Configuration management must load settings from environment variables and `.env` files, validate required keys, enforce strict typing, and fail fast during startup if credentials or settings are invalid.

## Decision
We select **pydantic-settings 2.x** to manage application configuration via `Settings` objects.

## Consequences
- Single source of truth for configuration defaults and type conversion.
- Early fail-fast error messages during startup if configuration is missing or malformed.
- Seamless integration with FastAPI dependency injection.
