from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    app_name: str = "SOCForge SOAR Engine"
    environment: str = "development"

    host: str = "0.0.0.0"
    port: int = 8000

    # Threat intelligence
    virustotal_api_key: str = ""

    # LLM
    llm_provider: str = "gemini"
    gemini_api_key: str = ""

    # Discord
    discord_webhook_url: str = ""
    discord_bot_token: str = ""
    discord_public_key: str = ""

    # Public URL
    soar_base_url: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    wazuh_api_url: str = ""

    wazuh_api_username: str = ""
    wazuh_api_password: str = ""

    wazuh_verify_ssl: bool = False

    socforge_containment_enabled: bool = False

    wazuh_isolate_command: str = "socforge-isolate"

    wazuh_kill_process_command: str = (
        "socforge-kill-process"
    )

    discord_application_id: str = ""

@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
