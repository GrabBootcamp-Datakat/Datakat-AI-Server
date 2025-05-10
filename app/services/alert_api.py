from fastapi import APIRouter, HTTPException
from app.models.alert_config import AlertConfig
from app.services.alert_config_service import AlertConfigService
from typing import List

router = APIRouter()
alert_config_service = AlertConfigService()

@router.get("/alert-config", response_model=AlertConfig)
async def get_alert_config():
    """Get current alert configuration"""
    try:
        return alert_config_service.get_config()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting alert config: {str(e)}")

@router.put("/alert-config", response_model=AlertConfig)
async def update_alert_config(config: AlertConfig):
    """Update alert configuration"""
    try:
        if alert_config_service.update_config(config):
            return config
        raise HTTPException(status_code=500, detail="Failed to update alert config")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating alert config: {str(e)}")

@router.get("/alert-config/levels", response_model=List[str])
async def get_available_log_levels():
    """Get available log levels for alert configuration"""
    return ["ERROR", "WARN", "INFO", "DEBUG"] 