from fastapi import APIRouter

from datetime import datetime

from agent.collectors.port_scanner import get_listening_ports

router = APIRouter(

    prefix="/api/ports",

    tags=["Ports"]

)

@router.get("/")

def get_ports():

    ports = get_listening_ports()

    return {

        "count": len(ports),

        "ports": ports,

        "timestamp": datetime.now().isoformat()

    }

@router.post("/scan/")

def run_port_scan():

    try:

        ports = get_listening_ports()

        return {

            "count": len(ports),

            "ports": ports,

            "timestamp": datetime.now().isoformat()

        }

    except Exception as error:

        return {

            "count": 0,

            "ports": [],

            "timestamp": datetime.now().isoformat(),

            "error": str(error)

        }