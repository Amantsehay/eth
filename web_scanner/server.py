#!/usr/bin/env python3
"""
FastAPI Server Entry Point
Run the web interface for the security scanner
"""

import uvicorn

def main():
    """Run the FastAPI server."""
    uvicorn.run(
        "web_scanner.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

if __name__ == "__main__":
    main()
