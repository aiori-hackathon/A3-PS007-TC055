"""
app.py - Main Flask Application Server for PS-007
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import os
import sys
import argparse
from flask import Flask, send_from_directory, render_template

# Ensure backend and simulation paths are loaded
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "simulation"))

from routes import api_bp, monitor, device_sim

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

def create_app() -> Flask:
    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

    # Register API blueprint
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        """Serve cybersecurity dashboard single page application."""
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:path>")
    def static_files(path):
        """Serve CSS, JS, and assets."""
        file_path = os.path.join(FRONTEND_DIR, path)
        if os.path.exists(file_path):
            return send_from_directory(FRONTEND_DIR, path)
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PS-007 IPv6 IoT Security Monitoring Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5005, help="Listening port (default: 5005)")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()

    app = create_app()
    print(f"\n=======================================================")
    print(f" PS-007: Privacy-Aware IPv6 IoT Security Monitoring")
    print(f" Running on http://127.0.0.1:{args.port}")
    print(f" Platform Detection: {monitor.packet_monitor.os_type}")
    print(f" Packet Monitoring Mode: {monitor.packet_monitor.mode}")
    print(f"=======================================================\n")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)

