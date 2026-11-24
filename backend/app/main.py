"""
Flask application entry point for PhishTrace AI.
"""
from flask import Flask
from flask_cors import CORS

from app.core.config import settings
from app.api.routes.analyze import analyze_bp
from app.api.routes.adversarial import adversarial_bp
from app.api.routes.history import history_bp
from app.api.routes.upload import upload_bp
from app.database.connection import init_db


def create_app() -> Flask:
    app = Flask(__name__)

    # Initialize CORS for all origins configured in settings
    CORS(app, origins=settings.cors_origins, supports_credentials=True)

    # Initialize database tables on startup
    try:
        init_db()
    except Exception as exc:
        print(f"Database initialization warning: {exc}")

    # Register Blueprints
    app.register_blueprint(analyze_bp)
    app.register_blueprint(adversarial_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(upload_bp)

    @app.route("/api/v1/health")
    def health_check():
        from flask import jsonify
        return jsonify({"status": "ok", "env": settings.app_env, "version": "0.7.0"})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=8000)
