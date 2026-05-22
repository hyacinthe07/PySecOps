from flask import Blueprint, jsonify, request
from app.utils.db_utils import get_stats
import datetime

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


@api_bp.route('/health')
def health():
    return jsonify({"status": "online", "version": "3.0"})


@api_bp.route('/stats')
def stats():
    return jsonify(get_stats())
