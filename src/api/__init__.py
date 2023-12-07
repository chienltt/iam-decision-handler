# -*- coding: utf-8 -*-
from flask import Blueprint

admin_bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')
