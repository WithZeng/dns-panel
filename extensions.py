import secrets
from flask import current_app, request, session

try:
    from flask_wtf.csrf import CSRFProtect as _CSRFProtect  # type: ignore
    from flask_wtf.csrf import CSRFError, generate_csrf  # type: ignore

    csrf = _CSRFProtect()
except Exception:  # pragma: no cover - fallback for minimal runtime env
    class CSRFError(Exception):
        def __init__(self, description='CSRF token missing or invalid'):
            super().__init__(description)
            self.description = description

    def generate_csrf():
        token = session.get('_csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['_csrf_token'] = token
        return token

    class _SimpleCSRFProtect:
        _SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}

        def init_app(self, app):
            app.jinja_env.globals['csrf_token'] = generate_csrf

            @app.before_request
            def _csrf_protect():
                if request.method in self._SAFE_METHODS:
                    return None
                if request.endpoint == 'static':
                    return None
                view = current_app.view_functions.get(request.endpoint or '')
                if view and getattr(view, '_csrf_exempt', False):
                    return None

                token = (
                    request.form.get('csrf_token')
                    or request.headers.get('X-CSRFToken')
                    or request.headers.get('X-CSRF-Token')
                )
                expected = session.get('_csrf_token')
                if not token or not expected or token != expected:
                    raise CSRFError()
                return None

        def exempt(self, view):
            view._csrf_exempt = True
            return view

    csrf = _SimpleCSRFProtect()
