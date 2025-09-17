import importlib, sys
importlib.invalidate_caches()

try:
    import app
    print('app imported OK')
except Exception as e:
    print('IMPORT_ERROR:', type(e).__name__, e)
    raise
