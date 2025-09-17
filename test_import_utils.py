import importlib, sys
importlib.invalidate_caches()

try:
    import utils
    print('utils imported OK')
    # Quick smoke test for Manila conversion helper
    import datetime
    now = datetime.datetime.utcnow()
    print('manila now:', utils.convert_to_manila_time(now))
except Exception as e:
    print('IMPORT_ERROR:', type(e).__name__, e)
    raise
