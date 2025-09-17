import sys
import os

print('PYTHON:', sys.executable)
print('CWD:', os.getcwd())

proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

try:
    import app
    print('Imported app OK')
except Exception as e:
    print('Import app failed:', repr(e))

try:
    from extensions import db
    print('Imported extensions.db OK')
except Exception as e:
    print('Import extensions failed:', repr(e))

print('Done')
