#!/bin/bash
# Extract script from index.html and syntax-check it with node
python3 -c "
import sys
with open('index.html') as f: html = f.read()
start = html.find('<script type=\"module\">') + len('<script type=\"module\">')
end = html.rfind('</script>')
with open('/tmp/_demo_check.mjs', 'w') as f: f.write(html[start:end])
"
node --check /tmp/_demo_check.mjs && echo "✓ Syntax OK" || echo "✗ Syntax ERROR"
rm -f /tmp/_demo_check.mjs
