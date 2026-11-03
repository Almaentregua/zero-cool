# technologies.yaml (planned format)

Defines which technologies the app tracks. Adding one means adding an entry;
no code changes. Proposed shape (may be refined on implementation):

```yaml
technologies:
  - name: Java
    osv_ecosystems: [Maven]
    products:            # vendor/product pairs used to match NVD/KEV data
      - {vendor: apache, product: log4j}
  - name: Node.js
    osv_ecosystems: [npm]
    products:
      - {vendor: nodejs, product: node.js}
```

The file is validated on startup; an invalid entry stops the app with a clear
error instead of failing silently.
