# Android / APK

Potential evidence layers:
- package/manifest metadata and permissions;
- resources and binary XML;
- DEX strings, constants and code context;
- native libraries;
- embedded SDK/configuration identifiers;
- application data / preferences / databases;
- network endpoints and request paths;
- signing/build metadata where available.

For behavior claims, separate permission/capability from actual data flow and observed execution. For endpoints, separate embedded/configured value from active use and from infrastructure ownership.

For encryption claims, identify the requested data, the transformation call/path, algorithm/mode/padding/key material as applicable. A crypto class/string alone is not enough.
