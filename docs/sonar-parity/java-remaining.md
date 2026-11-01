# Java rules covered in part

Every Sonar way Java rule has a sonda rule. The rules below are covered only in part: sonda's rule catches the common shape, but not every variant Sonar's own rule reaches (mostly because Sonar follows values across files or through type information that a single-file syntax check does not have). The full per-rule table is `java.csv` (status `partial`).

| Sonar key | Sonda rule | Title / type |
|---|---|---|
| `java:S108` | `java/empty-catch` | code_smell, major |
| `java:S1190` | `java/future-keyword-name` | code_smell, blocker |
| `java:S2068` | `java/hardcoded-credential` | vulnerability, major |
| `java:S2077` | `java/sql-built-dynamically` | vulnerability, major |
| `java:S2245` | `java/random-secret` | vulnerability, major |
| `java:S3306` | `java/field-injection` | bug, major |
| `java:S4288` | `java/field-injection` | code_smell, major |
| `java:S4502` | `java/csrf-disabled` | vulnerability, critical |
| `java:S5122` | `java/cors-any-origin` | vulnerability, major |
| `java:S5332` | `java/cleartext-url` | vulnerability, minor |
| `java:S6418` | `java/hardcoded-credential` | vulnerability, blocker |
| `java:S6437` | `java/hardcoded-credential` | vulnerability, blocker |
