//! JavaScript and TypeScript rules for security-sensitive configuration:
//! framework and library options that weaken a defense (ADR-0007, batch 1).

use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/angular-sanitizer-bypass",
        name: "Angular's built-in sanitization should not be bypassed",
        description: "bypassSecurityTrust* tells Angular to render a value without \
                      sanitizing it, so any attacker-controlled text in it runs as script.",
        message: "Remove this sanitization bypass, or sanitize the value yourself first.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S6268")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression
                            property: (property_identifier) @p
                            (#match? @p "^bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)$"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const html = this.sanitizer.bypassSecurityTrustHtml(userInput);",
            good: "const html = this.sanitizer.sanitize(SecurityContext.HTML, userInput);",
        }),
    },
    Rule {
        id: "js/mocha-timeout-disabled",
        name: "Mocha timeouts should not be disabled silently",
        description: "this.timeout(0) removes the time limit, so a hung test blocks the whole \
                      run. Use a large, explicit value so the intent is visible.",
        message: "Set an explicit, finite timeout instead of 0.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6080")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression
                            object: (this)
                            property: (property_identifier) @p (#eq? @p "timeout"))
                        arguments: (arguments . (number) @n (#eq? @n "0"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('syncs', function () { this.timeout(0); });",
            good: "it('syncs', function () { this.timeout(60000); });",
        }),
    },
    Rule {
        id: "js/error-handler-middleware",
        name: "Debugging middleware should not run in production",
        description: "The errorhandler package sends stack traces and internals to the \
                      client, which helps attackers map the application.",
        message: "Only install errorhandler outside production, or use your own handler.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4507")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "errorhandler")) @match"#,
            filter: Some(Keep(not_guarded_by_environment)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(errorhandler());",
            good: "if (process.env.NODE_ENV === 'development') { app.use(errorhandler()); }",
        }),
    },
    Rule {
        id: "js/csrf-methods-ignored",
        name: "CSRF protection should cover state-changing methods",
        description: "Listing POST, PUT, PATCH or DELETE in csurf's ignoreMethods turns off \
                      CSRF protection for exactly the requests it exists to protect.",
        message: "Only ignore safe methods (GET, HEAD, OPTIONS).",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S4502")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "ignoreMethods") value: (array)) @match"#,
            filter: Some(Keep(ignores_mutating_methods)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(csurf({ ignoreMethods: ['GET', 'POST'] }));",
            good: "app.use(csurf({ ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] }));",
        }),
    },
    Rule {
        id: "js/upload-without-limit",
        name: "File uploads should have a size limit",
        description: "Without a limit, one request can fill the disk or memory of the \
                      server.",
        message: "Set a file size limit for this upload handler.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[related("S2598")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "multer" "formidable")) @match"#,
            filter: Some(Keep(upload_without_limit)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const upload = multer({ dest: 'uploads/' });",
            good: "const upload = multer({ dest: 'uploads/', limits: { fileSize: 1000000 } });",
        }),
    },
    Rule {
        id: "js/template-built-dynamically",
        name: "Templates should not be built from strings at runtime",
        description: "Concatenating or interpolating data into the template source lets an \
                      attacker inject template code, which usually means code execution.",
        message: "Keep the template fixed and pass the data as variables.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S7790")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression
                            object: (identifier) @o
                            property: (property_identifier) @p
                            (#any-of? @o "Handlebars" "handlebars" "ejs" "pug" "_" "lodash" "nunjucks" "Mustache" "mustache" "doT")
                            (#any-of? @p "compile" "template" "render" "renderString" "precompile"))) @match"#,
            filter: Some(Keep(first_argument_is_built)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const html = ejs.render('<h1>' + title + '</h1>', data);",
            good: "const html = ejs.render('<h1><%= title %></h1>', { title });",
        }),
    },
    Rule {
        id: "js/express-version-disclosure",
        name: "Express should not announce its version",
        description: "The default X-Powered-By header tells attackers which framework is \
                      running, so they can look for known flaws in it.",
        message: "Disable the X-Powered-By header, or use helmet.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S5689")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "express") arguments: (arguments)) @match"#,
            filter: Some(Keep(express_app_announces_itself)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const app = express();",
            good: "const app = express();\napp.disable('x-powered-by');",
        }),
    },
    Rule {
        id: "js/cleartext-url",
        name: "Clear-text protocols should not be used",
        description: "http, ftp and telnet send data, including credentials, unencrypted. \
                      Loopback and private-network addresses, test domains and XML \
                      namespaces are not reported.",
        message: "Use the encrypted version of this protocol (https, sftp, ssh).",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S5332")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match (#match? @match "^['\"](http|ftp|telnet)://"))"#,
            filter: Some(Keep(is_public_cleartext_url)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const api = 'http://api.example-shop.io/v1';",
            good: "const api = 'https://api.example-shop.io/v1';\nconst dev = 'http://localhost:3000';",
        }),
    },
    Rule {
        id: "js/math-random-secret",
        name: "Math.random() should not generate secrets",
        description: "Math.random() is predictable, so tokens, passwords and nonces built from \
                      it can be guessed. Use crypto.randomBytes or crypto.randomUUID.",
        message: "Use a cryptographically secure generator for this value.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S2245")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression
                            object: (identifier) @o
                            property: (property_identifier) @p
                            (#eq? @o "Math") (#eq? @p "random"))) @match"#,
            filter: Some(Keep(random_feeds_a_secret)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const sessionToken = Math.random().toString(36);",
            good: "const sessionToken = crypto.randomBytes(16).toString('hex');\nconst jitter = Math.random() * 100;",
        }),
    },
    Rule {
        id: "js/this-in-function-component",
        name: "\"this\" should not be used in function components",
        description: "A function component has no instance, so `this` is undefined there; \
                      read props from the parameter and state from hooks.",
        message: "Remove 'this': use the props parameter and hooks.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6757")],
        check: Check::Query {
            langs: JSX,
            query: r#"(function_declaration name: (identifier) @n (#match? @n "^[A-Z]")) @match"#,
            filter: Some(Find(this_in_component)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Greeting(props) { return <h1>{this.props.name}</h1>; }",
            good: "function Greeting(props) { return <h1>{props.name}</h1>; }",
        }),
    },
    Rule {
        id: "js/table-without-headers",
        name: "Tables should have headers",
        description: "Screen readers announce a cell by its column and row headers; a table \
                      without any <th> leaves them guessing.",
        message: "Add header cells (<th>) to this table.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S5256")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#eq? @n "table"))) @match"#,
            filter: Some(Keep(table_without_headers)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const t = <table><tbody><tr><td>1</td></tr></tbody></table>;",
            good: "const t = <table><thead><tr><th>Id</th></tr></thead><tbody><tr><td>1</td></tr></tbody></table>;",
        }),
    },
    Rule {
        id: "js/upload-size-too-large",
        name: "Uploads should be limited to a reasonable size",
        description: "A limit above 8 MB lets a few requests exhaust memory or disk. Most \
                      uploads (images, documents) fit well below it.",
        message: "Lower this size limit to 8 MB or less, or process the upload as a stream.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S5693")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#any-of? @k "fileSize" "maxFileSize") value: (number)) @match"#,
            filter: Some(Keep(size_over_eight_megabytes)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const upload = multer({ limits: { fileSize: 50000000 } });",
            good: "const upload = multer({ limits: { fileSize: 2000000 } });",
        }),
    },
    Rule {
        id: "cdk/bucket-allows-plain-http",
        name: "S3 buckets should enforce HTTPS-only access",
        description: "Without enforceSSL, the bucket accepts requests over plain HTTP, where data and credentials can be read in transit.",
        message: "Set 'enforceSSL: true' on this bucket.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6249")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Bucket)$")) @match"#,
            filter: Some(Keep(lacks_enforce_ssl)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { versioned: true });",
            good: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { enforceSSL: true });",
        }),
    },
    Rule {
        id: "cdk/bucket-without-versioning",
        name: "S3 buckets should have versioning enabled",
        description: "Without versioning, an overwritten or deleted object cannot be recovered.",
        message: "Set 'versioned: true' on this bucket.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6252")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Bucket)$")) @match"#,
            filter: Some(Keep(lacks_versioned)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { enforceSSL: true });",
            good: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { versioned: true });",
        }),
    },
    Rule {
        id: "cdk/bucket-public-access",
        name: "S3 buckets should not grant access to everyone",
        description: "publicReadAccess and the PUBLIC_READ, PUBLIC_READ_WRITE and AUTHENTICATED_READ ACLs let anyone, or any AWS account, read the bucket.",
        message: "Remove the public access from this bucket.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6265")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Bucket)$")) @match"#,
            filter: Some(Keep(bucket_is_public)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Site', { publicReadAccess: true });",
            good: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Site', { publicReadAccess: false });",
        }),
    },
    Rule {
        id: "cdk/bucket-public-access-not-blocked",
        name: "S3 bucket public access should be fully blocked",
        description: "Without blockPublicAccess, a later ACL or policy mistake can make the bucket public.",
        message: "Set 'blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL' on this bucket.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S6281")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Bucket)$")) @match"#,
            filter: Some(Keep(bucket_public_access_not_blocked)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { versioned: true });",
            good: "import 'aws-cdk-lib';\nconst b = new s3.Bucket(this, 'Data', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });",
        }),
    },
    Rule {
        id: "cdk/volume-not-encrypted",
        name: "EBS volumes should be encrypted",
        description: "An unencrypted volume exposes its data if a snapshot or the disk is accessed outside the instance.",
        message: "Set 'encrypted: true' on this volume.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6275")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Volume|CfnVolume)$")) @match"#,
            filter: Some(Keep(lacks_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst v = new ec2.Volume(this, 'Disk', { size: Size.gibibytes(10) });",
            good: "import 'aws-cdk-lib';\nconst v = new ec2.Volume(this, 'Disk', { encrypted: true });",
        }),
    },
    Rule {
        id: "cdk/database-not-encrypted",
        name: "RDS databases should be encrypted at rest",
        description: "Without storage encryption, the database files, backups and snapshots are readable by anyone who gets at the storage.",
        message: "Set 'storageEncrypted: true' on this database.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6303")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(DatabaseInstance|DatabaseCluster|CfnDBInstance|CfnDBCluster)$")) @match"#,
            filter: Some(Keep(lacks_storage_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst d = new rds.DatabaseInstance(this, 'Db', { engine });",
            good: "import 'aws-cdk-lib';\nconst d = new rds.DatabaseInstance(this, 'Db', { engine, storageEncrypted: true });",
        }),
    },
    Rule {
        id: "cdk/search-domain-not-encrypted",
        name: "OpenSearch domains should be encrypted at rest",
        description: "Without encryption at rest, indexed documents are stored in clear text.",
        message: "Enable encryption at rest on this domain.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6308")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Domain|CfnDomain)$")) @match"#,
            filter: Some(Keep(search_domain_not_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst d = new opensearch.Domain(this, 'Search', { version });",
            good: "import 'aws-cdk-lib';\nconst d = new opensearch.Domain(this, 'Search', { version, encryptionAtRest: { enabled: true } });",
        }),
    },
    Rule {
        id: "cdk/notebook-not-encrypted",
        name: "SageMaker notebook instances should be encrypted at rest",
        description: "Without a KMS key, the notebook's storage volume is not encrypted with a key you control.",
        message: "Set 'kmsKeyId' on this notebook instance.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6319")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(CfnNotebookInstance)$")) @match"#,
            filter: Some(Keep(lacks_kms_key_id)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst n = new sagemaker.CfnNotebookInstance(this, 'Nb', { instanceType, roleArn });",
            good: "import 'aws-cdk-lib';\nconst n = new sagemaker.CfnNotebookInstance(this, 'Nb', { instanceType, roleArn, kmsKeyId: key.keyId });",
        }),
    },
    Rule {
        id: "cdk/topic-not-encrypted",
        name: "SNS topics should be encrypted at rest",
        description: "Messages in an unencrypted topic are stored in clear text.",
        message: "Set a KMS key ('masterKey') on this topic.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6327")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Topic|CfnTopic)$")) @match"#,
            filter: Some(Keep(topic_not_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst t = new sns.Topic(this, 'Events');",
            good: "import 'aws-cdk-lib';\nconst t = new sns.Topic(this, 'Events', { masterKey: key });",
        }),
    },
    Rule {
        id: "cdk/queue-not-encrypted",
        name: "SQS queues should be encrypted",
        description: "Messages in an unencrypted queue are stored in clear text.",
        message: "Remove the UNENCRYPTED setting, or encrypt this queue.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6330")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(Queue|CfnQueue)$")) @match"#,
            filter: Some(Keep(queue_not_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst q = new sqs.Queue(this, 'Jobs', { encryption: sqs.QueueEncryption.UNENCRYPTED });",
            good: "import 'aws-cdk-lib';\nconst q = new sqs.Queue(this, 'Jobs');",
        }),
    },
    Rule {
        id: "cdk/file-system-not-encrypted",
        name: "EFS file systems should be encrypted",
        description: "An unencrypted file system exposes its data to anyone with access to the underlying storage.",
        message: "Set 'encrypted: true' on this file system.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6332")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(FileSystem|CfnFileSystem)$")) @match"#,
            filter: Some(Keep(file_system_not_encrypted)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst f = new efs.FileSystem(this, 'Fs', { vpc, encrypted: false });",
            good: "import 'aws-cdk-lib';\nconst f = new efs.FileSystem(this, 'Fs', { vpc, encrypted: true });",
        }),
    },
    Rule {
        id: "cdk/api-method-without-auth",
        name: "API Gateway methods should require authentication",
        description: "authorizationType NONE lets anyone call the method.",
        message: "Require an authorizer on this method.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6333")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "authorizationType")) @match"#,
            filter: Some(Keep(authorization_is_none)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\napi.root.addMethod('GET', integration, { authorizationType: apigateway.AuthorizationType.NONE });",
            good: "import 'aws-cdk-lib';\napi.root.addMethod('GET', integration, { authorizationType: apigateway.AuthorizationType.IAM });",
        }),
    },
    Rule {
        id: "cdk/publicly-accessible",
        name: "Cloud resources should not be reachable from the public network",
        description: "publiclyAccessible gives the resource a public address, exposing it to attacks from the internet.",
        message: "Remove 'publiclyAccessible: true' and keep this resource in a private subnet.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6329")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "publiclyAccessible") value: (true)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nconst d = new rds.CfnDBInstance(this, 'Db', { publiclyAccessible: true });",
            good: "import 'aws-cdk-lib';\nconst d = new rds.CfnDBInstance(this, 'Db', { publiclyAccessible: false });",
        }),
    },
    Rule {
        id: "cdk/admin-port-open-to-world",
        name: "Administration services should not be open to the internet",
        description: "Letting any address reach SSH (22) or RDP (3389) exposes them to scans and brute-force attacks.",
        message: "Restrict this rule to specific addresses.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S6321")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "addIngressRule"))) @match"#,
            filter: Some(Keep(opens_admin_port_to_world)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nsg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));",
            good: "import 'aws-cdk-lib';\nsg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(22));",
        }),
    },
    Rule {
        id: "cdk/policy-grants-everything",
        name: "Policies should not grant all privileges",
        description: "An action of '*' lets the principal do anything with the resource.",
        message: "List only the actions this policy needs.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6302")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#any-of? @k "actions" "Action") value: [(array) (string)] @v) @match"#,
            filter: Some(Keep(grants_all_actions)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nnew iam.PolicyStatement({ actions: ['*'], resources: [arn] });",
            good: "import 'aws-cdk-lib';\nnew iam.PolicyStatement({ actions: ['s3:GetObject'], resources: [arn] });",
        }),
    },
    Rule {
        id: "cdk/policy-for-everyone",
        name: "Resource policies should not grant public access",
        description: "An AnyPrincipal or '*' principal lets every AWS account, and sometimes the whole internet, use the resource.",
        message: "Name the principals that need access.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6270")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: [(member_expression property: (property_identifier) @c) (identifier) @c] (#match? @c "^(AnyPrincipal|StarPrincipal|ArnPrincipal)$")) @match"#,
            filter: Some(Keep(principal_is_everyone)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import 'aws-cdk-lib';\nnew iam.PolicyStatement({ principals: [new iam.AnyPrincipal()], actions });",
            good: "import 'aws-cdk-lib';\nnew iam.PolicyStatement({ principals: [new iam.AccountPrincipal(id)], actions });",
        }),
    },
];

// ---------------------------------------------------- filters

fn text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    &src[node.byte_range()]
}

fn string_content<'s>(string: Node, src: &'s [u8]) -> &'s [u8] {
    let t = text(string, src);
    t.get(1..t.len().saturating_sub(1)).unwrap_or(b"")
}

fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The first node below `node` that satisfies `pred`, not looking inside
/// nested non-arrow functions. Iterative, like every tree walk in sonda.
fn find_below<'t>(node: Node<'t>, pred: impl Fn(Node<'t>) -> bool) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            return Some(n);
        }
        let own_scope = matches!(
            n.kind(),
            "function_declaration"
                | "function_expression"
                | "function"
                | "class_declaration"
                | "method_definition"
                | "generator_function_declaration"
                | "class"
        );
        if !own_scope && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

/// Whether an object literal has a property named `key`.
fn object_has_key(object: Node, key: &str, src: &[u8]) -> bool {
    let mut cursor = object.walk();
    object.named_children(&mut cursor).any(|member| {
        let name = match member.kind() {
            "pair" => member.child_by_field_name("key"),
            "shorthand_property_identifier" => Some(member),
            // A spread may supply anything.
            "spread_element" => return true,
            _ => None,
        };
        name.is_some_and(|n| {
            text(n, src) == key.as_bytes() || string_content(n, src) == key.as_bytes()
        })
    })
}

fn first_argument(call: Node) -> Option<Node> {
    call.child_by_field_name("arguments")?.named_child(0)
}

/// Whether the call sits inside an `if` whose condition mentions the
/// environment, or inside a function that is only called conditionally.
fn not_guarded_by_environment(call: Node, src: &[u8]) -> bool {
    let mut parent = call.parent();
    while let Some(p) = parent {
        if matches!(p.kind(), "if_statement" | "ternary_expression") {
            let condition = p.child_by_field_name("condition");
            if condition.is_some_and(|c| {
                contains_ignoring_case(text(c, src), b"env")
                    || contains_ignoring_case(text(c, src), b"production")
            }) {
                return false;
            }
        }
        parent = p.parent();
    }
    true
}

fn ignores_mutating_methods(pair: Node, src: &[u8]) -> bool {
    let Some(list) = pair.child_by_field_name("value") else {
        return false;
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor).any(|item| {
        item.kind() == "string"
            && [&b"POST"[..], b"PUT", b"PATCH", b"DELETE"]
                .iter()
                .any(|m| string_content(item, src).eq_ignore_ascii_case(m))
    })
}

fn upload_without_limit(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let wanted = if text(function, src) == b"multer" {
        "limits"
    } else {
        "maxFileSize"
    };
    match first_argument(call) {
        None => true,
        Some(options) if options.kind() == "object" => !object_has_key(options, wanted, src),
        // A variable may carry the limit: not provable here.
        Some(_) => false,
    }
}

fn first_argument_is_built(call: Node, _: &[u8]) -> bool {
    first_argument(call).is_some_and(|arg| match arg.kind() {
        "binary_expression" => {
            arg.child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "+")
                && !is_all_literals(arg)
        }
        "template_string" => {
            let mut cursor = arg.walk();
            arg.named_children(&mut cursor)
                .any(|c| c.kind() == "template_substitution")
        }
        _ => false,
    })
}

fn is_all_literals(expr: Node) -> bool {
    match expr.kind() {
        "string" | "number" => true,
        "binary_expression" => {
            expr.child_by_field_name("left")
                .is_some_and(is_all_literals)
                && expr
                    .child_by_field_name("right")
                    .is_some_and(is_all_literals)
        }
        _ => false,
    }
}

fn express_app_announces_itself(call: Node, src: &[u8]) -> bool {
    if call
        .child_by_field_name("arguments")
        .is_none_or(|a| a.named_child_count() != 0)
    {
        return false;
    }
    !(contains_ignoring_case(src, b"x-powered-by")
        || contains_ignoring_case(src, b"helmet")
        || contains_ignoring_case(src, b"hidePoweredBy"))
}

fn is_public_cleartext_url(string: Node, src: &[u8]) -> bool {
    let body = string_content(string, src);
    let Some(rest) = body
        .windows(3)
        .position(|w| w == b"://")
        .map(|i| &body[i + 3..])
    else {
        return false;
    };
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b':' | b'?' | b'#' | b'\\'))
        .unwrap_or(rest.len());
    let host = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
    if host.is_empty() || host.contains(['$', '{', '%', '<', '[', '@', ' ']) {
        return false;
    }
    !(is_private_host(&host) || is_namespace_host(&host))
}

fn is_private_host(host: &str) -> bool {
    if matches!(host, "localhost" | "0.0.0.0") {
        return true;
    }
    if [
        ".local",
        ".localhost",
        ".test",
        ".example",
        ".invalid",
        ".internal",
        ".lan",
    ]
    .iter()
    .any(|suffix| host.ends_with(suffix))
    {
        return true;
    }
    if matches!(
        host,
        "example.com" | "example.org" | "example.net" | "www.example.com" | "www.example.org"
    ) {
        return true;
    }
    let octets: Vec<u8> = host.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 || host.split('.').count() != 4 {
        // Single-label names (docker service names, hosts file entries).
        return !host.contains('.');
    }
    matches!(octets[0], 10 | 127)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
}

/// Hosts that appear as XML or schema namespace identifiers, not as
/// endpoints anyone connects to.
fn is_namespace_host(host: &str) -> bool {
    host.ends_with("w3.org")
        || host.ends_with("xmlsoap.org")
        || host.ends_with("openxmlformats.org")
        || host.ends_with("purl.org")
        || host.ends_with("json-schema.org")
        || host.ends_with("schema.org")
        || host.ends_with("sun.com")
        || host.starts_with("schemas.")
        || host.starts_with("xmlns")
        || host.starts_with("ns.")
}

const SECRET_WORDS: &[&[u8]] = &[
    b"token",
    b"secret",
    b"password",
    b"passwd",
    b"session",
    b"nonce",
    b"salt",
    b"otp",
    b"csrf",
    b"apikey",
    b"api_key",
    b"sessionid",
];

fn random_feeds_a_secret(call: Node, src: &[u8]) -> bool {
    let mut context = call.parent();
    while let Some(n) = context {
        if matches!(
            n.kind(),
            "lexical_declaration"
                | "variable_declaration"
                | "expression_statement"
                | "return_statement"
        ) {
            break;
        }
        context = n.parent();
    }
    let Some(statement) = context else {
        return false;
    };
    let mentions = |haystack: &[u8]| {
        SECRET_WORDS
            .iter()
            .any(|w| contains_ignoring_case(haystack, w))
    };
    if mentions(text(statement, src)) {
        return true;
    }
    // `return Math.random()...` inside `function generateToken()`.
    let mut owner = statement.parent();
    while let Some(n) = owner {
        if matches!(
            n.kind(),
            "function_declaration" | "method_definition" | "function_expression"
        ) {
            return n
                .child_by_field_name("name")
                .is_some_and(|name| mentions(text(name, src)));
        }
        owner = n.parent();
    }
    false
}

fn this_in_component<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = function.child_by_field_name("body")?;
    let returns_jsx = find_below(body, |n| {
        matches!(
            n.kind(),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
        )
    })
    .is_some();
    if !returns_jsx {
        return None;
    }
    find_below(body, |n| n.kind() == "this")
}

fn table_without_headers(table: Node, src: &[u8]) -> bool {
    let tag = |n: Node| -> Option<&[u8]> {
        match n.kind() {
            "jsx_opening_element" | "jsx_self_closing_element" => {
                n.child_by_field_name("name").map(|name| text(name, src))
            }
            _ => None,
        }
    };
    let opening = table.child_by_field_name("open_tag");
    if opening.is_some_and(|o| {
        contains_ignoring_case(text(o, src), b"presentation")
            || contains_ignoring_case(text(o, src), b"role=\"none\"")
    }) {
        return false;
    }
    // Anything that could render a header we can't see counts as having one.
    let may_have_headers = |n: Node| {
        if n.kind() == "jsx_expression" && n.parent().is_some_and(|p| p.kind() == "jsx_element") {
            return true;
        }
        tag(n).is_some_and(|name| {
            name == b"th"
                || name.first().is_some_and(u8::is_ascii_uppercase)
                || name.contains(&b'.')
        })
    };
    let mut cursor = table.walk();
    if table
        .children(&mut cursor)
        .any(|c| c.kind() == "jsx_expression")
    {
        return false;
    }
    !contains_any(table, may_have_headers)
}

/// Whether any node below `node` satisfies `pred`, looking inside functions
/// too (a table's rows are often built in a callback).
fn contains_any<'t>(node: Node<'t>, pred: impl Fn(Node<'t>) -> bool) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        if pred(cursor.node()) {
            return true;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return false;
            }
        }
    }
}

fn size_over_eight_megabytes(pair: Node, src: &[u8]) -> bool {
    pair.child_by_field_name("value").is_some_and(|v| {
        let digits: String = String::from_utf8_lossy(text(v, src)).replace('_', "");
        digits.parse::<f64>().is_ok_and(|n| n > 8_000_000.0)
    })
}

// ---- AWS CDK constructs

/// The props a CDK construct is created with: `new X(scope, id, props)`.
enum Props<'t> {
    Absent,
    /// A variable or call: can't tell what it holds.
    Unknown,
    Object(Node<'t>),
}

fn construct_props(construct: Node) -> Props {
    let Some(args) = construct.child_by_field_name("arguments") else {
        return Props::Absent;
    };
    match args.named_child(2) {
        None => Props::Absent,
        Some(o) if o.kind() == "object" && !object_has_spread(o) => Props::Object(o),
        Some(_) => Props::Unknown,
    }
}

fn object_has_spread(object: Node) -> bool {
    let mut cursor = object.walk();
    object
        .named_children(&mut cursor)
        .any(|m| m.kind() == "spread_element")
}

fn pair_value<'t>(object: Node<'t>, key: &str, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = object.walk();
    object.named_children(&mut cursor).find_map(|member| {
        let name = member
            .child_by_field_name("key")
            .filter(|_| member.kind() == "pair")?;
        (text(name, src) == key.as_bytes() || string_content(name, src) == key.as_bytes())
            .then(|| member.child_by_field_name("value"))
            .flatten()
    })
}

/// The class a `new` expression creates, without its namespace.
fn constructed_class<'a>(construct: Node, src: &'a [u8]) -> &'a [u8] {
    let Some(name) = construct.child_by_field_name("constructor") else {
        return b"";
    };
    match name.kind() {
        "member_expression" => name
            .child_by_field_name("property")
            .map_or(&b""[..], |p| text(p, src)),
        _ => text(name, src),
    }
}

/// Only files that use the AWS CDK: `Bucket` and `Topic` are common names.
fn uses_cdk(src: &[u8]) -> bool {
    contains_ignoring_case(src, b"aws-cdk")
}

/// Whether the construct lacks every one of `keys` set to something other
/// than `false`. Props that can't be read (a variable, a spread) are
/// assumed fine.
fn lacks_any_of(construct: Node, src: &[u8], keys: &[&str]) -> bool {
    uses_cdk(src)
        && match construct_props(construct) {
            Props::Absent => true,
            Props::Unknown => false,
            Props::Object(o) => !keys
                .iter()
                .any(|k| pair_value(o, k, src).is_some_and(|v| text(v, src) != b"false")),
        }
}

fn lacks_enforce_ssl(n: Node, src: &[u8]) -> bool {
    uses_cdk(src) && lacks_true(n, src, "enforceSSL")
}

fn lacks_true(construct: Node, src: &[u8], key: &str) -> bool {
    match construct_props(construct) {
        Props::Absent => true,
        Props::Unknown => false,
        Props::Object(o) => pair_value(o, key, src).is_none_or(|v| text(v, src) != b"true"),
    }
}

fn lacks_versioned(n: Node, src: &[u8]) -> bool {
    uses_cdk(src) && lacks_true(n, src, "versioned")
}

fn lacks_encrypted(n: Node, src: &[u8]) -> bool {
    uses_cdk(src) && lacks_true(n, src, "encrypted")
}

fn lacks_storage_encrypted(n: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && lacks_true(n, src, "storageEncrypted")
        && lacks_any_of(n, src, &["storageEncryptionKey", "kmsKeyId"])
}

fn lacks_kms_key_id(n: Node, src: &[u8]) -> bool {
    lacks_any_of(n, src, &["kmsKeyId"])
}

fn bucket_is_public(bucket: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && matches!(construct_props(bucket), Props::Object(o)
        if pair_value(o, "publicReadAccess", src).is_some_and(|v| text(v, src) == b"true")
            || pair_value(o, "accessControl", src).is_some_and(|v| {
                let t = text(v, src);
                contains_ignoring_case(t, b"PUBLIC_READ") || contains_ignoring_case(t, b"AUTHENTICATED_READ")
            }))
}

fn bucket_public_access_not_blocked(bucket: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && match construct_props(bucket) {
            Props::Absent => true,
            Props::Unknown => false,
            Props::Object(o) => pair_value(o, "blockPublicAccess", src).is_none_or(|v| {
                let t = text(v, src);
                contains_ignoring_case(t, b"false") || contains_ignoring_case(t, b"BLOCK_ACLS")
            }),
        }
}

fn search_domain_not_encrypted(domain: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && match construct_props(domain) {
            Props::Absent => true,
            Props::Unknown => false,
            Props::Object(o) => {
                match pair_value(o, "encryptionAtRest", src)
                    .or_else(|| pair_value(o, "encryptionAtRestOptions", src))
                {
                    None => true,
                    Some(v) => {
                        v.kind() == "object"
                            && pair_value(v, "enabled", src)
                                .is_some_and(|e| text(e, src) == b"false")
                    }
                }
            }
        }
}

fn topic_not_encrypted(topic: Node, src: &[u8]) -> bool {
    lacks_any_of(topic, src, &["masterKey", "kmsMasterKeyId"])
}

/// `Queue` is encrypted with SQS-managed keys unless told otherwise; only
/// the low-level `CfnQueue` leaves encryption off by default.
fn queue_not_encrypted(queue: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    if constructed_class(queue, src) == b"CfnQueue" {
        return lacks_any_of(queue, src, &["kmsMasterKeyId", "sqsManagedSseEnabled"]);
    }
    matches!(construct_props(queue), Props::Object(o)
        if pair_value(o, "encryption", src)
            .is_some_and(|v| contains_ignoring_case(text(v, src), b"UNENCRYPTED")))
}

/// `FileSystem` is encrypted by default in current CDK versions; only
/// `CfnFileSystem` needs the flag.
fn file_system_not_encrypted(fs: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    if constructed_class(fs, src) == b"CfnFileSystem" {
        return lacks_true(fs, src, "encrypted");
    }
    matches!(construct_props(fs), Props::Object(o)
        if pair_value(o, "encrypted", src).is_some_and(|v| text(v, src) == b"false"))
}

fn authorization_is_none(pair: Node, src: &[u8]) -> bool {
    pair.child_by_field_name("value").is_some_and(|v| {
        let t = text(v, src);
        t.ends_with(b"NONE") || t.ends_with(b"NONE'") || t.ends_with(b"NONE\"")
    })
}

fn opens_admin_port_to_world(call: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let (Some(peer), Some(port)) = (args.named_child(0), args.named_child(1)) else {
        return false;
    };
    let peer = text(peer, src);
    let port = text(port, src);
    let world = contains_ignoring_case(peer, b"anyIpv4")
        || contains_ignoring_case(peer, b"anyIpv6")
        || peer.windows(9).any(|w| w == b"0.0.0.0/0")
        || peer.windows(4).any(|w| w == b"::/0");
    world
        && [&b"tcp(22)"[..], b"tcp(3389)", b"allTraffic", b"allTcp"]
            .iter()
            .any(|p| contains_ignoring_case(port, p))
}

fn grants_all_actions(pair: Node, src: &[u8]) -> bool {
    let Some(value) = pair.child_by_field_name("value") else {
        return false;
    };
    let wildcard = |n: Node| n.kind() == "string" && string_content(n, src) == b"*";
    let grants = if value.kind() == "array" {
        let mut cursor = value.walk();
        value.named_children(&mut cursor).any(wildcard)
    } else {
        wildcard(value)
    };
    // A deny statement with '*' is the opposite of a problem.
    let denies = pair.parent().is_some_and(|o| {
        let mut cursor = o.walk();
        o.named_children(&mut cursor).any(|m| {
            m.kind() == "pair"
                && m.child_by_field_name("key")
                    .is_some_and(|k| text(k, src).eq_ignore_ascii_case(b"effect"))
                && contains_ignoring_case(text(m, src), b"deny")
        })
    });
    grants && !denies
}

fn principal_is_everyone(principal: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    match constructed_class(principal, src) {
        b"AnyPrincipal" | b"StarPrincipal" => true,
        _ => first_argument(principal)
            .is_some_and(|a| a.kind() == "string" && string_content(a, src) == b"*"),
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, lang: Lang, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", lang, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    const JS: Lang = Lang::JavaScript;

    #[test]
    fn error_handler_guarded_by_environment() {
        let src = "app.use(errorhandler());\nif (env === 'production') { x(); } else { app.use(errorhandler()); }";
        assert_eq!(flagged("js/error-handler-middleware", JS, src), [1]);
    }

    #[test]
    fn upload_limits() {
        let src = "multer();\nmulter({ storage });\nmulter({ limits });\nmulter(opts);\nformidable({ maxFileSize: 1 });\nformidable({ uploadDir });";
        assert_eq!(flagged("js/upload-without-limit", JS, src), [1, 2, 6]);
    }

    #[test]
    fn dynamic_templates_need_data_in_the_source() {
        let src = "ejs.render(`<p>${name}</p>`, d);\nejs.render('<p>' + 'x' + '</p>', d);\nejs.render(tpl, d);\n_.template('a' + b);\nres.render('v' + b);";
        assert_eq!(flagged("js/template-built-dynamically", JS, src), [1, 4]);
    }

    #[test]
    fn cleartext_urls_skip_private_and_namespace_hosts() {
        let src = "a('http://example-shop.io/x');\nb('http://localhost:3000');\nc('http://192.168.1.62/rpc');\nd('http://www.w3.org/2000/svg');\ne('ftp://files.corp.io');\nf('http://${host}/');\ng('http://myservice:8080');\nh('https://ok.io');";
        assert_eq!(flagged("js/cleartext-url", JS, src), [1, 5]);
    }

    #[test]
    fn random_only_matters_for_secrets() {
        let src = "const token = Math.random();\nconst x = Math.random() * 3;\nfunction makeSessionId() { return Math.random().toString(); }\nfunction pick() { return Math.random(); }";
        assert_eq!(flagged("js/math-random-secret", JS, src), [1, 3]);
    }

    #[test]
    fn components_only() {
        let src = "function Panel() { return <p>{this.state.a}</p>; }\nfunction helper() { return this.x; }\nfunction Plain() { return this.x; }\nfunction Fine(p) { const f = function () { return this; }; return <p>{p.a}</p>; }\nfunction Chart(p) { const o = { formatter() { return this.value; } }; return <c o={o} />; }";
        assert_eq!(flagged("js/this-in-function-component", JS, src), [1]);
    }

    #[test]
    fn tables_with_dynamic_content_are_left_alone() {
        let src = "const a = <table><tr><td>1</td></tr></table>;\nconst b = <table>{rows}</table>;\nconst c = <table><Header /><tr><td>1</td></tr></table>;\nconst d = <table role=\"presentation\"><tr><td>1</td></tr></table>;\nconst e = <table><tr><th>x</th></tr></table>;";
        assert_eq!(flagged("js/table-without-headers", JS, src), [1]);
    }

    #[test]
    fn size_limits() {
        let src = "a({ fileSize: 8_000_000 });\nb({ fileSize: 8_000_001 });\nc({ maxFileSize: 1e9 });\nd({ fileSize: limit });";
        assert_eq!(flagged("js/upload-size-too-large", JS, src), [2, 3]);
    }

    const TS: Lang = Lang::TypeScript;

    #[test]
    fn cdk_buckets() {
        let src = "import { Bucket } from 'aws-cdk-lib/aws-s3';
new s3.Bucket(this, 'a');
new s3.Bucket(this, 'b', { enforceSSL: true, versioned: true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });
new s3.Bucket(this, 'c', props);
new s3.Bucket(this, 'd', { ...base });
new Bucket(this, 'e', { publicReadAccess: true });
new s3.Bucket(this, 'f', { accessControl: s3.BucketAccessControl.PUBLIC_READ });
new s3.Bucket(this, 'g', { blockPublicAccess: new s3.BlockPublicAccess({ blockPublicAcls: false }) });";
        assert_eq!(
            flagged("cdk/bucket-allows-plain-http", TS, src),
            [2, 6, 7, 8]
        );
        assert_eq!(
            flagged("cdk/bucket-without-versioning", TS, src),
            [2, 6, 7, 8]
        );
        assert_eq!(flagged("cdk/bucket-public-access", TS, src), [6, 7]);
        assert_eq!(
            flagged("cdk/bucket-public-access-not-blocked", TS, src),
            [2, 6, 7, 8]
        );
    }

    #[test]
    fn cdk_rules_skip_files_without_the_cdk() {
        let src = "const b = new Bucket(this, 'a', { publicReadAccess: true });\nnew Topic(1, 2);";
        assert!(flagged("cdk/bucket-public-access", TS, src).is_empty());
        assert!(flagged("cdk/topic-not-encrypted", TS, src).is_empty());
    }

    #[test]
    fn cdk_defaults_that_are_already_safe() {
        let src = "import 'aws-cdk-lib';
new sqs.Queue(this, 'a');
new sqs.Queue(this, 'b', { encryption: sqs.QueueEncryption.UNENCRYPTED });
new sqs.CfnQueue(this, 'c', {});
new efs.FileSystem(this, 'd', { vpc });
new efs.CfnFileSystem(this, 'e', {});
new efs.FileSystem(this, 'f', { encrypted: false });";
        assert_eq!(flagged("cdk/queue-not-encrypted", TS, src), [3, 4]);
        assert_eq!(flagged("cdk/file-system-not-encrypted", TS, src), [6, 7]);
    }

    #[test]
    fn cdk_databases_and_search() {
        let src = "import 'aws-cdk-lib';
new rds.DatabaseInstance(this, 'a', { engine });
new rds.DatabaseInstance(this, 'b', { engine, storageEncrypted: true });
new rds.DatabaseCluster(this, 'c', { engine, storageEncryptionKey: key });
new opensearch.Domain(this, 'd', { version });
new opensearch.Domain(this, 'e', { encryptionAtRest: { enabled: true } });
new opensearch.Domain(this, 'f', { encryptionAtRest: { enabled: false } });";
        assert_eq!(flagged("cdk/database-not-encrypted", TS, src), [2]);
        assert_eq!(flagged("cdk/search-domain-not-encrypted", TS, src), [5, 7]);
    }

    #[test]
    fn cdk_network_and_policies() {
        let src = "import 'aws-cdk-lib';
sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));
sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443));
sg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(22));
new iam.PolicyStatement({ actions: ['*'], resources: [a] });
new iam.PolicyStatement({ effect: iam.Effect.DENY, actions: ['*'], resources: [a] });
new iam.PolicyStatement({ actions: ['s3:*'], resources: [a] });
new iam.PolicyStatement({ principals: [new iam.AnyPrincipal()] });
new iam.ArnPrincipal('*');
new iam.ArnPrincipal(arn);
const m = { authorizationType: AuthorizationType.NONE, b: { authorizationType: 'NONE' }, c: { authorizationType: AuthorizationType.IAM } };";
        assert_eq!(flagged("cdk/admin-port-open-to-world", TS, src), [2]);
        assert_eq!(flagged("cdk/policy-grants-everything", TS, src), [5]);
        assert_eq!(flagged("cdk/policy-for-everyone", TS, src), [8, 9]);
        assert_eq!(flagged("cdk/api-method-without-auth", TS, src), [11, 11]);
    }
}
