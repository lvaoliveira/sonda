//! AWS CDK and Lambda Python rules (ADR-0007, batch 15). The CDK checks
//! mirror `js_security.rs`: the props are keyword arguments here.

use super::py_more::{body_of, first_parameter_name, name_of, receiver_text};
use super::py_quality::{SCOPE_STOPS, find_in_scope, has_token, nearest_function, statements};
use super::py_security::{
    call_arguments, callee_name, contains_ignoring_case, keyword_value, string_value, text,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/cdk-bucket-plain-http",
        name: "S3 buckets should enforce HTTPS-only access",
        description: "Without a policy that denies plain HTTP, requests can travel unencrypted.",
        message: "Set enforce_ssl=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6249")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Bucket")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Bucket"))) @match"#,
            filter: Some(Keep(bucket_allows_plain_http)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nb = s3.Bucket(self, 'Data', versioned=True)\n",
            good: "import aws_cdk\nb = s3.Bucket(self, 'Data', enforce_ssl=True)\n",
        }),
    },
    Rule {
        id: "py/cdk-bucket-unversioned",
        name: "Amazon S3 buckets should have versioning enabled",
        description: "Without versioning an overwrite or delete cannot be undone.",
        message: "Set versioned=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6252")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Bucket")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Bucket"))) @match"#,
            filter: Some(Keep(bucket_is_unversioned)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nb = s3.Bucket(self, 'Data', enforce_ssl=True)\n",
            good: "import aws_cdk\nb = s3.Bucket(self, 'Data', versioned=True)\n",
        }),
    },
    Rule {
        id: "py/cdk-bucket-public",
        name: "S3 buckets should not grant access to all users or authenticated users",
        description: "A public bucket exposes its objects to the whole internet.",
        message: "Remove the public access.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6265")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Bucket")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Bucket"))) @match"#,
            filter: Some(Keep(bucket_is_public)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nb = s3.Bucket(self, 'Site', public_read_access=True)\n",
            good: "import aws_cdk\nb = s3.Bucket(self, 'Site')\n",
        }),
    },
    Rule {
        id: "py/cdk-bucket-public-access-not-blocked",
        name: "Amazon S3 bucket public access should be fully blocked",
        description: "Without a block, a later policy or ACL can still make objects public.",
        message: "Set block_public_access=BlockPublicAccess.BLOCK_ALL.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6281")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Bucket")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Bucket"))) @match"#,
            filter: Some(Keep(bucket_public_access_not_blocked)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nb = s3.Bucket(self, 'Data', versioned=True)\n",
            good: "import aws_cdk\nb = s3.Bucket(self, 'Data', block_public_access=s3.BlockPublicAccess.BLOCK_ALL)\n",
        }),
    },
    Rule {
        id: "py/cdk-policy-for-everyone",
        name: "AWS resource-based policies should not grant public access",
        description: "A policy for every principal lets anyone use the resource.",
        message: "Name the principals.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6270")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "AnyPrincipal" "StarPrincipal" "ArnPrincipal")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "AnyPrincipal" "StarPrincipal" "ArnPrincipal"))) @match"#,
            filter: Some(Keep(principal_is_everyone)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\ns = iam.PolicyStatement(principals=[iam.AnyPrincipal()], actions=a)\n",
            good: "import aws_cdk\ns = iam.PolicyStatement(principals=[iam.AccountRootPrincipal()], actions=a)\n",
        }),
    },
    Rule {
        id: "py/cdk-policy-grants-everything",
        name: "Policies should not grant all privileges",
        description: "An action of * allows every operation on the resource.",
        message: "List the actions needed.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6302")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "actions") value: [(list) (string)] @v) @match"#,
            filter: Some(Keep(grants_all_actions)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\ns = iam.PolicyStatement(actions=['*'], resources=[arn])\n",
            good: "import aws_cdk\ns = iam.PolicyStatement(actions=['s3:GetObject'], resources=[arn])\n",
        }),
    },
    Rule {
        id: "py/cdk-policy-all-resources",
        name: "IAM policies should not grant access to all account resources",
        description: "A resource of * covers every resource in the account.",
        message: "Name the resources.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6304")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "resources") value: [(list) (string)] @v) @match"#,
            filter: Some(Keep(grants_all_resources)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\ns = iam.PolicyStatement(actions=['s3:GetObject'], resources=['*'])\n",
            good: "import aws_cdk\ns = iam.PolicyStatement(actions=['s3:GetObject'], resources=[arn])\n",
        }),
    },
    Rule {
        id: "py/cdk-policy-privilege-escalation",
        name: "AWS IAM policies should limit the scope of permissions given",
        description: "These actions let a principal grant itself more access.",
        message: "Drop the action or scope it tightly.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S6317")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "actions") value: [(list) (string)] @v) @match"#,
            filter: Some(Keep(allows_privilege_escalation)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\ns = iam.PolicyStatement(actions=['iam:PassRole'], resources=['*'])\n",
            good: "import aws_cdk\ns = iam.PolicyStatement(actions=['s3:GetObject'], resources=['*'])\n",
        }),
    },
    Rule {
        id: "py/cdk-volume-unencrypted",
        name: "EBS volumes should be encrypted",
        description: "An unencrypted volume exposes data if a snapshot or disk leaks.",
        message: "Set encrypted=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6275")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Volume" "CfnVolume")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Volume" "CfnVolume"))) @match"#,
            filter: Some(Keep(volume_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nv = ec2.Volume(self, 'Disk', size=Size.gibibytes(10))\n",
            good: "import aws_cdk\nv = ec2.Volume(self, 'Disk', size=Size.gibibytes(10), encrypted=True)\n",
        }),
    },
    Rule {
        id: "py/cdk-database-unencrypted",
        name: "Amazon RDS resources should be encrypted at rest",
        description: "An unencrypted database exposes data if storage leaks.",
        message: "Set storage_encrypted=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6303")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "DatabaseInstance" "DatabaseCluster" "CfnDBInstance" "CfnDBCluster")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "DatabaseInstance" "DatabaseCluster" "CfnDBInstance" "CfnDBCluster"))) @match"#,
            filter: Some(Keep(database_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nd = rds.DatabaseInstance(self, 'Db', engine=e)\n",
            good: "import aws_cdk\nd = rds.DatabaseInstance(self, 'Db', engine=e, storage_encrypted=True)\n",
        }),
    },
    Rule {
        id: "py/cdk-search-unencrypted",
        name: "OpenSearch domains should have encryption at rest enabled",
        description: "An unencrypted domain exposes data if storage leaks.",
        message: "Enable encryption_at_rest.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6308")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Domain" "CfnDomain")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Domain" "CfnDomain"))) @match"#,
            filter: Some(Keep(search_domain_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nd = opensearch.Domain(self, 'Search', version=v)\n",
            good: "import aws_cdk\nd = opensearch.Domain(self, 'Search', version=v, encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True))\n",
        }),
    },
    Rule {
        id: "py/cdk-notebook-unencrypted",
        name: "SageMaker notebook instances should be encrypted at rest",
        description: "The notebook volume holds datasets and models.",
        message: "Set kms_key_id.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6319")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "CfnNotebookInstance")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "CfnNotebookInstance"))) @match"#,
            filter: Some(Keep(lacks_kms_key_id)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nn = sagemaker.CfnNotebookInstance(self, 'Nb', instance_type=t, role_arn=r)\n",
            good: "import aws_cdk\nn = sagemaker.CfnNotebookInstance(self, 'Nb', instance_type=t, role_arn=r, kms_key_id=k)\n",
        }),
    },
    Rule {
        id: "py/cdk-admin-port-open",
        name: "Administration services access should be restricted to specific IP addresses",
        description: "SSH or RDP open to the world invites brute force.",
        message: "Restrict the source range.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6321")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "add_ingress_rule"))) @match"#,
            filter: Some(Keep(opens_admin_port_to_world)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nsg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))\n",
            good: "import aws_cdk\nsg.add_ingress_rule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(22))\n",
        }),
    },
    Rule {
        id: "py/cdk-topic-unencrypted",
        name: "Amazon SNS topics should be encrypted at rest",
        description: "Messages are stored unencrypted otherwise.",
        message: "Set master_key.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6327")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Topic" "CfnTopic")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Topic" "CfnTopic"))) @match"#,
            filter: Some(Keep(topic_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nt = sns.Topic(self, 'Events')\n",
            good: "import aws_cdk\nt = sns.Topic(self, 'Events', master_key=key)\n",
        }),
    },
    Rule {
        id: "py/cdk-publicly-accessible",
        name: "Public network access to cloud resources should be disabled",
        description: "A public database or cluster is reachable from the internet.",
        message: "Set publicly_accessible=False.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6329")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "publicly_accessible") value: (true)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nd = rds.CfnDBInstance(self, 'Db', publicly_accessible=True)\n",
            good: "import aws_cdk\nd = rds.CfnDBInstance(self, 'Db', publicly_accessible=False)\n",
        }),
    },
    Rule {
        id: "py/cdk-queue-unencrypted",
        name: "SQS queues should be encrypted",
        description: "Messages are stored unencrypted otherwise.",
        message: "Enable encryption.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6330")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "Queue" "CfnQueue")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "Queue" "CfnQueue"))) @match"#,
            filter: Some(Keep(queue_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nq = sqs.Queue(self, 'Jobs', encryption=sqs.QueueEncryption.UNENCRYPTED)\n",
            good: "import aws_cdk\nq = sqs.Queue(self, 'Jobs')\n",
        }),
    },
    Rule {
        id: "py/cdk-filesystem-unencrypted",
        name: "Amazon EFS file systems should be encrypted",
        description: "An unencrypted file system exposes data if storage leaks.",
        message: "Set encrypted=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6332")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @c (#any-of? @c "FileSystem" "CfnFileSystem")) @match
(call function: (attribute attribute: (identifier) @c (#any-of? @c "FileSystem" "CfnFileSystem"))) @match"#,
            filter: Some(Keep(file_system_is_unencrypted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nf = efs.FileSystem(self, 'Fs', vpc=vpc, encrypted=False)\n",
            good: "import aws_cdk\nf = efs.FileSystem(self, 'Fs', vpc=vpc)\n",
        }),
    },
    Rule {
        id: "py/cdk-api-method-no-auth",
        name: "AWS API Gateway should require authentication",
        description: "A method without authorization is callable by anyone.",
        message: "Require an authorizer.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6333")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "authorization_type")) @match"#,
            filter: Some(Keep(authorization_is_none)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\napi.root.add_method('GET', i, authorization_type=apigateway.AuthorizationType.NONE)\n",
            good: "import aws_cdk\napi.root.add_method('GET', i, authorization_type=apigateway.AuthorizationType.IAM)\n",
        }),
    },
    Rule {
        id: "py/cdk-unrestricted-outbound",
        name: "Security groups should not allow unrestricted outbound traffic",
        description: "A compromised host can reach any destination.",
        message: "Set allow_all_outbound=False.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6463")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @k (#eq? @k "allow_all_outbound") value: (true)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import aws_cdk\nsg = ec2.SecurityGroup(self, 'Sg', vpc=vpc, allow_all_outbound=True)\n",
            good: "import aws_cdk\nsg = ec2.SecurityGroup(self, 'Sg', vpc=vpc, allow_all_outbound=False)\n",
        }),
    },
    Rule {
        id: "py/lambda-async-handler",
        name: "AWS Lambda handlers must not be an async function",
        description: "The runtime calls the handler without an event loop, so it never runs.",
        message: "Make it a plain function.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7614")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(handler_is_async)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def lambda_handler(event, context):\n    return {}\n",
            good: "def lambda_handler(event, context):\n    return {}\n",
        }),
    },
    Rule {
        id: "py/lambda-client-in-handler",
        name: "Reusable resources should be initialized at construction time of Lambda functions",
        description: "Creating a client on every invocation wastes the warm start.",
        message: "Create it at module level.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6243")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(handler_creates_a_client)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def lambda_handler(event, context):\n    s3 = boto3.client('s3')\n    return {}\n",
            good: "s3 = boto3.client('s3')\ndef lambda_handler(event, context):\n    return {}\n",
        }),
    },
    Rule {
        id: "py/lambda-reserved-variable",
        name: "Reserved environment variable names should not be overridden in Lambda functions",
        description: "The runtime sets these, and overriding them breaks it.",
        message: "Use another name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7617")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (subscript value: (attribute) @o subscript: (string) @match)) @decl"#,
            filter: Some(Keep(sets_a_reserved_variable)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import os\nos.environ['AWS_REGION'] = 'x'\n",
            good: "import os\nos.environ['APP_REGION'] = 'x'\n",
        }),
    },
    Rule {
        id: "py/lambda-request-timeout",
        name: "Network calls in AWS Lambda functions shouldn't be made without explicit timeout parameters",
        description: "A hung call burns the whole invocation budget.",
        message: "Pass timeout.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7618")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(handler_calls_without_timeout)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def lambda_handler(event, context):\n    r = requests.get(url)\n",
            good: "def lambda_handler(event, context):\n    r = requests.get(url, timeout=5)\n",
        }),
    },
    Rule {
        id: "py/cloudwatch-reserved-namespace",
        name: "AWS CloudWatch metrics namespace should not begin with AWS/",
        description: "That prefix is reserved for AWS services.",
        message: "Pick another namespace.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7609")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "Namespace") value: (string) @match)"#,
            filter: Some(Keep(namespace_is_reserved)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "cw.put_metric_data(Namespace='AWS/Custom', MetricData=[])\n",
            good: "cw.put_metric_data(Namespace='App/Custom', MetricData=[])\n",
        }),
    },
    Rule {
        id: "py/s3-bucket-owner",
        name: "S3 operations should verify bucket ownership using ExpectedBucketOwner parameter",
        description: "Without it a request can reach another account's bucket with the same name.",
        message: "Pass ExpectedBucketOwner.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7608")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "get_object" "put_object" "delete_object" "list_objects_v2" "list_objects" "head_object" "upload_file" "download_file" "copy_object"))) @match"#,
            filter: Some(Keep(s3_call_lacks_owner)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s3.get_object(Bucket='b', Key='k')\n",
            good: "s3.get_object(Bucket='b', Key='k', ExpectedBucketOwner=acct)\n",
        }),
    },
    Rule {
        id: "py/lambda-sync-invoke",
        name: "Lambdas should not invoke other lambdas synchronously",
        description: "The caller pays for the callee's whole run time.",
        message: "Invoke with InvocationType='Event', or use a queue.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6246")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "invoke"))) @match"#,
            filter: Some(Keep(invoke_is_synchronous)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def lambda_handler(event, context):\n    lambda_client.invoke(FunctionName='f', Payload=b'{}')\n",
            good: "def lambda_handler(event, context):\n    lambda_client.invoke(FunctionName='f', InvocationType='Event')\n",
        }),
    },
    Rule {
        id: "py/boto-manual-pagination",
        name: "boto3 operations that support pagination should be performed using paginators",
        description: "A single call returns only the first page.",
        message: "Use get_paginator().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7622")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "list_objects_v2" "list_objects" "list_object_versions" "describe_instances" "list_users" "list_roles"))) @match"#,
            filter: Some(Keep(listing_ignores_pagination)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "r = s3.list_objects_v2(Bucket='b')\n",
            good: "r = s3.get_paginator('list_objects_v2').paginate(Bucket='b')\n",
        }),
    },
];

// ---------------------------------------------------- filters

/// Only files that use the AWS CDK: `Bucket` and `Topic` are common names.
fn uses_cdk(src: &[u8]) -> bool {
    contains_ignoring_case(src, b"aws_cdk") || contains_ignoring_case(src, b"aws-cdk")
}

fn has_splat(call: Node) -> bool {
    call_arguments(call)
        .iter()
        .any(|a| a.kind() == "dictionary_splat")
}

/// Whether the construct lacks `key=True`. Props that can't be read (a
/// `**kwargs` splat) are assumed fine.
fn lacks_true(call: Node, src: &[u8], key: &str) -> bool {
    uses_cdk(src)
        && !has_splat(call)
        && keyword_value(call, key, src).is_none_or(|v| text(v, src) != b"True")
}

/// Whether the construct lacks every one of `keys` set to something other
/// than `False`.
fn lacks_any_of(call: Node, src: &[u8], keys: &[&str]) -> bool {
    uses_cdk(src)
        && !has_splat(call)
        && !keys
            .iter()
            .any(|k| keyword_value(call, k, src).is_some_and(|v| text(v, src) != b"False"))
}

fn bucket_allows_plain_http(call: Node, src: &[u8]) -> bool {
    lacks_true(call, src, "enforce_ssl")
}

fn bucket_is_unversioned(call: Node, src: &[u8]) -> bool {
    lacks_true(call, src, "versioned")
}

fn bucket_is_public(call: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && (keyword_value(call, "public_read_access", src).is_some_and(|v| text(v, src) == b"True")
            || keyword_value(call, "access_control", src).is_some_and(|v| {
                let t = text(v, src);
                contains_ignoring_case(t, b"PUBLIC_READ")
                    || contains_ignoring_case(t, b"AUTHENTICATED_READ")
            }))
}

fn bucket_public_access_not_blocked(call: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && !has_splat(call)
        && keyword_value(call, "block_public_access", src).is_none_or(|v| {
            let t = text(v, src);
            contains_ignoring_case(t, b"False") || contains_ignoring_case(t, b"BLOCK_ACLS")
        })
}

fn principal_is_everyone(call: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && (matches!(callee_name(call, src), b"AnyPrincipal" | b"StarPrincipal")
            || call_arguments(call)
                .first()
                .is_some_and(|a| string_value(*a, src) == Some(b"*")))
}

fn statement_of(keyword: Node) -> Option<Node> {
    keyword.parent()?.parent().filter(|c| c.kind() == "call")
}

fn is_deny(keyword: Node, src: &[u8]) -> bool {
    statement_of(keyword).is_some_and(|c| contains_ignoring_case(text(c, src), b"Effect.DENY"))
}

fn strings_of<'s>(value: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    if value.kind() == "string" {
        return string_value(value, src).into_iter().collect();
    }
    statements(value)
        .iter()
        .filter_map(|e| string_value(*e, src))
        .collect()
}

fn keyword_strings<'s>(keyword: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    keyword
        .child_by_field_name("value")
        .map_or_else(Vec::new, |v| strings_of(v, src))
}

fn grants_all_actions(keyword: Node, src: &[u8]) -> bool {
    uses_cdk(src) && !is_deny(keyword, src) && keyword_strings(keyword, src).contains(&&b"*"[..])
}

fn grants_all_resources(keyword: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && !is_deny(keyword, src)
        && statement_of(keyword).is_some_and(|c| callee_name(c, src) == b"PolicyStatement")
        && keyword_strings(keyword, src).contains(&&b"*"[..])
}

fn allows_privilege_escalation(keyword: Node, src: &[u8]) -> bool {
    const RISKY: &[&[u8]] = &[
        b"iam:*",
        b"iam:PassRole",
        b"iam:CreateAccessKey",
        b"iam:CreateLoginProfile",
        b"iam:UpdateLoginProfile",
        b"iam:AttachUserPolicy",
        b"iam:AttachGroupPolicy",
        b"iam:AttachRolePolicy",
        b"iam:PutUserPolicy",
        b"iam:PutGroupPolicy",
        b"iam:PutRolePolicy",
        b"iam:CreatePolicyVersion",
        b"iam:SetDefaultPolicyVersion",
        b"iam:UpdateAssumeRolePolicy",
    ];
    uses_cdk(src)
        && !is_deny(keyword, src)
        && keyword_strings(keyword, src)
            .iter()
            .any(|a| RISKY.contains(a))
}

fn volume_is_unencrypted(call: Node, src: &[u8]) -> bool {
    lacks_true(call, src, "encrypted")
}

fn database_is_unencrypted(call: Node, src: &[u8]) -> bool {
    lacks_true(call, src, "storage_encrypted")
        && lacks_any_of(call, src, &["storage_encryption_key", "kms_key_id"])
}

fn search_domain_is_unencrypted(call: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && !has_splat(call)
        && keyword_value(call, "encryption_at_rest", src)
            .is_none_or(|v| contains_ignoring_case(text(v, src), b"enabled=False"))
}

fn lacks_kms_key_id(call: Node, src: &[u8]) -> bool {
    lacks_any_of(call, src, &["kms_key_id"])
}

fn opens_admin_port_to_world(call: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    let args = call_arguments(call);
    let [peer, port, ..] = args.as_slice() else {
        return false;
    };
    let (peer, port) = (text(*peer, src), text(*port, src));
    let world = contains_ignoring_case(peer, b"any_ipv4")
        || contains_ignoring_case(peer, b"any_ipv6")
        || contains_ignoring_case(peer, b"0.0.0.0/0")
        || contains_ignoring_case(peer, b"::/0");
    world
        && [&b"tcp(22)"[..], b"tcp(3389)", b"all_traffic", b"all_tcp"]
            .iter()
            .any(|p| contains_ignoring_case(port, p))
}

fn topic_is_unencrypted(call: Node, src: &[u8]) -> bool {
    lacks_any_of(call, src, &["master_key", "kms_master_key_id"])
}

/// `Queue` is encrypted with SQS-managed keys unless told otherwise; only
/// the low-level `CfnQueue` leaves encryption off by default.
fn queue_is_unencrypted(call: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    if callee_name(call, src) == b"CfnQueue" {
        return lacks_any_of(call, src, &["kms_master_key_id", "sqs_managed_sse_enabled"]);
    }
    keyword_value(call, "encryption", src)
        .is_some_and(|v| contains_ignoring_case(text(v, src), b"UNENCRYPTED"))
}

/// `FileSystem` is encrypted by default in current CDK versions; only
/// `CfnFileSystem` needs the flag.
fn file_system_is_unencrypted(call: Node, src: &[u8]) -> bool {
    if !uses_cdk(src) {
        return false;
    }
    if callee_name(call, src) == b"CfnFileSystem" {
        return lacks_true(call, src, "encrypted");
    }
    keyword_value(call, "encrypted", src).is_some_and(|v| text(v, src) == b"False")
}

fn authorization_is_none(keyword: Node, src: &[u8]) -> bool {
    uses_cdk(src)
        && keyword
            .child_by_field_name("value")
            .is_some_and(|v| text(v, src).ends_with(b"NONE"))
}

fn is_handler(function: Node, src: &[u8]) -> bool {
    matches!(name_of(function, src), b"lambda_handler" | b"handler")
        && first_parameter_name(function, src) == Some(b"event")
}

fn handler_is_async(function: Node, src: &[u8]) -> bool {
    has_token(function, "async") && is_handler(function, src)
}

fn handler_creates_a_client<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_handler(function, src) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"boto3.client" | b"boto3.resource" | b"boto3.Session"
                )
            })
    })
}

fn sets_a_reserved_variable(string: Node, src: &[u8]) -> bool {
    const RESERVED: &[&[u8]] = &[
        b"AWS_REGION",
        b"AWS_DEFAULT_REGION",
        b"AWS_EXECUTION_ENV",
        b"AWS_LAMBDA_FUNCTION_NAME",
        b"AWS_LAMBDA_FUNCTION_VERSION",
        b"AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
        b"AWS_LAMBDA_LOG_GROUP_NAME",
        b"AWS_LAMBDA_LOG_STREAM_NAME",
        b"AWS_ACCESS_KEY_ID",
        b"AWS_SECRET_ACCESS_KEY",
        b"AWS_SESSION_TOKEN",
        b"LAMBDA_TASK_ROOT",
        b"LAMBDA_RUNTIME_DIR",
        b"_HANDLER",
    ];
    string.parent().is_some_and(|s| {
        s.kind() == "subscript"
            && s.child_by_field_name("value")
                .is_some_and(|v| text(v, src) == b"os.environ")
    }) && string_value(string, src).is_some_and(|v| RESERVED.contains(&v))
}

fn handler_calls_without_timeout<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_handler(function, src) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && n.child_by_field_name("function").is_some_and(|f| {
                f.kind() == "attribute"
                    && matches!(receiver_text(n, src), b"requests" | b"httpx")
                    && matches!(
                        callee_name(n, src),
                        b"get" | b"post" | b"put" | b"delete" | b"patch" | b"head" | b"request"
                    )
            })
            && keyword_value(n, "timeout", src).is_none()
            && !has_splat(n)
    })
}

fn namespace_is_reserved(string: Node, src: &[u8]) -> bool {
    string_value(string, src).is_some_and(|v| v.starts_with(b"AWS/"))
}

fn s3_call_lacks_owner(call: Node, src: &[u8]) -> bool {
    contains_ignoring_case(receiver_text(call, src), b"s3")
        && keyword_value(call, "ExpectedBucketOwner", src).is_none()
        && !has_splat(call)
        && (keyword_value(call, "Bucket", src).is_some() || call_arguments(call).len() >= 2)
}

fn invoke_is_synchronous(call: Node, src: &[u8]) -> bool {
    nearest_function(call, 20).is_some_and(|f| is_handler(f, src))
        && contains_ignoring_case(receiver_text(call, src), b"lambda")
        && !has_splat(call)
        && keyword_value(call, "InvocationType", src)
            .is_none_or(|v| contains_ignoring_case(text(v, src), b"RequestResponse"))
}

fn listing_ignores_pagination(call: Node, src: &[u8]) -> bool {
    let scope = nearest_function(call, 20).map_or(src, |f| text(f, src));
    ![
        "NextToken",
        "ContinuationToken",
        "Marker",
        "IsTruncated",
        "paginat",
    ]
    .iter()
    .any(|w| contains_ignoring_case(scope, w.as_bytes()))
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn cdk_rules_need_the_cdk() {
        let src = "b = s3.Bucket(self, 'Data')";
        assert!(flagged("py/cdk-bucket-plain-http", src).is_empty());
        let src = "import aws_cdk\nb = s3.Bucket(self, 'A')\nc = s3.Bucket(self, 'B', enforce_ssl=True)\nd = s3.Bucket(self, 'C', **props)";
        assert_eq!(flagged("py/cdk-bucket-plain-http", src), [2]);
    }

    #[test]
    fn cdk_defaults_that_are_already_safe() {
        let src = "import aws_cdk\na = sqs.Queue(self, 'A')\nb = sqs.CfnQueue(self, 'B')\nc = efs.FileSystem(self, 'F')\nd = efs.CfnFileSystem(self, 'G')\ne = sns.Topic(self, 'T', master_key=k)";
        assert_eq!(flagged("py/cdk-queue-unencrypted", src), [3]);
        assert_eq!(flagged("py/cdk-filesystem-unencrypted", src), [5]);
        assert!(flagged("py/cdk-topic-unencrypted", src).is_empty());
    }

    #[test]
    fn policies() {
        let src = "import aws_cdk\na = iam.PolicyStatement(actions=['*'], resources=[r])\nb = iam.PolicyStatement(effect=iam.Effect.DENY, actions=['*'], resources=['*'])\nc = iam.PolicyStatement(actions=['s3:Get*'], resources=['*'])";
        assert_eq!(flagged("py/cdk-policy-grants-everything", src), [2]);
        assert_eq!(flagged("py/cdk-policy-all-resources", src), [4]);
    }

    #[test]
    fn lambda_handlers() {
        let src = "def lambda_handler(event, context):\n    c = boto3.client('s3')\n    r = requests.get(u)\n    lambda_client.invoke(FunctionName='f')\ndef helper(x):\n    boto3.client('s3')";
        assert_eq!(flagged("py/lambda-client-in-handler", src), [2]);
        assert_eq!(flagged("py/lambda-request-timeout", src), [3]);
        assert_eq!(flagged("py/lambda-sync-invoke", src), [4]);
    }
}
