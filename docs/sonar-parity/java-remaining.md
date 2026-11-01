# Java rules not covered, and why

SonarQube's Java rules that sonda has no equivalent for yet (status `todo` in `java.csv`), grouped by what stands in the way. A rule moves out of this list when a sonda rule covers it exactly; some are covered in part by a rule that carries its key as `related`.

## Needs types or members of classes defined in other files (override contracts, hierarchies, Spring wiring, nullness).

- `S2162`: "equals" methods should be symmetric and work for subclasses
- `S2177`: Child class methods named for parent class methods should be overrides
- `S2221`: "Exception" should not be caught when not required by called methods
- `S2250`: Collection methods with O(n) performance should be used carefully
- `S2388`: Inner class calls to super class methods should be unambiguous
- `S2638`: Method overrides should not change contracts
- `S3242`: Method parameters should be declared with base types
- `S3254`: Default annotation parameter values should not be passed as arguments
- `S3398`: "private" methods called only by inner classes should be moved to those classes
- `S3437`: Value-based objects should not be serialized
- `S3551`: Overrides should match their parent class methods in synchronization
- `S3658`: Unit tests should throw exceptions
- `S3749`: Members of Spring components should be injected
- `S4449`: Nullness of parameters should be guaranteed
- `S4605`: Spring beans should be considered by "@ComponentScan"
- `S4926`: "serialVersionUID" should not be declared blindly
- `S4970`: Derived exceptions should not hide their parents' catch blocks
- `S5128`: "Bean Validation" (JSR 380) should be properly configured
- `S5669`: Vararg method arguments should not be confusing
- `S6816`: Nullable injected fields and parameters should provide a default value
- `S6832`: Non-singleton Spring beans should not be injected into singleton beans
- `S4512`: JavaBean properties should not be populated from untrusted input

## Targets Java 22 to 25 or JDK preview APIs (unnamed variables, ClassFile, Gatherers, constructor prologues); the grammar cannot parse some of the syntax and the APIs have almost no code to validate against.

- `S6203`: Text blocks should not be used in complex expressions
- `S6211`: Custom getter method should not be used to override record's getter behavior
- `S6216`: Reflection should not be used to increase accessibility of records' fields
- `S6878`: Use record pattern instead of explicit field access
- `S6916`: Use when instead of a single if inside a pattern match body
- `S7466`: Unnamed variable declarations should use the "var" identifier
- `S7474`: Markdown, HTML and Javadoc tags should be consistent
- `S7475`: Types of unused record components should be removed from pattern matching
- `S7476`: Comments should start with the appropriate number of slashes
- `S7477`: Class name should be omitted when unchanged by class transform
- `S7478`: "transformClass" method should be used instead of "build" when transforming a class
- `S7479`: "ClassBuilder.withMethodBody" should be preferred to "ClassBuilder.withMethod"
- `S7481`: Gatherer.ofSequential() should be used to build sequential gathers
- `S7482`: Don't provide an initializer for a stateless stream gatherer
- `S7629`: When a defaultFinisher is passed to a Gatherer factory, use the overload that does not take a finisher
- `S8433`: Validation logic should be placed in constructor prologue when possible
- `S8444`: Excessive logic before super() should not bloat constructor
- `S8445`: Module imports should come first and imports should be grouped by kind
- `S8447`: Subclass fields should be initialized before calls to "super()" or "this()"
- `S8469`: Prefer "IO.readln(String prompt)" rather than "IO.print(Object obj)" or "IO.println(Object obj)" followed by "IO.readln()"

## A judgement call the rule's own description leaves open (test quality, grouping, brain methods, Spring security design); a syntactic version would be mostly noise.

- `S1200`: Classes should not be coupled to too many other classes
- `S3937`: Number patterns should be regular
- `S5194`: Use Java 14 "switch" expression
- `S5663`: Simple string literal should be used for single line strings
- `S5679`: OpenSAML2 should be configured to prevent authentication bypass
- `S5804`: Authentication mechanisms should not permit user enumeration.
- `S5808`: Authorizations should be based on strong decisions
- `S5831`: AssertJ configuration should be applied
- `S5860`: Names of regular expressions named groups should be used
- `S5867`: Unicode-aware versions of character classes should be preferred
- `S5960`: Assertions should not be used in production code
- `S5969`: Mocking all non-private methods of a class should be avoided
- `S5970`: Spring's ModelAndViewAssert assertions should be used instead of other assertions
- `S5973`: Tests should be stable
- `S5976`: Similar tests should be grouped in a single Parameterized test
- `S6541`: Methods should not perform too many tasks (aka Brain method)
- `S6877`: Reverse view should be used instead of reverse copy in read-only cases
- `S7177`: Use appropriate @DirtiesContext modes

## Needs the file path, the project layout, or the analyzer itself rather than the code.

- `NoSonar`: Track uses of "NOSONAR" comments
- `S1120`: Source code should be indented consistently
- `S1228`: Packages should have a javadoc file 'package-info.java'
- `S1598`: Package declaration should match source file directory
- `S2260`: Java parser failure
- `S3414`: Tests should be kept in a dedicated source directory
- `S4032`: Packages containing only "package-info.java" should be removed

## Needs to know which executor runs a task, which depends on how the executor was built elsewhere.

- `S6881`: Virtual threads should be used for tasks that include heavy blocking operations
- `S6906`: Virtual threads should not run tasks that include synchronized code

## Android hardware heuristics that need the manifest and device configuration.

- `S6898`: High frame rates should not be used
- `S6923`: Motion Sensor should not use gyroscope

## Only applies to Java 8 and earlier source, where _ and enum were identifiers.

- `S1190`: Future keywords should not be used as names
