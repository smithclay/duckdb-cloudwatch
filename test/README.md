# Testing this extension
This directory contains the CloudWatch extension's tests. `sql` holds offline
[SQLLogicTests](https://duckdb.org/dev/sqllogictest/intro.html) for registration, credential errors,
and argument validation. `cpp/cloudwatch_json_test.cpp` covers request generation, response parsing,
and OTLP attribute mapping without making an AWS request.

The root makefile contains targets to build and run all of these tests. To run the SQLLogicTests:
```bash
make test
```
or 
```bash
make test_debug
```

Run the pure C++ helper test with:

```bash
cmake --build build/release --target cloudwatch_json_test cloudwatch_signing_test cloudwatch_protocol_test
./build/release/extension/cloudwatch/cloudwatch_json_test
./build/release/extension/cloudwatch/cloudwatch_signing_test
./build/release/extension/cloudwatch/cloudwatch_protocol_test
```
