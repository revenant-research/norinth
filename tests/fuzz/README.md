# Fuzz harnesses

Coverage-guided fuzzing with [atheris](https://github.com/google/atheris)
(libFuzzer for Python) of the two places where untrusted structure enters
the code base:

| Harness | Target | Contract checked |
| --- | --- | --- |
| `fuzz_otel_ingest.py` | `app.ingestion.otel.otel_spans_to_events`, the mapper behind `POST /v1/traces` | any JSON document maps to serializable events or raises `OtelPayloadError`; nothing else escapes, because anything else is a 500 to the collector |
| `fuzz_sdk_privacy.py` | `norinth_logger.privacy`, the SDK content boundary | the sanitizers never raise, their output serializes like a batch on the wire, and a planted email, SSN, card number, API key, or token never leaves the process under either content-capture setting |

CI runs each harness for a bounded time on every pull request (the `Fuzz`
job). A crash fails the job and the crashing input is uploaded as the
`fuzz-crash` artifact. Reproduce it with the harness and the file as its only
argument:

```bash
python tests/fuzz/fuzz_otel_ingest.py crash-<hash>
```

Locally, on Linux x86_64 with Python 3.12 or later:

```bash
pip install --require-hashes -r requirements-fuzz.lock.txt
make fuzz            # both harnesses, 60 seconds each
```

On macOS use a container:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src python:3.12-slim \
  sh -c 'pip install --require-hashes -r requirements-fuzz.lock.txt && make fuzz'
```

`tests/fuzz/corpus/<target>/` holds the seed inputs that are committed. Runs
write the inputs they discover to `.fuzz-corpus/`, which is git-ignored, so a
long local run does not turn into a large diff. Add a seed to the committed
corpus when it exercises a shape the mapper handles that the existing seeds do
not.
