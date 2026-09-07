# RFC 7208 test suite (open-spf.org)

`rfc7208-tests.yml` is the open-spf.org RFC 7208 test suite (release
2014.04), downloaded from
<http://www.open-spf.org/svn/project/test-suite/rfc7208-tests-yml/>.
`rfc7208-tests.LICENSE` is its license.

`rfc7208-tests.json` is a mechanical conversion of the YAML (multi-document
stream, scalar types preserved) so the conformance test can parse it with
the standard library only. Regenerate it after updating the YAML:

```sh
python3 -c '
import yaml, json
docs = [d for d in yaml.safe_load_all(open("rfc7208-tests.yml")) if d]
json.dump(docs, open("rfc7208-tests.json", "w"), indent=1, ensure_ascii=False)
'
```

(requires PyYAML; this is a one-off offline step, not part of the build).

The conformance test (`../conformance_test.go`) follows the suite's driver
rules (<http://www.open-spf.org/Test_Suite/Schema/>): SPF records are
auto-copied to TXT only when no TXT records are given for the name
(`TXT: NONE` suppresses the copy), and a `TIMEOUT` marker makes queries
that match no preceding records fail temporarily.

No cases are hand-picked: cases are skipped — with the reason in the test
name — only when their records use mechanisms or modifiers that are not
implemented yet. The skipped set shrinks as RFC 7208 coverage grows.
