"""canonical_json is RFC 8785 (JCS). The two examples from the RFC's section
3.2.3 are reproduced byte for byte, plus the ECMAScript number cases that
separate JCS from Python's own json.dumps."""

import json

from gargoyle.envelope import canonical_json


def test_rfc_8785_example():
    text = ('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
            '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}')
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
    assert canonical_json(json.loads(text)) == expected
    assert canonical_json(json.loads(text)).encode("utf-8")[:12] == b'{"literals":'


def test_rfc_8785_key_order_is_utf16_code_units():
    doc = json.loads('{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\ufb33": "Hebrew Letter Dalet With Dagesh", '
                     '"1": "One", "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control", '
                     '"\\u00f6": "Latin Small Letter O With Diaeresis"}')
    out = canonical_json(doc)
    assert list(json.loads(out)) == ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]
    # Only JSON's mandatory escapes; C1 controls and non-ASCII are literal UTF-8.
    assert out.startswith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"')


def test_numbers_are_ecmascript_not_python():
    cases = {1.0: "1", 100.0: "100", 0.1: "0.1", 1e21: "1e+21", 1e20: "100000000000000000000", 1e-7: "1e-7",
             0.000001: "0.000001", 1.25e-8: "1.25e-8", -2.5: "-2.5", 0.0: "0", -0.0: "0", 1e16: "10000000000000000",
             5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308", 123456789012345680000.0: "123456789012345680000"}
    for x, want in cases.items():
        assert canonical_json(x) == want, (x, canonical_json(x), want)
    assert canonical_json([7, True, None, "a"]) == '[7,true,null,"a"]'
    for bad in (float("nan"), float("inf")):
        try:
            canonical_json(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("non-finite accepted")


def test_strings_escape_only_what_json_requires():
    assert canonical_json("a\"b\\c\n\t\b\f\r\u0001\u001f\u007f\u0080\u00e9\u2028") == \
        '"a\\"b\\\\c\\n\\t\\b\\f\\r\\u0001\\u001f\u007f\u0080\u00e9\u2028"'
