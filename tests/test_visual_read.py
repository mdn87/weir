import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

from PIL import Image
from weir.visual import (
    Region,
    ValueQuery,
    _read_backend,
    crop_image,
    structured_value,
    visual_value,
)
from weir.visual_ocr import _offline


class VisualValueTests(unittest.TestCase):
    def test_zero_and_duplicate_accessibility_representations(self):
        query = ValueQuery("Tasks in review")
        result = structured_value(query, ["Tasks in review: 0"], '- button "Tasks in review: 0"')
        self.assertEqual((result.status, result.value), ("answered", 0))
        result = structured_value(query, [], """- 'button "Tasks in review: 0"'""")
        self.assertEqual(result.value, 0)

    def test_duplicate_labels_even_with_equal_values_require_review(self):
        result = structured_value(ValueQuery("Open"), [], '- text: "Open: 7"\n- text: "Open: 7"')
        self.assertEqual((result.status, result.value), ("ambiguous", None))
        result = structured_value(ValueQuery("Open"), ["Open: 7", "Open issues: 12"], "")
        self.assertEqual((result.status, result.value), ("answered", 7))

    def test_isolated_reader_accepts_only_two_bounded_outputs_from_its_engine(self):
        one = {"reader": "aire.rapidocr", "text": "Open: 7"}
        two = {"reader": "aire.rapidocr.contrast", "text": "Open: 7"}
        for raw, expected in (
            ([one, two], [one, two]),
            ([one], []),
            ([two, one], []),
            ([one, {**two, "text": "a" * 4100}], []),
        ):
            with patch("subprocess.run", return_value=Mock(stdout=json.dumps(raw))) as launch:
                self.assertEqual(_read_backend("rapidocr", b"pixels"), expected)
                self.assertIn("-I", launch.call_args.args[0])
                self.assertEqual(launch.call_args.kwargs["input"], b"pixels")
        for event in ("socket.connect", "socket.getaddrinfo", "socket.sendmsg"):
            with self.assertRaises(PermissionError):
                _offline(event, ())
        with self.assertRaises(PermissionError):
            _offline("socket.__new__", (None, socket.AF_INET, 0, 0))

    def test_no_guessing_or_converting_unrecognized_values(self):
        for text in [
            "Open: 7 of 12",
            "Open: -3",
            "Open: 7.0",
            "Open: send the report",
            "Open: 8,00",
        ]:
            with self.subTest(text=text):
                result = structured_value(ValueQuery("Open"), [text], "")
                self.assertEqual((result.status, result.value), ("unreadable", None))
        result = structured_value(
            ValueQuery("Build", ("Passing", "Failed")), [], "- text: Build: passing"
        )
        self.assertEqual(result.value, "Passing")

    def test_two_readings_must_name_the_question_and_agree(self):
        query = ValueQuery("Ready")
        self.assertEqual(visual_value(query, ["Ready: 23", "Ready 23"]).value, 23)
        duplicate = "Ready: 23 Ready: 23"
        self.assertEqual(visual_value(query, [duplicate, duplicate]).status, "ambiguous")
        for lines in [
            ["Ready: 23", "Ready: 28"],
            ["23", "23"],
            ["Ready: 23", ""],
            ["Ready: 23 Ready: 23", "Ready: 23"],
        ]:
            with self.subTest(lines=lines):
                self.assertIsNone(visual_value(query, lines).value)

    def test_crop_keeps_exact_pixels_and_rejects_outside_rectangle(self):
        source = Image.new("RGB", (80, 40), "white")
        source.putpixel((10, 12), (18, 19, 20))
        stream = io.BytesIO()
        source.save(stream, format="PNG")
        crop = crop_image(stream.getvalue(), Region(10, 12, 30, 20))
        self.assertEqual((crop.size, crop.getpixel((0, 0))), ((30, 20), (18, 19, 20)))
        with self.assertRaises(ValueError):
            crop_image(stream.getvalue(), Region(79, 2, 2, 2))
        stream = io.BytesIO()
        Image.new("RGBA", (10, 10), (0, 0, 0, 0)).save(stream, format="PNG")
        with self.assertRaisesRegex(ValueError, "opaque"):
            crop_image(stream.getvalue(), Region(0, 0, 5, 5))
