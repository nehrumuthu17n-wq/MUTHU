import unittest
from io import BytesIO

from PIL import Image, ImageDraw

from analyzers.image_analyzer import analyze_image


class TestImageAnalyzer(unittest.TestCase):
    def _make_photo_like_image(self):
        img = Image.new("RGB", (1200, 900), (245, 245, 245))
        draw = ImageDraw.Draw(img)

        for i in range(80):
            x = (i * 19) % 1180
            y = (i * 23) % 860
            r = 15 + (i % 20)
            draw.ellipse((x, y, x + r, y + r), fill=((30 + i * 3) % 255, (70 + i * 5) % 255, (120 + i * 2) % 255))

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        return buffer.getvalue()

    def _make_suspicious_image(self):
        img = Image.new("RGB", (100, 100), (240, 240, 240))
        draw = ImageDraw.Draw(img)
        draw.rectangle((10, 10, 90, 90), fill=(239, 239, 239))

        exif = Image.Exif()
        exif[0x0131] = "Adobe Photoshop"

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=95, exif=exif)
        return buffer.getvalue()

    def test_normal_photo_like_image_stays_trusted(self):
        result = analyze_image(self._make_photo_like_image())
        self.assertGreaterEqual(result["score"], 75)
        self.assertEqual(result["details"]["verdict"], "Likely original")

    def test_low_detail_edited_image_is_flagged(self):
        result = analyze_image(self._make_suspicious_image())
        self.assertLess(result["score"], 55)
        self.assertEqual(result["details"]["verdict"], "Likely manipulated or AI-generated")

    def test_content_safety_flags_are_separate_from_authenticity_score(self):
        img = Image.new("RGB", (800, 800), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.ellipse((80, 100, 720, 700), fill=(230, 190, 160))
        draw.ellipse((140, 180, 660, 620), fill=(245, 210, 180))
        draw.rectangle((120, 620, 680, 760), fill=(200, 150, 120))

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        result = analyze_image(buffer.getvalue())

        self.assertIn("safety", result["details"])
        self.assertFalse(result["details"]["safety"].get("nudity_risk"))
        self.assertFalse(result["details"]["safety"].get("explicit_content"))
        self.assertEqual(result["details"]["safety"]["nsfw_check"], "not_assessed")

    def test_color_only_image_never_receives_a_nudity_prediction(self):
        img = Image.new("RGB", (700, 900), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.ellipse((200, 150, 500, 520), fill=(220, 170, 140))
        draw.ellipse((220, 180, 470, 420), fill=(240, 210, 180))
        draw.rectangle((180, 520, 520, 760), fill=(160, 120, 100))

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        result = analyze_image(buffer.getvalue())

        self.assertGreaterEqual(result["score"], 70)
        self.assertFalse(result["details"]["safety"].get("nudity_risk"))
        self.assertFalse(any("nudity" in f["message"].lower() for f in result["findings"]))

    def test_normal_portrait_does_not_trigger_nudity_risk(self):
        img = Image.new("RGB", (700, 900), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.ellipse((260, 180, 440, 360), fill=(210, 160, 120))
        draw.rectangle((220, 350, 480, 700), fill=(120, 150, 180))
        draw.rectangle((250, 700, 450, 820), fill=(90, 90, 110))

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        result = analyze_image(buffer.getvalue())

        self.assertFalse(result["details"]["safety"].get("nudity_risk"))
        self.assertFalse(result["details"]["safety"].get("explicit_content"))

    def test_red_clothes_and_background_do_not_trigger_nudity_risk(self):
        img = Image.new("RGB", (900, 700), (175, 45, 45))
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, 900, 180), fill=(240, 240, 235))
        draw.rectangle((320, 180, 580, 650), fill=(210, 30, 35))
        draw.ellipse((390, 120, 510, 240), fill=(190, 135, 100))

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        result = analyze_image(buffer.getvalue())

        self.assertFalse(result["details"]["safety"].get("nudity_risk"))
        self.assertFalse(result["details"]["safety"].get("explicit_content"))


if __name__ == "__main__":
    unittest.main()
