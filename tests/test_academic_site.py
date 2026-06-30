from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


class AcademicSiteSourceTest(unittest.TestCase):
    def test_site_uses_github_pages_root_without_custom_domain(self):
        config = read("_config.yml")

        self.assertIn("url: https://yuuoniy.github.io", config)
        self.assertRegex(config, r"(?m)^baseurl:\s*$")
        for path in ["CNAME", "docs/CNAME", "static/CNAME"]:
            self.assertFalse((ROOT / path).exists(), f"{path} should not exist")

    def test_homepage_contains_migrated_profile_content_without_feeds(self):
        about = read("_pages/about.md")

        for text in [
            "Miaoqian Lin",
            "The University of Hong Kong",
            "BugAuditor",
            "SpecAuditor",
        ]:
            self.assertIn(text, about)

        self.assertIn('<h2 id="selected-publications" style="margin-top: 2.75rem;">Selected publications</h2>', about)
        self.assertIn("announcements:", about)
        self.assertIn("enabled: false", about)
        self.assertIn("latest_posts:", about)
        self.assertNotIn("subtitle: Postdoctoral Researcher at The University of Hong Kong", about)
        self.assertNotIn("## Education", about)
        self.assertNotIn("## Teaching", about)
        self.assertNotIn("Chinese Academy of Sciences, Ph.D.", about)
        self.assertNotIn("Sun Yat-Sen University, B.S.", about)

    def test_bio_text_uses_only_requested_inline_links(self):
        about = read("_pages/about.md")

        expected = (
            "I am a Postdoctoral Researcher at The University of Hong Kong, working with Prof. "
            "[Ho Chen](https://sec.hku.hk/). "
            "I received my Ph.D. from the University of Chinese Academy of Sciences, where I was advised "
            "by Prof. [Kai Chen](https://kaichen.org/). I feel very fortunate to work with excellent researchers.\n\n"
            "My research focuses on software security, program analysis, and AI for security. Specifically, "
            "I have designed and implemented automated analysis tools for large-scale bug detection. My work "
            "has detected hundreds of previously unknown security bugs in widely used programs. Based on my "
            "research, I have also contributed hundreds of bug-fixing patches to the mainline of the Linux kernel."
        )
        self.assertIn(expected, about)
        self.assertNotIn("[The University of Hong Kong]", about)
        self.assertNotIn("https://i.cs.hku.hk/~hchen/", about)
        self.assertNotIn("https://nsec.ict.ac.cn/people/chenkai/", about)

    def test_homepage_does_not_duplicate_home_nav_or_show_template_photo(self):
        about = read("_pages/about.md")

        self.assertRegex(about, r"(?m)^nav:\s*false$")
        self.assertRegex(about, r"(?m)^profile:\s*false$")
        self.assertNotIn("prof_pic.jpg", about)
        self.assertFalse((ROOT / "assets" / "img" / "prof_pic.jpg").exists())

    def test_homepage_uses_small_custom_image(self):
        about = read("_pages/about.md")

        self.assertIn('<img class="homepage-profile-image"', about)
        self.assertIn('src="/assets/img/image.png"', about)
        self.assertIn("max-width: 180px", about)
        self.assertTrue((ROOT / "assets" / "img" / "image.png").exists())

    def test_site_uses_custom_browser_icon(self):
        config = read("_config.yml")

        self.assertRegex(config, r"(?m)^icon:\s*icon\.png(?:\s+#.*)?$")
        self.assertTrue((ROOT / "assets" / "img" / "icon.png").exists())

    def test_google_search_console_verification_enabled(self):
        config = read("_config.yml")

        self.assertIn(
            "google_site_verification: sieUKjMGeBdG6hVraIc1YBOH9blYJGnpklzxYjIRpC8",
            config,
        )
        self.assertIn("enable_google_verification: true", config)

    def test_google_analytics_measurement_id_configured(self):
        config = read("_config.yml")

        self.assertIn("analytics:", config)
        self.assertIn("  google: G-0DJHMR0F89", config)

    def test_publications_use_al_folio_style_with_text_links_and_plain_artifact_badges(self):
        about = read("_pages/about.md")

        for text in [
            '<div class="publications">',
            '<ol class="bibliography">',
            '<div class="col col-sm-2 abbr">',
            "Artifact Available",
            "Functional",
            "Reproducible",
            "color: #8a6500",
            "background: rgba(218, 165, 32, 0.06)",
            ">PDF<",
            ">Code<",
        ]:
            self.assertIn(text, about)

        self.assertIn('href="https://yuuoniy.github.io/files/SpecAuditor.pdf"', about)
        self.assertIn('href="https://yuuoniy.github.io/files/BugAuditor.pdf"', about)
        self.assertIn('href="https://github.com/Yuuoniy/SpecAuditor"', about)
        publications = about.split('<div class="contact-links"', 1)[0]
        bugauditor = publications.split("BugAuditor", 1)[1].split("</li>", 1)[0]
        self.assertIn("PDF<", bugauditor)
        self.assertNotIn("Code<", bugauditor)
        self.assertNotIn("Google Scholar", publications)
        self.assertNotIn("Citation", about)
        self.assertNotIn('class="award btn', about)
        self.assertNotIn('artifact-badge" role="button"', about)
        self.assertNotIn('class="fa-solid fa-box-archive"', about)
        self.assertNotIn('class="fa-solid fa-check"', about)
        self.assertNotIn('class="fa-solid fa-repeat"', about)
        self.assertNotIn('class="fa-solid fa-award"', about)
        self.assertNotIn('class="fa-solid fa-file-pdf"', publications)
        self.assertNotIn('class="fa-solid fa-code"', publications)

    def test_contact_links_are_icon_links_at_homepage_bottom(self):
        about = read("_pages/about.md")

        self.assertIn('<div class="contact-links" style="text-align: center;', about)
        self.assertIn('class="fa-solid fa-envelope contact-icon"', about)
        self.assertIn('class="ai ai-google-scholar contact-icon"', about)
        self.assertIn('class="fa-brands fa-github"', about)
        self.assertIn('style="text-align: center;', about)
        self.assertIn('href="mailto:miaoqian@hku.hk"', about)
        self.assertNotIn("linmq006@gmail.com", about)
        self.assertIn('href="https://scholar.google.com/citations?user=sj17XuAAAAAJ&amp;hl=en"', about)
        self.assertIn('href="https://github.com/Yuuoniy"', about)
        self.assertLess(about.index('<h2 id="selected-publications"'), about.index('<div class="contact-links"'))
        self.assertNotIn(">miaoqian@hku.hk<", about)
        self.assertNotIn(">Yuuoniy<", about)

    def test_external_post_import_is_disabled(self):
        config = read("_config.yml")

        self.assertIn("external_sources: []", config)
        self.assertNotIn("- al_ext_posts", config)
        self.assertNotIn("medium.com/@al-folio", config)

    def test_local_work_files_are_excluded_from_site_output(self):
        config = read("_config.yml")

        for path in [
            "AGENTS.md",
            "CLAUDE.md",
            "findings.md",
            "progress.md",
            "requirements.txt",
            "task_plan.md",
            "tests/",
            ".github/",
        ]:
            self.assertIn(f"  - {path}", config)

    def test_misc_page_contains_migrated_reading_lists(self):
        misc = read("_pages/misc.md")
        page_layout = read("_layouts/page.liquid")

        self.assertIn("hide_title: true", misc)
        self.assertIn("description: Below are some materials that may help.", misc)
        self.assertIn(".post-description { font-size: 1rem;", misc)
        self.assertIn(".misc-section-heading { font-size: 1rem;", misc)
        self.assertIn("{% unless page.hide_title %}", page_layout)
        self.assertNotIn("Reading notes and references.", misc)
        self.assertIn('<h3 class="misc-section-heading">Research</h3>', misc)
        self.assertIn('<h3 class="misc-section-heading">Books about writing</h3>', misc)
        self.assertNotIn("## Research", misc)
        self.assertNotIn("## Books About Writing", misc)

        for text in [
            "You and Your Research",
            "Science as a Vocation",
            "*How to Solve It*",
            "*Discourse on the Method*",
            "*Writing Science*",
            "*The Sense of Style*",
            "*Bird by Bird*",
            "*The Art of Nonfiction*",
            "*On Revision: The Only Writing That Counts*",
        ]:
            self.assertIn(text, misc)

    def test_unused_template_pages_are_absent(self):
        for path in [
            "_pages/news.md",
            "_pages/blog.md",
            "_pages/projects.md",
            "_pages/cv.md",
            "_pages/repositories.md",
        ]:
            self.assertFalse((ROOT / path).exists(), f"{path} should be removed")

    def test_specauditor_pdf_is_preserved(self):
        pdf = ROOT / "files" / "SpecAuditor.pdf"

        self.assertTrue(pdf.exists())
        self.assertGreater(pdf.stat().st_size, 1_000_000)

    def test_bugauditor_pdf_is_available(self):
        pdf = ROOT / "files" / "BugAuditor.pdf"

        self.assertTrue(pdf.exists())
        self.assertGreater(pdf.stat().st_size, 100_000)


if __name__ == "__main__":
    unittest.main()
