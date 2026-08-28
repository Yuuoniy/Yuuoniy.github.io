---
layout: about
title: home
permalink: /
nav: false
nav_order: 1

profile: false

selected_papers: false
social: false

announcements:
  enabled: false

latest_posts:
  enabled: false
---

<img class="homepage-profile-image" src="/assets/img/image.png" alt="Miaoqian Lin" style="float: right; max-width: 180px; width: 28%; min-width: 120px; margin: 0 0 1rem 1.5rem; border-radius: 6px;">

I am a Postdoctoral Researcher at The University of Hong Kong, working with Prof. [Ho Chen](https://sec.hku.hk/). I received my Ph.D. from the University of Chinese Academy of Sciences, where I was advised by Prof. [Kai Chen](https://kaichen.org/). I feel very fortunate to work with excellent researchers.

My research focuses on software security, program analysis, and AI for security. Specifically, I have designed and implemented automated analysis tools for large-scale bug detection. My work has detected hundreds of previously unknown security bugs in widely used programs. Based on my research, I have also contributed hundreds of bug-fixing patches to the mainline of the Linux kernel.
<div class="research-opening" style="margin-top: 1.5rem; padding: 0.85rem 1rem; border-left: 4px solid #b58900; background: rgba(218, 165, 32, 0.08); border-radius: 4px; overflow: hidden;">
  ✨ <strong>Our research group has open positions.</strong><br>
  If you are interested in my work and would like to join us as a research assistant or visiting scholar (either locally or remotely), please feel free to drop me an <a href="mailto:miaoqian@hku.hk">email</a>! ✉️
</div>


<h2 id="selected-publications" style="margin-top: 2.75rem;">Selected publications</h2>

<style>
  .publication-links {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    column-gap: 0;
    row-gap: 0;
  }

  .publication-links .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 3.25rem;
    height: 1.45rem;
    padding: 0;
    font-size: 0.64rem;
    line-height: 1;
    margin: 0.375rem;
  }

  .bibtex-toggle {
    cursor: pointer;
  }

  .bibtex-block {
    margin: 0.45rem 0 0;
    max-width: 100%;
    overflow-x: auto;
    white-space: pre-wrap;
    font-size: 0.85rem;
    border-radius: 4px;
  }
</style>

<div class="publications">
  <ol class="bibliography">
    <li>
      <div class="row">
        <div class="col col-sm-2 abbr">
          <abbr class="badge rounded w-100">USENIX Security</abbr>
        </div>
        <div class="col-sm-10">
          <div class="title">BugAuditor: Detecting Bugs via Inconsistent Defensive Code Auditing</div>
          <div class="author"><em>Miaoqian Lin</em>, Kai Chen, and Hao Chen</div>
          <div class="periodical"><em>In Proceedings of the 35th USENIX Security Symposium</em>, 2026</div>
          <div class="links artifact-note" style="display: inline-block; color: #8a6500; background: rgba(218, 165, 32, 0.06); font-weight: 600; font-size: 0.9rem; padding: 0.12rem 0.45rem; border-radius: 4px;">Artifact Available · Functional · Reproducible</div>
          <div class="links publication-links">
            <a href="https://yuuoniy.github.io/files/BugAuditor.pdf" class="btn btn-sm z-depth-0" role="button" title="PDF" aria-label="PDF">PDF</a>
            <a href="https://github.com/Yuuoniy/BugAuditor" class="btn btn-sm z-depth-0" role="button" title="Code" aria-label="Code">Code</a>
            <a href="#bibtex-bugauditor" class="btn btn-sm z-depth-0 bibtex-toggle" role="button" aria-expanded="false" aria-controls="bibtex-bugauditor" data-bibtex-target="bibtex-bugauditor">BibTeX</a>
          </div>
          <pre id="bibtex-bugauditor" class="bibtex-block" hidden><code>@inproceedings{lin2026bugauditor,
  author = {Lin, Miaoqian and Chen, Kai and Chen, Hao},
  title = {BugAuditor: Detecting Bugs via Inconsistent Defensive Code Auditing},
  booktitle = {USENIX Security Symposium},
  date = {2026-08-12/2026-08-14},
  address = {Baltimore, MD, USA},
}</code></pre>
        </div>
      </div>
    </li>

    <li>
      <div class="row">
        <div class="col col-sm-2 abbr">
          <abbr class="badge rounded w-100">S&amp;P</abbr>
        </div>
        <div class="col-sm-10">
          <div class="title">SpecAuditor: Generating Audit Specifications for LLM-Driven Bug Detection</div>
          <div class="author"><em>Miaoqian Lin</em> and Hao Chen</div>
          <div class="periodical"><em>In Proceedings of the 47th IEEE Symposium on Security and Privacy</em>, 2026</div>
          <div class="links artifact-note" style="display: inline-block; color: #8a6500; background: rgba(218, 165, 32, 0.06); font-weight: 600; font-size: 0.9rem; padding: 0.12rem 0.45rem; border-radius: 4px;">Artifact Available · Functional · Reproducible</div>
          <div class="links publication-links">
            <a href="https://yuuoniy.github.io/files/SpecAuditor.pdf" class="btn btn-sm z-depth-0" role="button" title="PDF" aria-label="PDF">PDF</a>
            <a href="https://github.com/Yuuoniy/SpecAuditor" class="btn btn-sm z-depth-0" role="button" title="Code" aria-label="Code">Code</a>
            <a href="#bibtex-specauditor" class="btn btn-sm z-depth-0 bibtex-toggle" role="button" aria-expanded="false" aria-controls="bibtex-specauditor" data-bibtex-target="bibtex-specauditor">BibTeX</a>
          </div>
          <pre id="bibtex-specauditor" class="bibtex-block" hidden><code>@inproceedings{lin2026specauditor,
  author = {Lin, Miaoqian and Chen, Hao},
  title = {SpecAuditor: Generating Audit Specifications for LLM-Driven Bug Detection},
  booktitle = {IEEE Symposium on Security \&amp; Privacy},
  date = {2026-05-18/2026-05-21},
  address = {San Francisco, CA, USA},
}</code></pre>
        </div>
      </div>
    </li>

    <li>
      <div class="row">
        <div class="col col-sm-2 abbr">
          <abbr class="badge rounded w-100">NDSS</abbr>
        </div>
        <div class="col-sm-10">
          <div class="title">Uncovering the Iceberg from the Tip: Generating API Specifications for Bug Detection via Specification Propagation Analysis</div>
          <div class="author"><em>Miaoqian Lin</em>, Kai Chen, Yi Yang, and Jinghua Liu</div>
          <div class="periodical"><em>In Proceedings of the 32nd Network and Distributed System Security Symposium</em>, 2025</div>
          <div class="links artifact-note" style="display: inline-block; color: #8a6500; background: rgba(218, 165, 32, 0.06); font-weight: 600; font-size: 0.9rem; padding: 0.12rem 0.45rem; border-radius: 4px;">Artifact Available · Functional · Reproducible</div>
          <div class="links publication-links">
            <a href="https://www.ndss-symposium.org/wp-content/uploads/2025-2001-paper.pdf" class="btn btn-sm z-depth-0" role="button" title="PDF" aria-label="PDF">PDF</a>
            <a href="https://github.com/Yuuoniy/APISpecGen" class="btn btn-sm z-depth-0" role="button" title="Code" aria-label="Code">Code</a>
            <a href="#bibtex-uncovering" class="btn btn-sm z-depth-0 bibtex-toggle" role="button" aria-expanded="false" aria-controls="bibtex-uncovering" data-bibtex-target="bibtex-uncovering">BibTeX</a>
          </div>
          <pre id="bibtex-uncovering" class="bibtex-block" hidden><code>@inproceedings{lin2025uncovering,
  author = {Lin, Miaoqian and Chen, Kai and Yang, Yi and Liu, Jinghua},
  title = {Uncovering the Iceberg from the Tip: Generating API Specifications for Bug Detection via Specification Propagation Analysis},
  booktitle = {Network and Distributed System Security Symposium},
  date = {2025-02-24/2025-02-28},
  address = {San Diego, CA, USA},
}</code></pre>
        </div>
      </div>
    </li>

    <li>
      <div class="row">
        <div class="col col-sm-2 abbr">
          <abbr class="badge rounded w-100">USENIX Security</abbr>
        </div>
        <div class="col-sm-10">
          <div class="title">Detecting API Post-Handling Bugs Using Code and Description in Patches</div>
          <div class="author"><em>Miaoqian Lin</em>, Kai Chen, and Yang Xiao</div>
          <div class="periodical"><em>In Proceedings of the 32nd USENIX Security Symposium</em>, 2023</div>
          <div class="links publication-links">
            <a href="https://www.usenix.org/system/files/usenixsecurity23-lin.pdf" class="btn btn-sm z-depth-0" role="button" title="PDF" aria-label="PDF">PDF</a>
            <a href="https://github.com/Yuuoniy/APHP" class="btn btn-sm z-depth-0" role="button" title="Code" aria-label="Code">Code</a>
            <a href="#bibtex-detecting" class="btn btn-sm z-depth-0 bibtex-toggle" role="button" aria-expanded="false" aria-controls="bibtex-detecting" data-bibtex-target="bibtex-detecting">BibTeX</a>
          </div>
          <pre id="bibtex-detecting" class="bibtex-block" hidden><code>@inproceedings{lin2023detecting,
  author = {Lin, Miaoqian and Chen, Kai and Xiao, Yang},
  title = {Detecting API Post-Handling Bugs Using Code and Description in Patches},
  booktitle = {USENIX Security Symposium},
  date = {2023-08-09/2023-08-11},
  address = {Anaheim, CA, USA},
}</code></pre>
        </div>
      </div>
    </li>
  </ol>
</div>

<h2 id="academic-services" style="margin-top: 2.25rem; font-size: 1.35rem;">Academic services</h2>

<div class="academic-services">
  <ul style="margin: 0.25rem 0 0; padding-left: 1.25rem;">
    <li><strong>Program committee member:</strong> IEEE SaTML 2027, USENIX Security 2027</li>
    <li><strong>Reviewer:</strong> TSE 2026</li>
  </ul>
</div>

<script>
  document.querySelectorAll(".bibtex-toggle").forEach((control) => {
    control.addEventListener("click", (event) => {
      event.preventDefault();
      const target = document.getElementById(control.dataset.bibtexTarget);
      if (!target) return;
      const isOpening = target.hasAttribute("hidden");
      target.toggleAttribute("hidden", !isOpening);
      control.setAttribute("aria-expanded", String(isOpening));
    });
  });
</script>

<div class="contact-links" style="text-align: center; margin-top: 2rem;">
  <a href="mailto:miaoqian@hku.hk" title="Email" aria-label="Email" style="margin-right: 1rem;"><i class="fa-solid fa-envelope contact-icon" style="font-size: 1.75rem;"></i></a>
  <a href="https://scholar.google.com/citations?user=sj17XuAAAAAJ&amp;hl=en" title="Google Scholar" aria-label="Google Scholar" style="margin-right: 1rem;"><i class="ai ai-google-scholar contact-icon" style="font-size: 1.75rem;"></i></a>
  <a href="https://www.linkedin.com/in/miaoqian-lin-2565b7332/" title="LinkedIn" aria-label="LinkedIn" style="margin-right: 1rem;"><i class="fa-brands fa-linkedin" style="font-size: 1.75rem;"></i></a>
  <a href="https://github.com/Yuuoniy" title="GitHub" aria-label="GitHub"><i class="fa-brands fa-github" style="font-size: 1.75rem;"></i></a>
</div>
