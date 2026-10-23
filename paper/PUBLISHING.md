# Publishing this paper

The submission draft is `what-does-zero-mean.md`. The case-study report is
`price-of-zero.md`.

## What only you can do

- **Fill in the author line.** The paper intentionally says `[to be completed]`.
  Add your name and affiliation (or "Independent researcher").
- **Read it once, out loud.** You should be able to explain the four arms and why 0/33
  becomes 14/33 with an approving user without notes. If you cannot, do not publish yet.
- **Confirm the artifact is public.** The paper links
  `https://github.com/FlyingGrasss/agent-os`. If the repository is private, either make it
  public or add an anonymized archive and change the link.
- **Choose licenses.** Code: MIT or Apache-2.0 (add a `LICENSE` file; there is none yet).
  Paper: CC BY 4.0, or the arXiv default license.
- **Check for secrets before making the repo public.** `git status` should not contain
  tokens, keys, or personal paths. The untracked audit logs and scratch files are not
  tracked, but confirm.
- **Convert to PDF.** arXiv accepts PDF (LaTeX source optional). There is no `pandoc` or
  LaTeX engine installed on this host; use one of:
  - `pandoc what-does-zero-mean.md -o what-does-zero-mean.pdf` on a machine that has it;
  - a Markdown-to-PDF editor;
  - a minimal LaTeX transcription, if you want the tables to look typeset.
- **Create an arXiv account and submit to `cs.CR`.** A first submission may require an
  endorsement; arXiv will tell you. Choose the license and metadata, upload the PDF, and
  submit.
- **Decide whether to submit to a workshop.** Do not do this until someone who does not
  already believe the thesis has read the paper. The current version is a technical report,
  not a peer-reviewed result.

## Before you click submit

- [ ] Author and affiliation filled in.
- [ ] Artifact URL resolves (or is anonymized for review).
- [ ] A `LICENSE` file exists.
- [ ] No secrets or credentials in tracked files.
- [ ] PDF renders the tables and the code blocks.
- [ ] The abstract says "case study" and "the authors' own system."
- [ ] The live arm is labelled exploratory / single run.
- [ ] References are complete and the arXiv IDs resolve.
- [ ] You can defend the numbers: 45 programs, 33 attacks, 12 automatic, 17 human,
      4 budget; 16 model tasks; 11/16 = 5 attacks + 6 benign twins.

## What not to do

- Do not describe it as peer reviewed.
- Do not add 3 models x 5 runs or an AgentDojo port just to make it look bigger. The paper's
  claim is the protocol; those are a different project.
- Do not claim the architecture is novel. The paper explicitly positions it against CaMeL,
  Progent, IsolateGPT, and FIDES.
- Do not publish a version whose numbers you cannot reproduce from the artifact.

## After publishing

- Link the paper from the repository README.
- Keep the artifact frozen at the measured commit (`e09992a`) or tag it.
- Archive the repository (GitHub archive or Zenodo) if you want a DOI.
- If you never touch the project again, that is a valid ending. The paper and the artifact
  are the output.
