# Publishing this paper

The submission draft is `what-does-zero-mean.md`; the PDF is
`what-does-zero-mean.pdf`. The case-study report is `price-of-zero.md`.

## Done

- **Author:** Emre Bozkurt.
- **Code license:** MIT (`LICENSE`).
- **Paper license:** CC BY 4.0 (`paper/LICENSE`), also stated on the first page.
- **PDF:** generated from the Markdown, 11 pages, tables and code blocks render.
- **Secret scan:** no tracked credentials, keys, `.env`/`.pem` files, or common token
  patterns; the history was checked for the same patterns. No personal paths or personal
  email addresses were found in tracked files.
- **Artifact:** `https://github.com/FlyingGrasss/agent-os`.

## Remaining

- **Read it once.** You should be able to explain the four arms and why 0/33 becomes 14/33
  with an approving user without notes.
- **Create an arXiv account** and submit to `cs.CR`. A first submission may require an
  endorsement; arXiv will tell you.
- **Choose the arXiv license.** Use CC BY 4.0 to match the paper.
- **Upload `paper/what-does-zero-mean.pdf`.** Add the title, author, abstract, and the
  artifact URL in the metadata.
- **Optional:** submit to a workshop later, after someone who does not already believe the
  thesis has read it.

## Before you click submit

- [ ] PDF opens and the tables render.
- [ ] Artifact URL resolves.
- [ ] arXiv license is CC BY 4.0.
- [ ] You can defend the numbers: 45 programs, 33 attacks, 12 automatic / 17 human /
      4 budget; 16 model tasks; 11/16 = 5 attacks + 6 benign twins.
- [ ] The live arm is labelled exploratory / single run.

## What not to do

- Do not describe it as peer reviewed.
- Do not add 3 models x 5 runs or an AgentDojo port just to make it look bigger. The paper's
  claim is the protocol; those are a different project.
- Do not claim the architecture is novel. The paper positions it against CaMeL, Progent,
  IsolateGPT, and FIDES.
- Do not publish a version whose numbers you cannot reproduce from the artifact.

## After publishing

- Link the paper from the repository README.
- Tag or archive the measured commit (`e09992a`) if you want a frozen artifact.
- If you never touch the project again, that is a valid ending. The paper and the artifact
  are the output.
