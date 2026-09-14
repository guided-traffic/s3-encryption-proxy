// semantic-release configuration. A JavaScript file rather than JSON because the
// release-notes template is read from disk and the coverage figure is handed to
// it from the environment. There must be no `release` key in package.json: the
// configuration loader takes that key first and it would shadow this file.
import { readFileSync } from "node:fs";
import createPreset from "conventional-changelog-conventionalcommits";

const mainTemplate = readFileSync(new URL("./.github/release-template.hbs", import.meta.url), "utf8");

// The conventionalcommits preset must stay in the generation that
// @semantic-release/commit-analyzer and release-notes-generator are built on
// (conventional-changelog-angular 8.x, conventional-changelog-writer 8.x). The
// 10.x line changes the preset shape and needs Node 22; renovate.json pins it.
const preset = "conventionalcommits";

// Types that release nothing. A breaking marker on one of them is a mistake, not
// a product break: ADR 0018 D5 defines a break as stored data, an existing
// configuration or a client-visible answer, and none of those is what a test or a
// pipeline change moves.
const nonReleasingTypes = new Set(["docs", "style", "chore", "test", "build", "ci"]);

// The section map, used twice: once as presetConfig, once to build the preset
// instance whose transform this file wraps. Two copies would drift.
const noteTypes = [
  { type: "feat", section: "Features" },
  { type: "fix", section: "Bug Fixes" },
  { type: "perf", section: "Performance Improvements" },
  { type: "revert", section: "Reverts" },
  { type: "refactor", section: "Code Refactoring" },
  { type: "security", section: "Security" },
];

// The preset's own transform shortens hashes, links issues and maps a type onto
// its section. Supplying a transform REPLACES it rather than running beside it,
// so it is wrapped.
const presetTransform = (await createPreset({ types: noteTypes })).writer.transform;

// A real footer, which the parser does not insist on: its note keywords match
// case-insensitively and the colon is optional, so a body whose first words are
// "Breaking Change Guard and Version Dry Run had become..." is read as a breaking
// note and injected headless into the release. Require the colon.
const breakingFooter = /^BREAKING[ -]CHANGE:/m;

// The release notes are assembled from the breaking footers of the commits a
// release contains (ADR 0018 D10), which only works while a footer means what it
// says. Two ways it did not, both found by rendering the 5.0.0 notes before
// cutting them: a keyword without a colon, and a marker on a commit that changes
// no product behaviour. A note dropped here is still a marker on the commit, so
// the pull-request guard of ADR 0018 D3 sees it either way.
function keepOnlyRealBreakingNotes(commit, context) {
  const type = (commit.type || "").toLowerCase();
  // The parser splits a message into header, body and footer, and a well-formed
  // footer lands in the third. A keyword in the first body paragraph lands in the
  // second, so both are searched.
  const raw = [commit.body, commit.footer].filter(Boolean).join("\n");
  const keep = !nonReleasingTypes.has(type) && breakingFooter.test(raw);
  const input = keep ? commit : { ...commit, notes: [] };
  return presetTransform(input, context);
}

// TEST_COVERAGE is set by the release job from the combined coverage report.
function finalizeContext(context) {
  // isMajor drives the compatibility banner at the top of the notes. A major of
  // this project breaks the stored format by policy (ADR 0017), and the
  // statement an operator has to read first must not sit forty bullets into the
  // breaking-changes list.
  const isMajor = context.version ? /^\d+\.0\.0$/.test(context.version) : false;

  const coverage = Number.parseFloat(process.env.TEST_COVERAGE ?? "");
  if (Number.isNaN(coverage)) return { ...context, isMajor };
  const coverageColor = coverage >= 80 ? "brightgreen" : coverage >= 60 ? "yellow" : "red";
  return { ...context, coverage, coverageColor, isMajor };
}

export default {
  branches: ["main"],
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset,
        releaseRules: [
          { breaking: true, release: "major" },
          { type: "feat", release: "minor" },
          { type: "fix", release: "patch" },
          { type: "perf", release: "patch" },
          { type: "revert", release: "patch" },
          { type: "refactor", release: "patch" },
          { type: "docs", release: false },
          { type: "style", release: false },
          { type: "chore", release: false },
          { type: "test", release: false },
          { type: "build", release: false },
          { type: "ci", release: false },
        ],
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset,
        presetConfig: { types: noteTypes },
        writerOpts: { mainTemplate, finalizeContext, transform: keepOnlyRealBreakingNotes },
      },
    ],
    ["@semantic-release/changelog", { changelogFile: "CHANGELOG.md" }],
    [
      "@semantic-release/github",
      {
        assets: [
          { path: "build/s3-encryption-proxy", name: "s3-encryption-proxy-${nextRelease.gitTag}-linux-amd64" },
          { path: "build/s3ep-keygen", name: "s3ep-keygen-${nextRelease.gitTag}-linux-amd64" },
          { path: "coverage/merged.out", name: "coverage-${nextRelease.gitTag}.out" },
          { path: "coverage/coverage.txt", name: "coverage-${nextRelease.gitTag}.txt" },
        ],
      },
    ],
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md", ".github/badges/coverage.json"],
        message: "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
      },
    ],
  ],
};
