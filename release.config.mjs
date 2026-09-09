// semantic-release configuration. A JavaScript file rather than JSON because the
// release-notes template is read from disk and the coverage figure is handed to
// it from the environment. There must be no `release` key in package.json: the
// configuration loader takes that key first and it would shadow this file.
import { readFileSync } from "node:fs";

const mainTemplate = readFileSync(new URL("./.github/release-template.hbs", import.meta.url), "utf8");

// The conventionalcommits preset must stay in the generation that
// @semantic-release/commit-analyzer and release-notes-generator are built on
// (conventional-changelog-angular 8.x, conventional-changelog-writer 8.x). The
// 10.x line changes the preset shape and needs Node 22; renovate.json pins it.
const preset = "conventionalcommits";

// TEST_COVERAGE is set by the release job from the combined coverage report.
function finalizeContext(context) {
  const coverage = Number.parseFloat(process.env.TEST_COVERAGE ?? "");
  if (Number.isNaN(coverage)) return context;
  const coverageColor = coverage >= 80 ? "brightgreen" : coverage >= 60 ? "yellow" : "red";
  return { ...context, coverage, coverageColor };
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
        presetConfig: {
          types: [
            { type: "feat", section: "Features" },
            { type: "fix", section: "Bug Fixes" },
            { type: "perf", section: "Performance Improvements" },
            { type: "revert", section: "Reverts" },
            { type: "refactor", section: "Code Refactoring" },
            { type: "security", section: "Security" },
          ],
        },
        writerOpts: { mainTemplate, finalizeContext },
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
